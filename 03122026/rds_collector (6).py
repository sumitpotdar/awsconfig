import boto3
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from decimal import Decimal
from botocore.exceptions import ClientError

# Environment variables
DYNAMODB_TABLE = os.environ.get('DYNAMODB_TABLE', 'RDSSecurityAudit')
ROLE_NAME = os.environ.get('CROSS_ACCOUNT_ROLE', 'RDSAuditRole')

# DynamoDB client
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(DYNAMODB_TABLE)

# Account configuration
ACCOUNTS = [
        {'account_id': '<Account>', 'name': '<AccountName>'}
]

# ─────────────────────────────────────────────────────────────────────────────
# Custom secret prefix pattern
#
# Only the /rds/<app_name> segment matters for matching.
# Everything before /rds/ (e.g. the leading app prefix and environment) is
# captured but NOT used for matching — only the app_name that follows /rds/
# is compared against the RDS instance tags and secret tags.
#
# Examples:
#   pocapp/dev/rds/pocapp                  → rds_app_name = "pocapp"
#   pocapp/dev/rds/pocapp/ppjam            → rds_app_name = "pocapp"
#   payments/prod/rds/payments/Ab1Cd-XyZ  → rds_app_name = "payments"
#
# Named capture groups:
#   prefix       – everything before /rds/  (informational only, not matched)
#   rds_app_name – the app_name segment directly after /rds/  ← MATCH KEY
#   unique_id    – optional AWS-generated suffix after rds_app_name
# ─────────────────────────────────────────────────────────────────────────────
CUSTOM_SECRET_PATTERN = re.compile(
    r'^(?P<prefix>.+)/rds/(?P<rds_app_name>[^/]+)(?:/(?P<unique_id>.+))?$',
    re.IGNORECASE
)

# Common environment tokens used in secret names / RDS tags
ENV_TOKENS = {'dev', 'development', 'staging', 'stage', 'uat', 'qa',
              'prod', 'production', 'test', 'sandbox', 'preprod'}

# ─────────────────────────────────────────────────────────────────────────────
# Region-level caches  (populated ONCE per region, reused for all instances)
# ─────────────────────────────────────────────────────────────────────────────
# _secrets_cache[region] = list of fully-described secret dicts
_secrets_cache: dict = {}
# _param_group_cache[pg_name] = ssl_enforced bool
_param_group_cache: dict = {}


def _load_secrets_for_region(region: str, credentials=None) -> list:
    """
    Fetch ALL secrets in a region exactly once and cache them.
    Each entry is the full describe_secret response dict.
    Subsequent calls return the cached list instantly.
    """
    if region in _secrets_cache:
        return _secrets_cache[region]

    sm_kwargs = dict(region_name=region)
    if credentials:
        sm_kwargs.update(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )

    secrets = []
    try:
        sm        = boto3.client('secretsmanager', **sm_kwargs)
        paginator = sm.get_paginator('list_secrets')
        stubs     = []
        for page in paginator.paginate():
            stubs.extend(page.get('SecretList', []))

        print(f"  [cache] {region}: fetched {len(stubs)} secret stubs — calling describe_secret in parallel")

        # describe_secret in parallel (max 20 threads — well within SM rate limits)
        seen_arns = set()

        def _describe(stub):
            arn  = stub.get('ARN') or stub.get('SecretArn') or ''
            name = stub.get('Name', '')
            try:
                full = sm.describe_secret(SecretId=arn or name)
                return full
            except Exception as e:
                print(f"  describe_secret failed for {name}: {e}")
                return stub   # fall back to stub

        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {pool.submit(_describe, s): s for s in stubs}
            for fut in as_completed(futures):
                full = fut.result()
                arn  = full.get('ARN') or full.get('SecretArn') or ''
                if arn and arn not in seen_arns:
                    seen_arns.add(arn)
                    secrets.append(full)

        print(f"  [cache] {region}: cached {len(secrets)} fully-described secrets")

    except Exception as e:
        print(f"  [cache] Error loading secrets for region {region}: {e}")

    _secrets_cache[region] = secrets
    return secrets


# ─────────────────────────────────────────────────────────────────────────────
# Matching helpers
# ─────────────────────────────────────────────────────────────────────────────

def _normalise(value: str) -> str:
    """Lower-case, strip hyphens/underscores for fuzzy comparison."""
    return re.sub(r'[-_]', '', value.lower())


def _extract_app_id_from_tags(tags: dict) -> str | None:
    """
    Return the best 'app id' candidate from an RDS instance's tag map.
    Checks common tag keys in priority order.
    """
    for key in ('app_id', 'AppId', 'application_id', 'ApplicationId',
                'app', 'App', 'application', 'Application',
                'service', 'Service', 'Name', 'name'):
        if key in tags:
            return tags[key]
    return None


def match_secret_to_instance(secret_name: str,
                              secret_tags: dict,
                              instance_id: str,
                              instance_tags: dict) -> dict:
    """
    Determine whether a Secrets Manager secret belongs to a given RDS instance.

    Returns a dict:
        {
            'matched': bool,
            'match_type': str,          # how the match was made
            'app_name':  str | None,    # app_name parsed from prefix pattern
            'environment': str | None,  # environment parsed from prefix pattern
        }
    """
    result = {'matched': False, 'match_type': None, 'app_name': None, 'environment': None, 'unique_id': None}

    # ── 1. AWS-managed tag: rds:primaryDBInstanceArn ─────────────────────────
    primary_arn = secret_tags.get('aws:rds:primaryDBInstanceArn', '')
    if primary_arn and instance_id in primary_arn:
        result.update(matched=True, match_type='aws_rds_tag')
        return result

    # ── 2. Custom prefix pattern  …/rds/<rds_app_name>[/<unique_id>]
    #
    #  Only the segment immediately after /rds/ is used for matching.
    #  That value is compared against:
    #    a) the RDS instance's app_name / app_id tags
    #    b) the secret's own app_name / app_id tags
    #  Both sides must carry the same app_name — if either tag is missing the
    #  match falls through to the legacy checks below.
    # ──────────────────────────────────────────────────────────────────────────
    m = CUSTOM_SECRET_PATTERN.match(secret_name)
    if m:
        rds_app_name = m.group('rds_app_name')  # e.g. "pocapp"  ← the only match key
        unique_id    = m.group('unique_id')      # e.g. "ppjam"   (may be None)

        # Parse environment from the prefix segment if present
        # prefix = "pocapp/dev"  →  last non-rds segment before /rds/
        prefix_parts = (m.group('prefix') or '').split('/')
        environment  = prefix_parts[-1] if prefix_parts else None

        result['app_name']    = rds_app_name
        result['environment'] = environment
        result['unique_id']   = unique_id

        norm_rds_app = _normalise(rds_app_name)

        # ── a) Match rds_app_name against RDS instance tags ───────────────────
        inst_app_name = instance_tags.get('app_name') or instance_tags.get('APP_NAME') or instance_tags.get('AppName')
        inst_app_id   = instance_tags.get('app_id')   or instance_tags.get('APP_ID')   or instance_tags.get('AppId')

        inst_match_val = inst_app_name or inst_app_id  # prefer app_name, fall back to app_id
        if not inst_match_val:
            # no app tags on instance — skip custom matching
            pass
        else:
            norm_inst_app = _normalise(inst_match_val)

            # ── b) Match rds_app_name against secret's own tags ───────────────
            sec_app_name = secret_tags.get('app_name') or secret_tags.get('APP_NAME') or secret_tags.get('AppName')
            sec_app_id   = secret_tags.get('app_id')   or secret_tags.get('APP_ID')   or secret_tags.get('AppId')

            sec_match_val = sec_app_name or sec_app_id  # prefer app_name, fall back to app_id

            # Match condition:
            #   rds_app_name == instance app_name/app_id tag
            #   AND (secret has no app tags  OR  secret app tag also matches)
            if norm_rds_app == norm_inst_app:
                if sec_match_val is None or _normalise(sec_match_val) == norm_inst_app:
                    result.update(matched=True, match_type='custom')
                    return result

    # ── 3. Instance ID substring in secret name (legacy / non-standard) ──────
    if _normalise(instance_id) in _normalise(secret_name):
        result.update(matched=True, match_type='instance_id_in_name')
        return result

    # ── 4. Secret description contains instance ID ────────────────────────────
    # (handled by the caller who passes description separately – see below)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Lambda entry point
# ─────────────────────────────────────────────────────────────────────────────

def lambda_handler(event, context):
    """
    Main handler - Scans all RDS instances across multiple AWS accounts
    Runs daily via EventBridge scheduled rule
    """
    print(f"Starting RDS security audit at {datetime.now().isoformat()}")

    sts = boto3.client('sts')
    current_account = sts.get_caller_identity()['Account']
    print(f"Running in account: {current_account}")

    scan_timestamp = datetime.now().isoformat()
    scan_date      = datetime.now().strftime('%Y-%m-%d')
    total_instances = 0

    try:
        accounts = load_accounts_config()

        for account in accounts:
            account_id   = account['account_id']
            account_name = account.get('name', account_id)

            print(f"\n=== Scanning Account: {account_name} ({account_id}) ===")

            try:
                if account_id == current_account:
                    print(f"Scanning current account {account_name} - no role assumption needed")
                    credentials = None
                else:
                    credentials = assume_role(account_id)

                instances = scan_account(account_id, account_name, credentials, scan_timestamp)
                store_instances(instances, scan_date, scan_timestamp)

                total_instances += len(instances)
                print(f"Found {len(instances)} instances in account {account_name}")

            except Exception as e:
                print(f"Error scanning account {account_id}: {str(e)}")
                continue

        store_scan_metadata(scan_date, scan_timestamp, total_instances, len(accounts))

        print(f"\n=== Scan Complete ===")
        print(f"Total instances scanned: {total_instances}")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Scan completed successfully',
                'scan_timestamp': scan_timestamp,
                'total_instances': total_instances,
                'accounts_scanned': len(accounts)
            })
        }

    except Exception as e:
        print(f"ERROR: {str(e)}")
        raise


# ─────────────────────────────────────────────────────────────────────────────
# Account helpers
# ─────────────────────────────────────────────────────────────────────────────

def load_accounts_config():
    """Load account configuration from Parameter Store or use default."""
    try:
        ssm = boto3.client('ssm')
        response = ssm.get_parameter(Name='/rds-audit/accounts', WithDecryption=True)
        return json.loads(response['Parameter']['Value'])
    except Exception:
        print("Using default account configuration")
        return ACCOUNTS


def assume_role(account_id):
    """Assume cross-account role and return credentials."""
    sts      = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{ROLE_NAME}"

    try:
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"RDSAudit-{account_id}",
            DurationSeconds=3600
        )
        return response['Credentials']
    except ClientError as e:
        print(f"Failed to assume role in account {account_id}: {str(e)}")
        raise


# ─────────────────────────────────────────────────────────────────────────────
# Scanning
# ─────────────────────────────────────────────────────────────────────────────

def scan_account(account_id, account_name, credentials, scan_timestamp):
    """Scan all RDS instances in all regions for a given account."""
    # Clear region-level caches for each account scan
    _secrets_cache.clear()
    _param_group_cache.clear()
    instances = []

    ec2_kwargs = dict(region_name='us-east-1')
    if credentials:
        ec2_kwargs.update(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )

    try:
        ec2     = boto3.client('ec2', **ec2_kwargs)
        regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
    except Exception:
        regions = ['us-east-1', 'us-west-2', 'eu-west-1']

    for region in regions:
        rds_kwargs = dict(region_name=region)
        if credentials:
            rds_kwargs.update(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )

        try:
            rds       = boto3.client('rds', **rds_kwargs)
            paginator = rds.get_paginator('describe_db_instances')

            for page in paginator.paginate():
                for db in page['DBInstances']:
                    try:
                        instance_data = process_instance(
                            rds, db, account_id, account_name, region,
                            scan_timestamp, credentials
                        )
                        instances.append(instance_data)
                    except Exception as e:
                        print(f"Error processing instance "
                              f"{db.get('DBInstanceIdentifier')}: {str(e)}")
                        continue

        except ClientError as e:
            if e.response['Error']['Code'] == 'UnauthorizedOperation':
                print(f"Not authorized for region {region}")
            else:
                print(f"Error in region {region}: {str(e)}")
            continue

    return instances


def process_instance(rds, db, account_id, account_name, region,
                     scan_timestamp, credentials=None):
    """Process a single RDS instance and extract security data."""
    instance_id = db['DBInstanceIdentifier']
    db_arn      = db['DBInstanceArn']

    try:
        tags_response = rds.list_tags_for_resource(ResourceName=db_arn)
        tags = {tag['Key']: tag['Value'] for tag in tags_response['TagList']}
    except Exception:
        tags = {}

    # If app_id tag is missing, default it to the AWS account number.
    # Set only in the local record — does NOT write back to AWS.
    # 'app_id_defaulted' is stored in DynamoDB so the UI can highlight
    # instances that are missing a real app_id tag.
    has_app_id = any(k in tags for k in ('app_id', 'APP_ID', 'AppId',
                                          'application_id', 'ApplicationId'))
    app_id_defaulted = not has_app_id
    if app_id_defaulted:
        tags['app_id'] = account_id
        print(f"  [{instance_id}] Missing app_id tag — defaulting to account_id: {account_id}")

    ssl_info     = get_ssl_configuration(rds, db, region)
    secrets_info = check_secrets_manager(instance_id, tags, region, credentials)

    return {
        'id':           instance_id,
        'name':         db.get('DBName') or instance_id,
        'resourceType': 'RDS',
        'engine':       db['Engine'],
        'version':      db['EngineVersion'],
        'status':       db['DBInstanceStatus'],
        'region':       region,
        'account_id':   account_id,
        'account_name': account_name,
        'arn':          db_arn,
        'tags':         tags,
        'app_id_defaulted': app_id_defaulted,
        'scan_timestamp': scan_timestamp,
        'encryption': {
            'atRest':                db.get('StorageEncrypted', False),
            'inTransit':             ssl_info['enabled'],
            'inTransitEnforced':     ssl_info['enforced'],
            'certificateAuthority':  ssl_info['ca_identifier'],
            'certificateExpiryDate': ssl_info['cert_expiry_date'],
            'certificateDaysToExpiry': ssl_info['days_to_expiry'],
            'kmsKeyId':              db.get('KmsKeyId')
        },
        'backups': {
            'automated':     db.get('BackupRetentionPeriod', 0) > 0,
            'encrypted':     db.get('StorageEncrypted', False),
            'retentionDays': db.get('BackupRetentionPeriod', 0)
        },
        'network': {
            'publiclyAccessible': db.get('PubliclyAccessible', False),
            'vpcId': (db['DBSubnetGroup']['VpcId']
                      if db.get('DBSubnetGroup') else None),
            'securityGroups': [
                sg['VpcSecurityGroupId']
                for sg in db.get('VpcSecurityGroups', [])
            ]
        },
        'authentication': {
            'iamEnabled':      db.get('IAMDatabaseAuthenticationEnabled', False),
            'passwordRotation': secrets_info['rotation_enabled'],
            'secretArn':       secrets_info.get('secret_arn'),
            'lastRotated':     secrets_info.get('last_rotated'),
            'rotationDays':    secrets_info.get('rotation_days')
        },
        'monitoring': {
            'enhancedMonitoring':  db.get('EnhancedMonitoringResourceArn') is not None,
            'performanceInsights': db.get('PerformanceInsightsEnabled', False)
        },
        'secrets': secrets_info
    }


# ─────────────────────────────────────────────────────────────────────────────
# SSL helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_ssl_configuration(rds, db, region):
    """Get SSL/TLS configuration including certificate expiry date."""
    ssl_info = {
        'enabled': False, 'enforced': False,
        'ca_identifier': None, 'cert_expiry_date': None, 'days_to_expiry': None
    }

    try:
        ca_cert = db.get('CACertificateIdentifier')
        if ca_cert:
            ssl_info['enabled']       = True
            ssl_info['ca_identifier'] = ca_cert

            try:
                cert_response = rds.describe_certificates(CertificateIdentifier=ca_cert)
                if cert_response.get('Certificates'):
                    certificate = cert_response['Certificates'][0]
                    if certificate.get('ValidTill'):
                        valid_till = certificate['ValidTill']
                        ssl_info['cert_expiry_date'] = valid_till.isoformat()
                        now = datetime.now(valid_till.tzinfo)
                        days = (valid_till - now).days
                        ssl_info['days_to_expiry'] = days
                        print(f"  Certificate {ca_cert} expires {valid_till:%Y-%m-%d} ({days}d)")
                        if days < 30:
                            print(f"  WARNING: Certificate expires in {days} days!")
                        elif days < 90:
                            print(f"  NOTICE:  Certificate expires in {days} days")
            except Exception as e:
                print(f"  Error fetching certificate details for {ca_cert}: {e}")

        if db.get('DBParameterGroups'):
            pg_name = db['DBParameterGroups'][0]['DBParameterGroupName']
            # Use cache to avoid re-fetching the same parameter group
            if pg_name in _param_group_cache:
                ssl_info['enforced'] = _param_group_cache[pg_name]
            else:
                enforced = False
                try:
                    paginator = rds.get_paginator('describe_db_parameters')
                    for page in paginator.paginate(DBParameterGroupName=pg_name):
                        for param in page.get('Parameters', []):
                            name  = param.get('ParameterName', '')
                            value = param.get('ParameterValue', '')
                            if name in ('rds.force_ssl', 'require_secure_transport') and value == '1':
                                enforced = True
                                break
                        if enforced:
                            break
                except Exception as e:
                    print(f"  Error checking SSL enforcement: {e}")
                _param_group_cache[pg_name] = enforced
                ssl_info['enforced'] = enforced

    except Exception as e:
        print(f"Error checking SSL: {e}")

    return ssl_info


# ─────────────────────────────────────────────────────────────────────────────
# Secrets Manager – enhanced with custom prefix pattern
# ─────────────────────────────────────────────────────────────────────────────

def check_secrets_manager(instance_id: str,
                           instance_tags: dict,
                           region: str,
                           credentials=None) -> dict:
    """
    Match secrets from the region-level cache against a single RDS instance.
    The cache is populated once per region (parallel describe_secret calls),
    so this function is pure in-memory filtering — zero API calls per instance.
    """
    result = {
        'rotation_enabled': False,
        'secret_arn':       None,
        'secret_name':      None,
        'last_rotated':     None,
        'rotation_days':    None,
        'auto_rotation':    False,
        'all_secrets':      []
    }

    try:
        # Pull from cache — no API calls made here if already loaded
        all_region_secrets = _load_secrets_for_region(region, credentials)

        PRIORITY = {
            'aws_rds_tag':         0,
            'custom':              1,
            'instance_id_in_name': 2,
            'description':         3,
        }

        for full in all_region_secrets:
            secret_arn  = full.get('ARN') or full.get('SecretArn') or ''
            secret_name = full.get('Name', '')
            secret_tags = {t['Key']: t['Value'] for t in full.get('Tags', [])}
            description = full.get('Description', '')

            # ── match against this RDS instance ───────────────────────────────
            match = match_secret_to_instance(
                secret_name, secret_tags, instance_id, instance_tags
            )

            if not match['matched'] and instance_id in description:
                match = {'matched': True, 'match_type': 'description',
                         'app_name': None, 'environment': None, 'unique_id': None}

            if not match['matched']:
                continue

            # ── extract rotation info ─────────────────────────────────────────
            rotation_enabled = bool(full.get('RotationEnabled'))
            rotation_rules   = full.get('RotationRules', {})
            rotation_days    = rotation_rules.get('AutomaticallyAfterDays')

            last_rotated = None
            if full.get('LastRotatedDate'):
                last_rotated = full['LastRotatedDate'].isoformat()
            elif full.get('LastChangedDate'):
                last_rotated = full['LastChangedDate'].isoformat()

            secret_record = {
                'name':             secret_name,
                'arn':              secret_arn,
                'match_type':       match['match_type'],
                'app_name':         match.get('app_name'),
                'environment':      match.get('environment'),
                'unique_id':        match.get('unique_id'),
                'rotation_enabled': rotation_enabled,
                'rotation_days':    rotation_days,
                'last_rotated':     last_rotated,
            }
            result['all_secrets'].append(secret_record)

            print(f"  Matched secret [{match['match_type']}]: {secret_name}"
                  + (f"  (app={match['app_name']}, environment={match['environment']})"
                     if match.get('app_name') else ''))

        # ── promote the best secret to top-level fields ───────────────────────
        if result['all_secrets']:
            primary = min(
                result['all_secrets'],
                key=lambda s: PRIORITY.get(s['match_type'], 99)
            )
            result['secret_name']      = primary['name']
            result['secret_arn']       = primary['arn']
            result['rotation_enabled'] = primary['rotation_enabled']
            result['auto_rotation']    = primary['rotation_enabled']
            result['rotation_days']    = primary['rotation_days']
            result['last_rotated']     = primary['last_rotated']

            print(f"  Primary secret: {primary['name']} "
                  f"(rotation={'on' if primary['rotation_enabled'] else 'off'})")
            if result['rotation_days']:
                print(f"  Rotation interval: {result['rotation_days']} days")
        else:
            print(f"  No Secrets Manager secret found for {instance_id}")

    except Exception as e:
        print(f"  Error checking Secrets Manager: {e}")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# DynamoDB persistence
# ─────────────────────────────────────────────────────────────────────────────

def store_instances(instances, scan_date, scan_timestamp):
    """Store instances in DynamoDB with RDS prefix."""
    with table.batch_writer() as batch:
        for instance in instances:
            item = json.loads(json.dumps(instance), parse_float=Decimal)

            item['PK']     = f"RDS#ACCOUNT#{instance['account_id']}"
            item['SK']     = f"INSTANCE#{instance['id']}#{scan_timestamp}"
            item['GSI1PK'] = f"RDS#DATE#{scan_date}"
            item['GSI1SK'] = f"ACCOUNT#{instance['account_id']}#INSTANCE#{instance['id']}"
            item['resourceType'] = 'RDS'
            item['TTL']    = int((datetime.now() + timedelta(days=90)).timestamp())

            batch.put_item(Item=item)

    print(f"Stored {len(instances)} instances in DynamoDB")


def store_scan_metadata(scan_date, scan_timestamp, total_instances, accounts_scanned):
    """Store scan metadata."""
    item = {
        'PK':               f"RDS#METADATA#{scan_date}",
        'SK':               f"SCAN#{scan_timestamp}",
        'GSI1PK':           'RDS#METADATA',
        'GSI1SK':           scan_timestamp,
        'resourceType':     'RDS',
        'scan_date':        scan_date,
        'scan_timestamp':   scan_timestamp,
        'total_instances':  total_instances,
        'accounts_scanned': accounts_scanned,
        'TTL':              int((datetime.now() + timedelta(days=90)).timestamp())
    }
    table.put_item(Item=item)
    print("Stored scan metadata")
