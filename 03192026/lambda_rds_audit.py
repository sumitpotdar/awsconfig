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
ROLE_NAME      = os.environ.get('CROSS_ACCOUNT_ROLE', 'RDSAuditRole')

# DynamoDB client
dynamodb = boto3.resource('dynamodb')
table    = dynamodb.Table(DYNAMODB_TABLE)

# Account configuration
ACCOUNTS = [
    {'account_id': '<Account>', 'name': '<AccountName>'}
]

# ─────────────────────────────────────────────────────────────────────────────
# Secret name filter — only secrets whose name contains /rds/ are considered.
# Examples that PASS:   pocapp/dev/rds/pocapp/ppjam
#                       myapp/prod/rds/myapp
# Examples that SKIP:   myapp/dev/db/password
#                       rds-admin-creds          (no /rds/ path segment)
#
# AWS-managed secrets starting with "rds!" are always passed through because
# they are matched via the aws:rds:primaryDBInstanceArn tag, not the name.
# ─────────────────────────────────────────────────────────────────────────────
RDS_PREFIX_PATTERN = re.compile(r'/rds/', re.IGNORECASE)

# Parse display fields (app_name, environment, unique_id) from secret name.
# These are NOT used for matching — matching is purely by app_id tag equality.
#   pocapp / dev / rds / pocapp / ppjam
#            ^^^          ^^^^^^   ^^^^^
#        environment    app_name  unique_id
ENV_PATTERN = re.compile(
    r'^(?P<prefix>.+)/rds/(?P<rds_app_name>[^/]+)(?:/(?P<unique_id>.+))?$',
    re.IGNORECASE
)

# ─────────────────────────────────────────────────────────────────────────────
# Region-level caches  (populated ONCE per account+region, reused for all instances)
#
# FIX: Cache key is now (account_id, region) — not just region.
#      Previously the key was region-only, so when scanning Account B after
#      Account A the cache returned Account A's secrets for every instance in
#      Account B, causing zero matches for all cross-account secrets.
# ─────────────────────────────────────────────────────────────────────────────
# _secrets_cache[(account_id, region)] = list of fully-described secret dicts
_secrets_cache: dict = {}
# _param_group_cache[pg_name] = ssl_enforced bool
_param_group_cache: dict = {}


def _load_secrets_for_region(region: str,
                              credentials=None,
                              account_id: str = 'local') -> list:
    """
    Fetch ALL secrets in a region exactly once per account and cache them.

    FIX: Cache key is (account_id, region) so each account gets its own
    isolated cache entry.  The old key was region-only, which caused the
    first account's secrets to be returned for every subsequent account.

    Each entry is the full describe_secret response dict.
    Subsequent calls for the same account+region return the cached list instantly.
    """
    cache_key = (account_id, region)          # ← FIX: scoped per account
    if cache_key in _secrets_cache:
        return _secrets_cache[cache_key]

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

        print(f"  [cache] {account_id}/{region}: fetched {len(stubs)} secret stubs"
              f" — calling describe_secret in parallel")

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

        print(f"  [cache] {account_id}/{region}: cached {len(secrets)} fully-described secrets")

    except Exception as e:
        print(f"  [cache] Error loading secrets for {account_id}/{region}: {e}")

    _secrets_cache[cache_key] = secrets
    return secrets


# ─────────────────────────────────────────────────────────────────────────────
# Matching helpers
# ─────────────────────────────────────────────────────────────────────────────

def _normalise(value: str) -> str:
    """Lower-case, strip hyphens/underscores for fuzzy comparison."""
    return re.sub(r'[-_]', '', str(value).lower())


def match_secret_to_instance(secret_name: str,
                              secret_tags: dict,
                              instance_id: str,
                              instance_tags: dict) -> dict:
    """
    Determine whether a Secrets Manager secret belongs to a given RDS instance.

    Matching rules (in priority order):

      1. AWS-managed secret — has tag aws:rds:primaryDBInstanceArn pointing
         at this instance. Authoritative, always wins.

      2. Custom /rds/ prefix secret — secret name MUST contain /rds/ (filtered
         upfront in check_secrets_manager before this function is called).
         Match is purely by app_id tag equality:
           secret tag  app_id  ==  RDS instance tag  app_id
         Both tags must be present and equal (case/hyphen/underscore insensitive).
         app_name, environment, unique_id are parsed from the name for display only.

    Returns:
        {
            'matched':     bool,
            'match_type':  'aws_rds_tag' | 'custom' | None,
            'app_name':    str | None,   # segment after /rds/ in secret name
            'environment': str | None,   # segment before /rds/ (e.g. "dev")
            'unique_id':   str | None,   # suffix after app_name (e.g. "ppjam")
        }
    """
    result = {
        'matched':     False,
        'match_type':  None,
        'app_name':    None,
        'environment': None,
        'unique_id':   None,
    }

    # ── 1. AWS-managed secret tag ─────────────────────────────────────────────
    primary_arn = secret_tags.get('aws:rds:primaryDBInstanceArn', '')
    if primary_arn and instance_id in primary_arn:
        result.update(matched=True, match_type='aws_rds_tag')
        return result

    # ── 2. /rds/ prefix secret — match by app_id tag equality ────────────────
    # Parse display fields from the secret name (not used for matching)
    m = ENV_PATTERN.match(secret_name)
    if m:
        rds_app_name = m.group('rds_app_name')          # e.g. "pocapp"
        unique_id    = m.group('unique_id')              # e.g. "ppjam" (may be None)
        prefix_parts = (m.group('prefix') or '').split('/')
        environment  = prefix_parts[-1] if prefix_parts else None

        result['app_name']    = rds_app_name
        result['environment'] = environment
        result['unique_id']   = unique_id

    # Resolve app_id from both sides — support common key variants
    inst_app_id = (instance_tags.get('app_id') or instance_tags.get('APP_ID')
                   or instance_tags.get('AppId'))
    sec_app_id  = (secret_tags.get('app_id')   or secret_tags.get('APP_ID')
                   or secret_tags.get('AppId'))

    if inst_app_id and sec_app_id:
        if _normalise(inst_app_id) == _normalise(sec_app_id):
            result.update(matched=True, match_type='custom')
            return result

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Lambda entry point
# ─────────────────────────────────────────────────────────────────────────────

def lambda_handler(event, context):
    """
    Main handler - Scans all RDS instances across multiple AWS accounts.
    Runs daily via EventBridge scheduled rule.
    """
    print(f"Starting RDS security audit at {datetime.now().isoformat()}")

    sts             = boto3.client('sts')
    current_account = sts.get_caller_identity()['Account']
    print(f"Running in account: {current_account}")

    scan_timestamp  = datetime.now().isoformat()
    scan_date       = datetime.now().strftime('%Y-%m-%d')
    total_instances = 0

    try:
        accounts = load_accounts_config()

        for account in accounts:
            account_id   = account['account_id']
            account_name = account.get('name', account_id)

            print(f"\n=== Scanning Account: {account_name} ({account_id}) ===")

            try:
                if account_id == current_account:
                    print(f"Scanning current account {account_name} — no role assumption needed")
                    credentials = None
                else:
                    credentials = assume_role(account_id)

                instances = scan_account(
                    account_id, account_name, credentials, scan_timestamp
                )
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
                'message':          'Scan completed successfully',
                'scan_timestamp':   scan_timestamp,
                'total_instances':  total_instances,
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
        ssm      = boto3.client('ssm')
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

def _scan_region(region, account_id, account_name, credentials, scan_timestamp):
    """
    Scan a single region — called in parallel by scan_account.

    Secrets are pre-loaded into the (account_id, region)-scoped cache before
    any instance processing begins, so check_secrets_manager makes zero
    additional API calls per instance.
    """
    rds_kwargs = dict(region_name=region)
    if credentials:
        rds_kwargs.update(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )

    instances = []
    try:
        rds       = boto3.client('rds', **rds_kwargs)
        paginator = rds.get_paginator('describe_db_instances')

        # Collect all DB stubs first
        db_stubs = []
        for page in paginator.paginate():
            db_stubs.extend(page['DBInstances'])

        if not db_stubs:
            return instances

        print(f"  [{region}] {len(db_stubs)} instances found"
              f" — pre-loading secrets cache and fetching tags in parallel")

        # ── Pre-load secrets cache for this account+region BEFORE processing ──
        # This single call populates the cache so every subsequent
        # check_secrets_manager() call in this region is a cache-hit (no API calls).
        # Running it here (before the instance loop) keeps all the I/O in one
        # place and avoids any risk of redundant concurrent cache fills.
        _load_secrets_for_region(region, credentials, account_id)

        # ── Fetch tags for all instances concurrently ─────────────────────────
        def _fetch_tags(db):
            try:
                resp = rds.list_tags_for_resource(ResourceName=db['DBInstanceArn'])
                return db['DBInstanceIdentifier'], {
                    t['Key']: t['Value'] for t in resp['TagList']
                }
            except Exception:
                return db['DBInstanceIdentifier'], {}

        tags_map = {}
        with ThreadPoolExecutor(max_workers=20) as pool:
            for inst_id, tags in pool.map(_fetch_tags, db_stubs):
                tags_map[inst_id] = tags

        # ── Process each instance (secrets use cache — zero extra API calls) ──
        for db in db_stubs:
            try:
                instance_data = process_instance(
                    rds, db, account_id, account_name, region,
                    scan_timestamp, credentials,
                    prefetched_tags=tags_map.get(db['DBInstanceIdentifier'], {})
                )
                instances.append(instance_data)
            except Exception as e:
                print(f"  Error processing instance "
                      f"{db.get('DBInstanceIdentifier')}: {str(e)}")
                continue

    except ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print(f"  Not authorized for region {region}")
        else:
            print(f"  Error in region {region}: {str(e)}")

    return instances


def scan_account(account_id, account_name, credentials, scan_timestamp):
    """
    Scan all RDS instances across all regions in parallel.

    NOTE: We no longer call _secrets_cache.clear() here.
    With the (account_id, region) cache key, each account's secrets are stored
    under a unique key, so there is no risk of cross-account cache pollution.
    Clearing the cache between accounts was the old workaround and would have
    caused redundant API calls on Lambda retries or if the same account appears
    twice in the config.
    """
    # Fixed scan regions
    regions = ['us-east-1', 'us-west-2']

    print(f"  Scanning {len(regions)} regions in parallel")

    all_instances = []
    with ThreadPoolExecutor(max_workers=len(regions)) as pool:
        futures = {
            pool.submit(
                _scan_region, region, account_id, account_name,
                credentials, scan_timestamp
            ): region
            for region in regions
        }
        for fut in as_completed(futures):
            region = futures[fut]
            try:
                region_instances = fut.result()
                all_instances.extend(region_instances)
                print(f"  [{region}] completed — {len(region_instances)} instances")
            except Exception as e:
                print(f"  [{region}] failed: {e}")

    return all_instances


def process_instance(rds, db, account_id, account_name, region,
                     scan_timestamp, credentials=None, prefetched_tags=None):
    """Process a single RDS instance and extract security data."""
    instance_id = db['DBInstanceIdentifier']
    db_arn      = db['DBInstanceArn']

    # Use pre-fetched tags if available (avoids redundant API call)
    if prefetched_tags is not None:
        tags = prefetched_tags
    else:
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

    # FIX: pass account_id so check_secrets_manager uses the correct
    # (account_id, region) cache key instead of the old region-only key.
    secrets_info = check_secrets_manager(
        instance_id, tags, region, credentials, account_id
    )

    return {
        'id':               instance_id,
        'name':             db.get('DBName') or instance_id,
        'resourceType':     'RDS',
        'engine':           db['Engine'],
        'version':          db['EngineVersion'],
        'status':           db['DBInstanceStatus'],
        'region':           region,
        'account_id':       account_id,
        'account_name':     account_name,
        'arn':              db_arn,
        'tags':             tags,
        'app_id_defaulted': app_id_defaulted,
        'scan_timestamp':   scan_timestamp,
        'encryption': {
            'atRest':                  db.get('StorageEncrypted', False),
            'inTransit':               ssl_info['enabled'],
            'inTransitEnforced':       ssl_info['enforced'],
            'certificateAuthority':    ssl_info['ca_identifier'],
            'certificateExpiryDate':   ssl_info['cert_expiry_date'],
            'certificateDaysToExpiry': ssl_info['days_to_expiry'],
            'kmsKeyId':                db.get('KmsKeyId')
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
            'iamEnabled':       db.get('IAMDatabaseAuthenticationEnabled', False),
            'passwordRotation': secrets_info['rotation_enabled'],
            'secretArn':        secrets_info.get('secret_arn'),
            'lastRotated':      secrets_info.get('last_rotated'),
            'rotationDays':     secrets_info.get('rotation_days')
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
                        now  = datetime.now(valid_till.tzinfo)
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
# Secrets Manager
# ─────────────────────────────────────────────────────────────────────────────

def check_secrets_manager(instance_id: str,
                           instance_tags: dict,
                           region: str,
                           credentials=None,
                           account_id: str = 'local') -> dict:   # ← FIX: added account_id
    """
    Match secrets from the (account_id, region)-scoped cache against a single
    RDS instance.  Makes ZERO additional API calls per instance — the cache is
    populated once per account+region in _scan_region before the instance loop.

    FIX: account_id is now threaded through to _load_secrets_for_region so the
    correct per-account cache bucket is used.  Previously, all accounts shared
    the same region-only bucket, so cross-account instances got the wrong secrets.

    Two-step process per secret:
      1. Filter  — skip any secret whose name lacks /rds/ (unless AWS-managed rds!)
      2. Match   — aws_rds_tag (ARN tag) or custom (app_id tag equality)
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

    PRIORITY = {
        'aws_rds_tag': 0,
        'custom':      1,
    }

    try:
        # FIX: pass account_id — returns the correct account-scoped cache bucket
        all_region_secrets = _load_secrets_for_region(region, credentials, account_id)

        for full in all_region_secrets:
            secret_arn  = full.get('ARN') or full.get('SecretArn') or ''
            secret_name = full.get('Name', '')
            secret_tags = {t['Key']: t['Value'] for t in full.get('Tags', [])}

            # ── Step 1: filter by name ────────────────────────────────────────
            # Only process secrets that have /rds/ in the name OR are
            # AWS-managed (rds!...) — those are matched via ARN tag not name.
            has_rds_prefix = bool(RDS_PREFIX_PATTERN.search(secret_name))
            is_aws_managed = secret_name.startswith('rds!')
            if not has_rds_prefix and not is_aws_managed:
                continue

            # ── Step 2: match against this instance ───────────────────────────
            match = match_secret_to_instance(
                secret_name, secret_tags, instance_id, instance_tags
            )

            if not match['matched']:
                continue

            # ── Extract rotation info ─────────────────────────────────────────
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
                  + (f"  (app={match['app_name']}, env={match['environment']})"
                     if match.get('app_name') else ''))

        # ── Promote the best-priority secret to top-level fields ──────────────
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

def _strip_none(obj):
    """
    Recursively remove None values from dicts/lists so DynamoDB never sees them.
    DynamoDB rejects None — it causes the entire attribute to be silently dropped
    or raises a serialization error, which is why secrets disappear from records.
    """
    if isinstance(obj, dict):
        return {k: _strip_none(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_strip_none(i) for i in obj if i is not None]
    return obj


def store_instances(instances, scan_date, scan_timestamp):
    """Store instances in DynamoDB with RDS prefix."""
    # ── Deduplicate by PK+SK before writing ──────────────────────────────────
    # Duplicates happen when:
    #   • The same instance ARN appears in multiple region scans (rare but possible)
    #   • A Lambda retry re-processes the same instance in the same scan window
    # SK includes region so instances with the same id in different regions
    # get separate records rather than overwriting each other.
    unique_items = {}
    for instance in instances:
        item = _strip_none(
            json.loads(json.dumps(instance), parse_float=Decimal)
        )

        pk  = f"RDS#ACCOUNT#{instance['account_id']}"
        sk  = f"INSTANCE#{instance['region']}#{instance['id']}#{scan_timestamp}"
        key = f"{pk}#{sk}"

        item['PK']           = pk
        item['SK']           = sk
        item['GSI1PK']       = f"RDS#DATE#{scan_date}"
        item['GSI1SK']       = f"ACCOUNT#{instance['account_id']}#INSTANCE#{instance['id']}"
        item['resourceType'] = 'RDS'
        item['TTL']          = int((datetime.now() + timedelta(days=90)).timestamp())

        if key in unique_items:
            print(f"  [dedup] Skipping duplicate: {instance['id']} ({instance['region']})")
        else:
            unique_items[key] = item

    # ── Write in batches of 25 (DynamoDB batch_writer limit) ─────────────────
    items = list(unique_items.values())
    with table.batch_writer() as batch:
        for item in items:
            batch.put_item(Item=item)

    print(f"Stored {len(items)} instances in DynamoDB "
          f"({len(instances) - len(items)} duplicates skipped)")


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
