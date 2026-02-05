import boto3
import json
import os
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
    {'account_id': '243762578311', 'name': 'Sumit'}
]

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
    scan_date = datetime.now().strftime('%Y-%m-%d')
    total_instances = 0
    
    try:
        accounts = load_accounts_config()
        
        for account in accounts:
            account_id = account['account_id']
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


def load_accounts_config():
    """Load account configuration from Parameter Store or use default"""
    try:
        ssm = boto3.client('ssm')
        response = ssm.get_parameter(
            Name='/rds-audit/accounts',
            WithDecryption=True
        )
        return json.loads(response['Parameter']['Value'])
    except:
        print("Using default account configuration")
        return ACCOUNTS


def assume_role(account_id):
    """Assume cross-account role and return credentials"""
    sts = boto3.client('sts')
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


def scan_account(account_id, account_name, credentials, scan_timestamp):
    """Scan all RDS instances in all regions for a given account"""
    instances = []
    
    if credentials:
        ec2 = boto3.client(
            'ec2',
            region_name='us-east-1',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
    else:
        ec2 = boto3.client('ec2', region_name='us-east-1')
    
    try:
        regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
    except:
        regions = ['us-east-1', 'us-west-2', 'eu-west-1']
    
    for region in regions:
        try:
            if credentials:
                rds = boto3.client(
                    'rds',
                    region_name=region,
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken']
                )
            else:
                rds = boto3.client('rds', region_name=region)
            
            paginator = rds.get_paginator('describe_db_instances')
            
            for page in paginator.paginate():
                for db in page['DBInstances']:
                    try:
                        instance_data = process_instance(
                            rds, db, account_id, account_name, region, scan_timestamp
                        )
                        instances.append(instance_data)
                    except Exception as e:
                        print(f"Error processing instance {db.get('DBInstanceIdentifier')}: {str(e)}")
                        continue
                        
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'UnauthorizedOperation':
                print(f"Not authorized for region {region}")
            else:
                print(f"Error in region {region}: {str(e)}")
            continue
            
    return instances


def process_instance(rds, db, account_id, account_name, region, scan_timestamp):
    """Process a single RDS instance and extract security data"""
    instance_id = db['DBInstanceIdentifier']
    db_arn = db['DBInstanceArn']
    
    try:
        tags_response = rds.list_tags_for_resource(ResourceName=db_arn)
        tags = {tag['Key']: tag['Value'] for tag in tags_response['TagList']}
    except:
        tags = {}
    
    ssl_info = get_ssl_configuration(rds, db, region)
    secrets_info = check_secrets_manager(instance_id, region)
    
    instance_data = {
        'id': instance_id,
        'name': db.get('DBName') or instance_id,
        'resourceType': 'RDS',  # Resource type identifier
        'engine': db['Engine'],
        'version': db['EngineVersion'],
        'status': db['DBInstanceStatus'],
        'region': region,
        'account_id': account_id,
        'account_name': account_name,
        'arn': db_arn,
        'tags': tags,
        'scan_timestamp': scan_timestamp,
        'encryption': {
            'atRest': db.get('StorageEncrypted', False),
            'inTransit': ssl_info['enabled'],
            'inTransitEnforced': ssl_info['enforced'],
            'certificateAuthority': ssl_info['ca_identifier'],
            'certificateExpiryDate': ssl_info['cert_expiry_date'],
            'certificateDaysToExpiry': ssl_info['days_to_expiry'],
            'kmsKeyId': db.get('KmsKeyId')
        },
        'backups': {
            'automated': db.get('BackupRetentionPeriod', 0) > 0,
            'encrypted': db.get('StorageEncrypted', False),
            'retentionDays': db.get('BackupRetentionPeriod', 0)
        },
        'network': {
            'publiclyAccessible': db.get('PubliclyAccessible', False),
            'vpcId': db['DBSubnetGroup']['VpcId'] if db.get('DBSubnetGroup') else None,
            'securityGroups': [sg['VpcSecurityGroupId'] for sg in db.get('VpcSecurityGroups', [])]
        },
        'authentication': {
            'iamEnabled': db.get('IAMDatabaseAuthenticationEnabled', False),
            'passwordRotation': secrets_info['rotation_enabled'],
            'secretArn': secrets_info.get('secret_arn'),
            'lastRotated': secrets_info.get('last_rotated'),
            'rotationDays': secrets_info.get('rotation_days')
        },
        'monitoring': {
            'enhancedMonitoring': db.get('EnhancedMonitoringResourceArn') is not None,
            'performanceInsights': db.get('PerformanceInsightsEnabled', False)
        },
        'secrets': secrets_info
    }
    
    return instance_data


def get_ssl_configuration(rds, db, region):
    """Get SSL/TLS configuration including certificate expiry date"""
    ssl_info = {
        'enabled': False,
        'enforced': False,
        'ca_identifier': None,
        'cert_expiry_date': None,
        'days_to_expiry': None
    }
    
    try:
        ca_cert = db.get('CACertificateIdentifier')
        if ca_cert:
            ssl_info['enabled'] = True
            ssl_info['ca_identifier'] = ca_cert
            
            try:
                cert_response = rds.describe_certificates(
                    CertificateIdentifier=ca_cert
                )
                
                if cert_response.get('Certificates'):
                    certificate = cert_response['Certificates'][0]
                    
                    if certificate.get('ValidTill'):
                        valid_till = certificate['ValidTill']
                        ssl_info['cert_expiry_date'] = valid_till.isoformat()
                        
                        now = datetime.now(valid_till.tzinfo)
                        days_to_expiry = (valid_till - now).days
                        ssl_info['days_to_expiry'] = days_to_expiry
                        
                        print(f"  Certificate {ca_cert} expires on {valid_till.strftime('%Y-%m-%d')} ({days_to_expiry} days)")
                        
                        if days_to_expiry < 30:
                            print(f"  WARNING: Certificate expires in {days_to_expiry} days!")
                        elif days_to_expiry < 90:
                            print(f"  NOTICE: Certificate expires in {days_to_expiry} days")
                            
            except Exception as e:
                print(f"  Error fetching certificate details for {ca_cert}: {str(e)}")
        
        if db.get('DBParameterGroups'):
            pg_name = db['DBParameterGroups'][0]['DBParameterGroupName']
            
            try:
                paginator = rds.get_paginator('describe_db_parameters')
                
                for page in paginator.paginate(DBParameterGroupName=pg_name):
                    for param in page.get('Parameters', []):
                        param_name = param.get('ParameterName', '')
                        param_value = param.get('ParameterValue', '')
                        
                        if param_name == 'rds.force_ssl' and param_value == '1':
                            ssl_info['enforced'] = True
                            break
                        elif param_name == 'require_secure_transport' and param_value == '1':
                            ssl_info['enforced'] = True
                            break
            except Exception as e:
                print(f"  Error checking SSL enforcement: {str(e)}")
                
    except Exception as e:
        print(f"Error checking SSL: {str(e)}")
    
    return ssl_info


def check_secrets_manager(instance_id, region):
    """Check AWS Secrets Manager for RDS credentials and rotation status"""
    secrets_info = {
        'rotation_enabled': False,
        'secret_arn': None,
        'secret_name': None,
        'last_rotated': None,
        'rotation_days': None,
        'auto_rotation': False
    }
    
    try:
        secretsmanager = boto3.client('secretsmanager', region_name=region)
        paginator = secretsmanager.get_paginator('list_secrets')
        
        for page in paginator.paginate():
            for secret in page.get('SecretList', []):
                secret_name = secret.get('Name', '')
                tags = {tag['Key']: tag['Value'] for tag in secret.get('Tags', [])}
                
                is_rds_secret = False
                
                if tags.get('aws:rds:primaryDBInstanceArn'):
                    if instance_id in tags['aws:rds:primaryDBInstanceArn']:
                        is_rds_secret = True
                
                if instance_id.lower() in secret_name.lower():
                    is_rds_secret = True
                
                description = secret.get('Description', '')
                if instance_id in description:
                    is_rds_secret = True
                
                if is_rds_secret:
                    print(f"  Found secret: {secret_name}")
                    
                    secrets_info['secret_name'] = secret_name
                    secrets_info['secret_arn'] = secret.get('SecretArn')
                    
                    if secret.get('RotationEnabled'):
                        secrets_info['rotation_enabled'] = True
                        secrets_info['auto_rotation'] = True
                        
                        rotation_rules = secret.get('RotationRules', {})
                        secrets_info['rotation_days'] = rotation_rules.get('AutomaticallyAfterDays')
                    
                    if secret.get('LastRotatedDate'):
                        secrets_info['last_rotated'] = secret['LastRotatedDate'].isoformat()
                    elif secret.get('LastChangedDate'):
                        secrets_info['last_rotated'] = secret['LastChangedDate'].isoformat()
                    
                    break
        
        if secrets_info['secret_arn']:
            print(f"  Rotation enabled: {secrets_info['rotation_enabled']}")
            if secrets_info['rotation_days']:
                print(f"  Rotation interval: {secrets_info['rotation_days']} days")
        else:
            print(f"  No Secrets Manager secret found for {instance_id}")
            
    except Exception as e:
        print(f"  Error checking Secrets Manager: {str(e)}")
    
    return secrets_info


def store_instances(instances, scan_date, scan_timestamp):
    """Store instances in DynamoDB with RDS prefix"""
    with table.batch_writer() as batch:
        for instance in instances:
            item = json.loads(json.dumps(instance), parse_float=Decimal)
            
            # Add DynamoDB keys with RDS prefix
            item['PK'] = f"RDS#ACCOUNT#{instance['account_id']}"
            item['SK'] = f"INSTANCE#{instance['id']}#{scan_timestamp}"
            item['GSI1PK'] = f"RDS#DATE#{scan_date}"
            item['GSI1SK'] = f"ACCOUNT#{instance['account_id']}#INSTANCE#{instance['id']}"
            
            # Add resource type for filtering
            item['resourceType'] = 'RDS'
            
            # Add TTL (keep data for 90 days)
            item['TTL'] = int((datetime.now() + timedelta(days=90)).timestamp())
            
            batch.put_item(Item=item)
    
    print(f"Stored {len(instances)} instances in DynamoDB")


def store_scan_metadata(scan_date, scan_timestamp, total_instances, accounts_scanned):
    """Store scan metadata"""
    item = {
        'PK': f"RDS#METADATA#{scan_date}",
        'SK': f"SCAN#{scan_timestamp}",
        'GSI1PK': 'RDS#METADATA',
        'GSI1SK': scan_timestamp,
        'resourceType': 'RDS',
        'scan_date': scan_date,
        'scan_timestamp': scan_timestamp,
        'total_instances': total_instances,
        'accounts_scanned': accounts_scanned,
        'TTL': int((datetime.now() + timedelta(days=90)).timestamp())
    }
    
    table.put_item(Item=item)
    print("Stored scan metadata")