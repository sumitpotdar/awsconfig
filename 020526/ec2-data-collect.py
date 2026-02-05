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
    Main handler - Scans all EC2 instances across multiple AWS accounts
    Runs daily via EventBridge scheduled rule
    """
    print(f"Starting EC2 security audit at {datetime.now().isoformat()}")
    
    # Get current account ID
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
                
                # Scan all regions in this account
                instances = scan_account(account_id, account_name, credentials, scan_timestamp)
                
                # Store in DynamoDB
                store_instances(instances, scan_date, scan_timestamp)
                
                total_instances += len(instances)
                print(f"Found {len(instances)} EC2 instances in account {account_name}")
                
            except Exception as e:
                print(f"Error scanning account {account_id}: {str(e)}")
                continue
        
        # Store scan metadata
        store_scan_metadata(scan_date, scan_timestamp, total_instances, len(accounts))
        
        print(f"\n=== EC2 Scan Complete ===")
        print(f"Total instances scanned: {total_instances}")
        print(f"Accounts scanned: {len(accounts)}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'EC2 scan completed successfully',
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
            RoleSessionName=f"EC2Audit-{account_id}",
            DurationSeconds=3600
        )
        return response['Credentials']
    except ClientError as e:
        print(f"Failed to assume role in account {account_id}: {str(e)}")
        raise


def scan_account(account_id, account_name, credentials, scan_timestamp):
    """Scan all EC2 instances in all regions for a given account"""
    instances = []
    
    # Create EC2 client to get regions
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
            # Create EC2 client for this region
            if credentials:
                ec2_client = boto3.client(
                    'ec2',
                    region_name=region,
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken']
                )
            else:
                ec2_client = boto3.client('ec2', region_name=region)
            
            # Get all EC2 instances in this region
            paginator = ec2_client.get_paginator('describe_instances')
            
            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        try:
                            instance_data = process_instance(
                                ec2_client, instance, account_id, account_name, 
                                region, scan_timestamp
                            )
                            instances.append(instance_data)
                        except Exception as e:
                            print(f"Error processing instance {instance.get('InstanceId')}: {str(e)}")
                            continue
                        
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'UnauthorizedOperation':
                print(f"Not authorized for region {region}")
            else:
                print(f"Error in region {region}: {str(e)}")
            continue
            
    return instances


def process_instance(ec2_client, instance, account_id, account_name, region, scan_timestamp):
    """Process a single EC2 instance and extract security data"""
    instance_id = instance['InstanceId']
    
    # Get tags
    tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
    instance_name = tags.get('Name', instance_id)
    
    # Get EBS volumes and check encryption
    ebs_volumes = analyze_ebs_volumes(ec2_client, instance)
    
    # Get security groups
    security_groups = analyze_security_groups(ec2_client, instance)
    
    # Get network interfaces and public IPs
    network_info = analyze_network_interfaces(instance)
    
    # Check IMDSv2
    imds_info = analyze_imds(instance)
    
    # Check if Systems Manager (SSM) agent is installed/connected
    ssm_info = check_ssm_status(instance_id, region, account_id)
    
    # Build instance data
    instance_data = {
        'id': instance_id,
        'name': instance_name,
        'resourceType': 'EC2',  # Resource type identifier
        'instanceType': instance.get('InstanceType'),
        'state': instance['State']['Name'],
        'platform': instance.get('Platform', 'Linux/Unix'),
        'region': region,
        'account_id': account_id,
        'account_name': account_name,
        'arn': f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}",
        'tags': tags,
        'scan_timestamp': scan_timestamp,
        'launchTime': instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None,
        
        # Storage Security
        'storage': {
            'volumes': ebs_volumes['volumes'],
            'totalVolumes': ebs_volumes['total_count'],
            'encryptedVolumes': ebs_volumes['encrypted_count'],
            'unencryptedVolumes': ebs_volumes['unencrypted_count'],
            'allEncrypted': ebs_volumes['all_encrypted'],
            'encryptionDetails': ebs_volumes['details']
        },
        
        # Network Security
        'network': {
            'vpcId': instance.get('VpcId'),
            'subnetId': instance.get('SubnetId'),
            'privateIpAddress': instance.get('PrivateIpAddress'),
            'publicIpAddress': network_info['public_ip'],
            'hasPublicIp': network_info['has_public_ip'],
            'hasElasticIp': network_info['has_elastic_ip'],
            'securityGroups': security_groups['groups'],
            'hasOpenPorts': security_groups['has_open_ports'],
            'openToInternet': security_groups['open_to_internet'],
            'riskyPorts': security_groups['risky_ports']
        },
        
        # IAM and Access
        'iam': {
            'iamRole': instance.get('IamInstanceProfile', {}).get('Arn') if instance.get('IamInstanceProfile') else None,
            'hasIamRole': instance.get('IamInstanceProfile') is not None
        },
        
        # Metadata Service
        'metadata': {
            'imdsVersion': imds_info['version'],
            'imdsv2Required': imds_info['v2_required'],
            'httpTokens': imds_info['http_tokens'],
            'httpPutResponseHopLimit': imds_info['hop_limit']
        },
        
        # Monitoring and Management
        'monitoring': {
            'detailedMonitoring': instance.get('Monitoring', {}).get('State') == 'enabled',
            'ssmManaged': ssm_info['managed'],
            'ssmPingStatus': ssm_info['ping_status'],
            'ssmAgentVersion': ssm_info['agent_version']
        },
        
        # Compliance Flags (quick reference)
        'compliance': {
            'allVolumesEncrypted': ebs_volumes['all_encrypted'],
            'imdsv2Enforced': imds_info['v2_required'],
            'noPublicAccess': not network_info['has_public_ip'],
            'noOpenPorts': not security_groups['has_open_ports'],
            'hasIamRole': instance.get('IamInstanceProfile') is not None
        }
    }
    
    return instance_data


def analyze_ebs_volumes(ec2_client, instance):
    """Analyze EBS volumes attached to instance"""
    volumes_info = {
        'volumes': [],
        'total_count': 0,
        'encrypted_count': 0,
        'unencrypted_count': 0,
        'all_encrypted': True,
        'details': []
    }
    
    block_devices = instance.get('BlockDeviceMappings', [])
    
    if not block_devices:
        volumes_info['all_encrypted'] = False
        return volumes_info
    
    volumes_info['total_count'] = len(block_devices)
    
    for device in block_devices:
        if 'Ebs' not in device:
            continue
            
        volume_id = device['Ebs']['VolumeId']
        device_name = device['DeviceName']
        
        try:
            # Get volume details
            volume_response = ec2_client.describe_volumes(VolumeIds=[volume_id])
            
            if volume_response['Volumes']:
                volume = volume_response['Volumes'][0]
                encrypted = volume.get('Encrypted', False)
                kms_key_id = volume.get('KmsKeyId')
                volume_type = volume.get('VolumeType')
                size = volume.get('Size')
                
                volume_info = {
                    'volumeId': volume_id,
                    'deviceName': device_name,
                    'encrypted': encrypted,
                    'kmsKeyId': kms_key_id,
                    'volumeType': volume_type,
                    'size': size
                }
                
                volumes_info['volumes'].append(volume_info)
                
                if encrypted:
                    volumes_info['encrypted_count'] += 1
                    volumes_info['details'].append(f"{volume_id} ({device_name}): Encrypted")
                else:
                    volumes_info['unencrypted_count'] += 1
                    volumes_info['all_encrypted'] = False
                    volumes_info['details'].append(f"{volume_id} ({device_name}): NOT ENCRYPTED ⚠️")
                    print(f"  WARNING: Unencrypted volume {volume_id} on {device_name}")
                    
        except Exception as e:
            print(f"  Error checking volume {volume_id}: {str(e)}")
            volumes_info['all_encrypted'] = False
    
    return volumes_info


def analyze_security_groups(ec2_client, instance):
    """Analyze security groups for risky configurations"""
    sg_info = {
        'groups': [],
        'has_open_ports': False,
        'open_to_internet': False,
        'risky_ports': []
    }
    
    security_groups = instance.get('SecurityGroups', [])
    
    # Risky ports to check
    RISKY_PORTS = {
        22: 'SSH',
        3389: 'RDP',
        23: 'Telnet',
        21: 'FTP',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        1433: 'SQL Server',
        27017: 'MongoDB',
        6379: 'Redis'
    }
    
    for sg in security_groups:
        sg_id = sg['GroupId']
        sg_name = sg.get('GroupName', sg_id)
        
        try:
            # Get security group rules
            sg_response = ec2_client.describe_security_groups(GroupIds=[sg_id])
            
            if sg_response['SecurityGroups']:
                sg_details = sg_response['SecurityGroups'][0]
                
                risky_rules = []
                
                # Check ingress rules
                for rule in sg_details.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 0)
                    
                    # Check if open to 0.0.0.0/0
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp', '')
                        
                        if cidr == '0.0.0.0/0':
                            sg_info['open_to_internet'] = True
                            sg_info['has_open_ports'] = True
                            
                            # Check if it's a risky port
                            for port, service in RISKY_PORTS.items():
                                if from_port <= port <= to_port:
                                    risk = {
                                        'port': port,
                                        'service': service,
                                        'securityGroup': sg_id
                                    }
                                    sg_info['risky_ports'].append(risk)
                                    risky_rules.append(f"{service} (port {port}) open to 0.0.0.0/0")
                                    print(f"  WARNING: {sg_name} allows {service} from internet")
                
                sg_info['groups'].append({
                    'groupId': sg_id,
                    'groupName': sg_name,
                    'riskyRules': risky_rules
                })
                
        except Exception as e:
            print(f"  Error analyzing security group {sg_id}: {str(e)}")
    
    return sg_info


def analyze_network_interfaces(instance):
    """Analyze network interfaces and public IP assignments"""
    network_info = {
        'public_ip': None,
        'has_public_ip': False,
        'has_elastic_ip': False
    }
    
    # Check for public IP
    public_ip = instance.get('PublicIpAddress')
    if public_ip:
        network_info['public_ip'] = public_ip
        network_info['has_public_ip'] = True
    
    # Check network interfaces for Elastic IPs
    for ni in instance.get('NetworkInterfaces', []):
        if ni.get('Association', {}).get('PublicIp'):
            network_info['has_public_ip'] = True
            if not network_info['public_ip']:
                network_info['public_ip'] = ni['Association']['PublicIp']
        
        # Check if it's an Elastic IP
        if ni.get('Association', {}).get('IpOwnerId'):
            network_info['has_elastic_ip'] = True
    
    return network_info


def analyze_imds(instance):
    """Analyze Instance Metadata Service configuration"""
    imds_info = {
        'version': 'v1',
        'v2_required': False,
        'http_tokens': 'optional',
        'hop_limit': 1
    }
    
    metadata_options = instance.get('MetadataOptions', {})
    
    if metadata_options:
        http_tokens = metadata_options.get('HttpTokens', 'optional')
        imds_info['http_tokens'] = http_tokens
        imds_info['v2_required'] = (http_tokens == 'required')
        imds_info['version'] = 'v2' if http_tokens == 'required' else 'v1/v2'
        imds_info['hop_limit'] = metadata_options.get('HttpPutResponseHopLimit', 1)
        
        if http_tokens == 'optional':
            print(f"  NOTICE: IMDSv2 not enforced (allows v1)")
    
    return imds_info


def check_ssm_status(instance_id, region, account_id):
    """Check if instance is managed by Systems Manager"""
    ssm_info = {
        'managed': False,
        'ping_status': None,
        'agent_version': None
    }
    
    try:
        ssm = boto3.client('ssm', region_name=region)
        
        response = ssm.describe_instance_information(
            Filters=[
                {'Key': 'InstanceIds', 'Values': [instance_id]}
            ]
        )
        
        if response.get('InstanceInformationList'):
            instance_info = response['InstanceInformationList'][0]
            ssm_info['managed'] = True
            ssm_info['ping_status'] = instance_info.get('PingStatus')
            ssm_info['agent_version'] = instance_info.get('AgentVersion')
            
    except Exception as e:
        # SSM not available or not managed
        pass
    
    return ssm_info


def store_instances(instances, scan_date, scan_timestamp):
    """Store instances in DynamoDB"""
    with table.batch_writer() as batch:
        for instance in instances:
            # Convert to DynamoDB format
            item = json.loads(json.dumps(instance), parse_float=Decimal)
            
            # Add DynamoDB keys with EC2 prefix
            item['PK'] = f"EC2#ACCOUNT#{instance['account_id']}"
            item['SK'] = f"INSTANCE#{instance['id']}#{scan_timestamp}"
            item['GSI1PK'] = f"EC2#DATE#{scan_date}"
            item['GSI1SK'] = f"ACCOUNT#{instance['account_id']}#INSTANCE#{instance['id']}"
            
            # Add resource type for filtering
            item['resourceType'] = 'EC2'
            
            # Add TTL (keep data for 90 days)
            item['TTL'] = int((datetime.now() + timedelta(days=90)).timestamp())
            
            batch.put_item(Item=item)
    
    print(f"Stored {len(instances)} EC2 instances in DynamoDB")


def store_scan_metadata(scan_date, scan_timestamp, total_instances, accounts_scanned):
    """Store scan metadata"""
    item = {
        'PK': f"EC2#METADATA#{scan_date}",
        'SK': f"SCAN#{scan_timestamp}",
        'GSI1PK': 'EC2#METADATA',
        'GSI1SK': scan_timestamp,
        'resourceType': 'EC2',
        'scan_date': scan_date,
        'scan_timestamp': scan_timestamp,
        'total_instances': total_instances,
        'accounts_scanned': accounts_scanned,
        'TTL': int((datetime.now() + timedelta(days=90)).timestamp())
    }
    
    table.put_item(Item=item)
    print("Stored EC2 scan metadata")