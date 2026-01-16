import boto3
import json
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    """
    Lambda function to audit RDS instances filtered by app_id tag
    """
    # Get parameters from event
    tag_key = event.get('tagKey', 'app_id')
    tag_value = event.get('tagValue')
    
    if not tag_value:
        return {
            'statusCode': 400,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({'error': 'tagValue is required'})
        }
    
    print(f"Scanning RDS instances with tag: {tag_key}={tag_value}")
    
    instances = []
    
    # Get all AWS regions
    ec2 = boto3.client('ec2', region_name='us-east-1')
    try:
        regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
    except Exception as e:
        print(f"Error getting regions: {str(e)}")
        regions = ['us-east-1', 'us-west-2', 'eu-west-1']
    
    # Scan each region
    for region in regions:
        try:
            rds_client = boto3.client('rds', region_name=region)
            
            # Get all RDS instances in this region
            paginator = rds_client.get_paginator('describe_db_instances')
            
            for page in paginator.paginate():
                for db in page['DBInstances']:
                    try:
                        db_arn = db['DBInstanceArn']
                        
                        # Get tags for this instance
                        tags_response = rds_client.list_tags_for_resource(ResourceName=db_arn)
                        tags = {tag['Key']: tag['Value'] for tag in tags_response['TagList']}
                        
                        # Filter by tag
                        if tag_key in tags and tags[tag_key] == tag_value:
                            print(f"Found matching instance: {db['DBInstanceIdentifier']} in {region}")
                            
                            # Get SSL/TLS configuration
                            ssl_info = get_ssl_configuration(rds_client, db)
                            
                            instance_data = {
                                'id': db['DBInstanceIdentifier'],
                                'name': db.get('DBName') or db['DBInstanceIdentifier'],
                                'engine': db['Engine'],
                                'version': db['EngineVersion'],
                                'status': db['DBInstanceStatus'],
                                'region': region,
                                'tags': tags,
                                'encryption': {
                                    'atRest': db.get('StorageEncrypted', False),
                                    'inTransit': ssl_info['enabled'],
                                    'inTransitEnforced': ssl_info['enforced'],
                                    'certificateAuthority': ssl_info['ca_identifier'],
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
                                    'passwordRotation': False
                                },
                                'monitoring': {
                                    'enhancedMonitoring': db.get('EnhancedMonitoringResourceArn') is not None,
                                    'performanceInsights': db.get('PerformanceInsightsEnabled', False)
                                }
                            }
                            
                            instances.append(instance_data)
                            
                    except Exception as e:
                        print(f"Error processing instance {db.get('DBInstanceIdentifier', 'unknown')}: {str(e)}")
                        continue
                        
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'UnauthorizedOperation':
                print(f"Not authorized to access region {region}")
            else:
                print(f"Error scanning region {region}: {str(e)}")
            continue
        except Exception as e:
            print(f"Unexpected error in region {region}: {str(e)}")
            continue
    
    print(f"Total instances found: {len(instances)}")
    
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-API-Key',
            'Access-Control-Allow-Methods': 'POST,OPTIONS'
        },
        'body': json.dumps({
            'instances': instances,
            'count': len(instances),
            'filter': {
                'tagKey': tag_key,
                'tagValue': tag_value
            }
        })
    }


def get_ssl_configuration(rds_client, db):
    """
    Get comprehensive SSL/TLS configuration for RDS instance
    Returns dict with:
    - enabled: Whether SSL certificate is configured (available)
    - enforced: Whether SSL is required/enforced via parameter
    - ca_identifier: Certificate Authority identifier
    """
    ssl_info = {
        'enabled': False,
        'enforced': False,
        'ca_identifier': None
    }
    
    try:
        # Check if CA certificate is assigned
        # If CACertificateIdentifier exists, SSL is available/enabled
        ca_cert = db.get('CACertificateIdentifier')
        if ca_cert:
            ssl_info['enabled'] = True
            ssl_info['ca_identifier'] = ca_cert
            print(f"  SSL Certificate: {ca_cert} (SSL Available)")
        
        # Check if SSL is ENFORCED via parameter groups
        if db.get('DBParameterGroups'):
            pg_name = db['DBParameterGroups'][0]['DBParameterGroupName']
            
            try:
                # Get parameter group details
                paginator = rds_client.get_paginator('describe_db_parameters')
                
                for page in paginator.paginate(DBParameterGroupName=pg_name):
                    for param in page.get('Parameters', []):
                        # Check SSL enforcement parameters by engine type
                        param_name = param.get('ParameterName', '')
                        param_value = param.get('ParameterValue', '')
                        
                        # PostgreSQL and Amazon RDS for PostgreSQL
                        if param_name == 'rds.force_ssl' and param_value == '1':
                            ssl_info['enforced'] = True
                            print(f"  SSL Enforced: rds.force_ssl=1")
                            break
                        
                        # MySQL and MariaDB
                        elif param_name == 'require_secure_transport' and param_value == '1':
                            ssl_info['enforced'] = True
                            print(f"  SSL Enforced: require_secure_transport=1")
                            break
                        
                        # Oracle (check SQLNET.SSL_VERSION)
                        elif param_name == 'sqlnet.ssl_version' and param_value:
                            ssl_info['enforced'] = True
                            print(f"  SSL Enforced: sqlnet.ssl_version={param_value}")
                            break
                
            except Exception as e:
                print(f"  Warning: Could not check parameter group {pg_name}: {str(e)}")
        
        # If SSL is enabled but not enforced, log it
        if ssl_info['enabled'] and not ssl_info['enforced']:
            print(f"  SSL Available but NOT Enforced (clients can connect with or without SSL)")
        
    except Exception as e:
        print(f"  Error checking SSL configuration: {str(e)}")
    
    return ssl_info


def check_ssl_enforcement(rds_client, db):
    """
    Deprecated: Use get_ssl_configuration instead
    Kept for backward compatibility
    """
    ssl_info = get_ssl_configuration(rds_client, db)
    return ssl_info['enabled']  # Return True if SSL is at least available
