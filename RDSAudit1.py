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
        regions = ['us-east-1', 'us-west-2', 'eu-west-1']  # Fallback to common regions
    
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
                                    'inTransit': check_ssl_enforcement(rds_client, db),
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
                                    'passwordRotation': False  # Would need to check Secrets Manager
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
            'Access-Control-Allow-Origin': '*'  # Enable CORS
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

def check_ssl_enforcement(rds_client, db):
    """Check if SSL/TLS is enforced via parameter groups"""
    try:
        if not db.get('DBParameterGroups'):
            return False
            
        pg_name = db['DBParameterGroups'][0]['DBParameterGroupName']
        
        # Get parameters
        paginator = rds_client.get_paginator('describe_db_parameters')
        
        for page in paginator.paginate(DBParameterGroupName=pg_name, Source='user'):
            for param in page.get('Parameters', []):
                # Check for SSL enforcement parameter (varies by engine)
                if param['ParameterName'] in ['rds.force_ssl', 'require_secure_transport']:
                    return param.get('ParameterValue') == '1'
        
        return False
        
    except Exception as e:
        print(f"Error checking SSL enforcement: {str(e)}")
        return False