import boto3
import json

def lambda_handler(event, context):
    tag_key = event.get('tagKey')
    tag_value = event.get('tagValue')
    
    rds = boto3.client('rds')
    instances = []
    
    # Get all RDS instances across all regions
    ec2 = boto3.client('ec2')
    regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
    
    for region in regions:
        rds_client = boto3.client('rds', region_name=region)
        
        try:
            response = rds_client.describe_db_instances()
            
            for db in response['DBInstances']:
                db_arn = db['DBInstanceArn']
                
                # Get tags for this instance
                tags_response = rds_client.list_tags_for_resource(ResourceName=db_arn)
                tags = {tag['Key']: tag['Value'] for tag in tags_response['TagList']}
                
                # Filter by tag
                if tag_key in tags and tags[tag_key] == tag_value:
                    instances.append({
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
                            'vpcId': db['DBSubnetGroup']['VpcId'],
                            'securityGroups': [sg['VpcSecurityGroupId'] for sg in db['VpcSecurityGroups']]
                        },
                        'authentication': {
                            'iamEnabled': db.get('IAMDatabaseAuthenticationEnabled', False),
                            'passwordRotation': False  # Check Secrets Manager separately
                        },
                        'monitoring': {
                            'enhancedMonitoring': db.get('EnhancedMonitoringResourceArn') is not None,
                            'performanceInsights': db.get('PerformanceInsightsEnabled', False)
                        }
                    })
        except Exception as e:
            print(f"Error scanning region {region}: {str(e)}")
            continue
    
    return {
        'statusCode': 200,
        'body': json.dumps({'instances': instances})
    }

def check_ssl_enforcement(rds_client, db):
    """Check if SSL/TLS is enforced via parameter groups"""
    try:
        pg_name = db['DBParameterGroups'][0]['DBParameterGroupName']
        params = rds_client.describe_db_parameters(
            DBParameterGroupName=pg_name,
            Source='user'
        )
        
        for param in params.get('Parameters', []):
            if param['ParameterName'] == 'rds.force_ssl':
                return param.get('ParameterValue') == '1'
        return False
    except:
        return False