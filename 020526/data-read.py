import boto3
import json
import os
from datetime import datetime, timedelta
from decimal import Decimal
from boto3.dynamodb.conditions import Key, Attr

# Environment variables
DYNAMODB_TABLE = os.environ.get('DYNAMODB_TABLE', 'RDSSecurityAudit')

# DynamoDB client
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(DYNAMODB_TABLE)


class DecimalEncoder(json.JSONEncoder):
    """Helper class to convert Decimal to int/float for JSON serialization"""
    def default(self, obj):
        if isinstance(obj, Decimal):
            return int(obj) if obj % 1 == 0 else float(obj)
        return super(DecimalEncoder, self).default(obj)


def lambda_handler(event, context):
    """
    Enhanced API Gateway Lambda handler supporting combined RDS + EC2 data
    When no resource_type is specified, returns BOTH RDS and EC2 data combined
    """
    
    print(f"Event: {json.dumps(event)}")
    
    # CORS headers
    headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-API-Key',
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
    }
    
    try:
        # Handle OPTIONS request (CORS preflight)
        if event.get('httpMethod') == 'OPTIONS':
            return {
                'statusCode': 200,
                'headers': headers,
                'body': ''
            }
        
        # Parse request
        http_method = event.get('httpMethod', 'GET')
        path = event.get('path', '')
        query_params = event.get('queryStringParameters') or {}
        body = event.get('body')
        
        # Parse filters from POST body or query params
        if http_method == 'POST' and body:
            filters = json.loads(body)
        else:
            filters = query_params.copy()
        
        # Route to handler - by default, get COMBINED data (RDS + EC2)
        result = query_combined_instances(filters)
        
        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps(result, cls=DecimalEncoder)
        }
        
    except Exception as e:
        print(f"ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({
                'error': str(e),
                'message': 'Internal server error'
            })
        }


def query_combined_instances(filters):
    """
    Query BOTH RDS and EC2 instances and combine them
    This is the main function for the existing UI
    """
    
    # Extract filters
    date = filters.get('date') or filters.get('scan_date')
    account_id = filters.get('account_id')
    tag_key = filters.get('tagKey') or filters.get('tag_key')
    tag_value = filters.get('tagValue') or filters.get('tag_value')
    region = filters.get('region')
    
    print(f"Combined query - date={date}, account={account_id}, tag={tag_key}={tag_value}, region={region}")
    
    # Get RDS instances
    rds_instances = []
    if date:
        rds_instances = query_by_date(date, 'RDS')
    elif account_id:
        rds_instances = query_by_account(account_id, 'RDS')
    else:
        # Get latest RDS data
        rds_result = get_latest_scan('RDS')
        rds_instances = rds_result.get('instances', [])
    
    print(f"Retrieved {len(rds_instances)} RDS instances")
    
    # Get EC2 instances
    ec2_instances = []
    if date:
        ec2_instances = query_by_date(date, 'EC2')
    elif account_id:
        ec2_instances = query_by_account(account_id, 'EC2')
    else:
        # Get latest EC2 data
        ec2_result = get_latest_scan('EC2')
        ec2_instances = ec2_result.get('instances', [])
    
    print(f"Retrieved {len(ec2_instances)} EC2 instances")
    
    # Apply tag filters to both
    if tag_key and tag_value:
        print(f"Applying tag filter: {tag_key}={tag_value}")
        rds_instances = filter_by_tag(rds_instances, tag_key, tag_value)
        ec2_instances = filter_by_tag(ec2_instances, tag_key, tag_value)
        print(f"After tag filter: {len(rds_instances)} RDS, {len(ec2_instances)} EC2")
    
    # Apply account filter if needed
    if account_id and date:
        rds_instances = [i for i in rds_instances if i.get('account_id') == account_id]
        ec2_instances = [i for i in ec2_instances if i.get('account_id') == account_id]
    
    # Apply region filter
    if region:
        rds_instances = [i for i in rds_instances if i.get('region') == region]
        ec2_instances = [i for i in ec2_instances if i.get('region') == region]
    
    # Convert EC2 instances to look like platform instances in the UI
    # Add necessary fields that the UI expects
    for ec2_inst in ec2_instances:
        # Map EC2 fields to RDS-like structure for UI compatibility
        ec2_inst['engine'] = f"EC2 {ec2_inst.get('instanceType', 'Unknown')}"
        ec2_inst['version'] = ec2_inst.get('platform', 'Linux/Unix')
        
        # Add platform-specific data to tags for UI display
        if 'tags' not in ec2_inst:
            ec2_inst['tags'] = {}
        
        # Force EC2 instances to appear in Platform category
        if 'Component' not in ec2_inst['tags'] and 'component' not in ec2_inst['tags']:
            ec2_inst['tags']['Component'] = 'platform'
        
        # Map encryption data for UI
        if 'encryption' not in ec2_inst:
            ec2_inst['encryption'] = {}
        
        # Use EBS encryption status
        ec2_inst['encryption']['atRest'] = ec2_inst.get('storage', {}).get('allEncrypted', False)
        
        # EC2 doesn't have in-transit encryption in the same way
        # We'll use IMDSv2 as a security indicator
        ec2_inst['encryption']['inTransit'] = ec2_inst.get('metadata', {}).get('imdsv2Required', False)
        ec2_inst['encryption']['inTransitEnforced'] = ec2_inst.get('metadata', {}).get('imdsv2Required', False)
        
        # Map network data
        if 'network' not in ec2_inst:
            ec2_inst['network'] = {}
        
        ec2_inst['network']['publiclyAccessible'] = ec2_inst.get('network', {}).get('hasPublicIp', False)
    
    # Combine instances - RDS first, then EC2
    combined_instances = rds_instances + ec2_instances
    
    print(f"Final combined result: {len(combined_instances)} total instances ({len(rds_instances)} RDS + {len(ec2_instances)} EC2)")
    
    return {
        'instances': combined_instances,
        'count': len(combined_instances),
        'rds_count': len(rds_instances),
        'ec2_count': len(ec2_instances),
        'filters': filters
    }


def get_latest_scan(resource_type='RDS'):
    """Get the most recent scan data for a specific resource type"""
    try:
        today = datetime.now().strftime('%Y-%m-%d')
        yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
        
        # Try today first
        instances = query_by_date(today, resource_type)
        
        # If no data for today, try yesterday
        if not instances:
            print(f"No {resource_type} data found for {today}, trying {yesterday}")
            instances = query_by_date(yesterday, resource_type)
        
        # If still no data, try last 7 days
        if not instances:
            print(f"No {resource_type} data found for today or yesterday, searching last 7 days")
            for days_back in range(2, 8):
                date = (datetime.now() - timedelta(days=days_back)).strftime('%Y-%m-%d')
                print(f"Trying {date}...")
                instances = query_by_date(date, resource_type)
                if instances:
                    print(f"Found {resource_type} data from {date}")
                    break
        
        scan_date = today if instances else yesterday
        
        return {
            'instances': instances,
            'count': len(instances),
            'scan_date': scan_date,
            'resource_type': resource_type
        }
        
    except Exception as e:
        print(f"Error getting latest scan for {resource_type}: {str(e)}")
        raise


def query_by_date(scan_date, resource_type='RDS'):
    """Query all instances for a specific date and resource type using GSI1"""
    print(f"Querying {resource_type} by date: {scan_date}")
    
    try:
        # Build the GSI1PK based on resource type
        gsi_pk = f"{resource_type}#DATE#{scan_date}"
        
        response = table.query(
            IndexName='GSI1',
            KeyConditionExpression=Key('GSI1PK').eq(gsi_pk),
            ScanIndexForward=False  # Most recent first
        )
        
        items = response.get('Items', [])
        
        # Handle pagination
        while 'LastEvaluatedKey' in response:
            response = table.query(
                IndexName='GSI1',
                KeyConditionExpression=Key('GSI1PK').eq(gsi_pk),
                ExclusiveStartKey=response['LastEvaluatedKey'],
                ScanIndexForward=False
            )
            items.extend(response.get('Items', []))
        
        print(f"Retrieved {len(items)} total {resource_type} items before deduplication")
        
        # Sort items by scan_timestamp (newest first)
        items.sort(key=lambda x: x.get('scan_timestamp', ''), reverse=True)
        
        # Get only the latest scan for each instance
        instances_map = {}
        for item in items:
            instance_id = item.get('id')
            if instance_id not in instances_map:
                instances_map[instance_id] = clean_instance_data(item)
        
        instances = list(instances_map.values())
        print(f"Found {len(instances)} unique {resource_type} instances for date {scan_date}")
        
        return instances
        
    except Exception as e:
        print(f"Error querying {resource_type} by date: {str(e)}")
        import traceback
        traceback.print_exc()
        return []


def query_by_account(account_id, resource_type='RDS'):
    """Query instances for a specific account and resource type"""
    print(f"Querying {resource_type} by account: {account_id}")
    
    try:
        # Build the PK based on resource type
        pk = f"{resource_type}#ACCOUNT#{account_id}"
        
        response = table.query(
            KeyConditionExpression=Key('PK').eq(pk),
            ScanIndexForward=False,
            Limit=100  # Get most recent 100
        )
        
        items = response.get('Items', [])
        
        print(f"Retrieved {len(items)} total {resource_type} items before deduplication")
        
        # Sort items by scan_timestamp (newest first)
        items.sort(key=lambda x: x.get('scan_timestamp', ''), reverse=True)
        
        # Get unique instances (latest only)
        instances_map = {}
        for item in items:
            instance_id = item.get('id')
            if instance_id not in instances_map:
                instances_map[instance_id] = clean_instance_data(item)
        
        instances = list(instances_map.values())
        print(f"Found {len(instances)} unique {resource_type} instances for account {account_id}")
        
        return instances
        
    except Exception as e:
        print(f"Error querying {resource_type} by account: {str(e)}")
        import traceback
        traceback.print_exc()
        return []


def filter_by_tag(instances, tag_key, tag_value):
    """Filter instances by tag"""
    print(f"Filtering by tag: {tag_key}={tag_value}")
    
    filtered = []
    for instance in instances:
        tags = instance.get('tags', {})
        if tag_key in tags and tags[tag_key] == tag_value:
            filtered.append(instance)
    
    print(f"Filtered to {len(filtered)} instances")
    return filtered


def clean_instance_data(item):
    """Remove DynamoDB-specific fields from instance data"""
    # Remove PK, SK, GSI keys, TTL
    item.pop('PK', None)
    item.pop('SK', None)
    item.pop('GSI1PK', None)
    item.pop('GSI1SK', None)
    item.pop('TTL', None)
    
    return item
