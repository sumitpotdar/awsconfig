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
    API Gateway Lambda handler
    Supports multiple operations:
    - GET /instances?date=2024-01-22 - Get all instances for a date
    - GET /instances?account_id=123456789 - Get instances for an account
    - GET /instances?tag_key=app_id&tag_value=APP001 - Filter by tags
    - GET /latest - Get latest scan data
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
        
        # Route to appropriate handler
        if path == '/latest' or query_params.get('latest') == 'true':
            result = get_latest_scan()
        elif http_method == 'POST':
            # Support POST for filtering (body contains filters)
            filters = json.loads(body) if body else {}
            result = query_instances(filters)
        else:
            # GET request with query parameters
            result = query_instances(query_params)
        
        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps(result, cls=DecimalEncoder)
        }
        
    except Exception as e:
        print(f"ERROR: {str(e)}")
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({
                'error': str(e),
                'message': 'Internal server error'
            })
        }


def get_latest_scan():
    """Get the most recent scan data"""
    try:
        # Get today's date and yesterday
        today = datetime.now().strftime('%Y-%m-%d')
        yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
        
        # Try today first
        instances = query_by_date(today)
        
        # If no data for today, try yesterday
        if not instances:
            instances = query_by_date(yesterday)
        
        return {
            'instances': instances,
            'count': len(instances),
            'scan_date': today if instances else yesterday
        }
        
    except Exception as e:
        print(f"Error getting latest scan: {str(e)}")
        raise


def query_instances(filters):
    """Query instances based on filters"""
    
    # Extract filters
    date = filters.get('date') or filters.get('scan_date')
    account_id = filters.get('account_id')
    tag_key = filters.get('tagKey') or filters.get('tag_key')
    tag_value = filters.get('tagValue') or filters.get('tag_value')
    region = filters.get('region')
    
    print(f"Filters: date={date}, account={account_id}, tag={tag_key}={tag_value}, region={region}")
    
    # Query by date (most common)
    if date:
        instances = query_by_date(date)
    elif account_id:
        instances = query_by_account(account_id)
    else:
        # Default to latest
        return get_latest_scan()
    
    # Apply additional filters
    if tag_key and tag_value:
        instances = filter_by_tag(instances, tag_key, tag_value)
    
    if account_id and date:
        instances = [i for i in instances if i.get('account_id') == account_id]
    
    if region:
        instances = [i for i in instances if i.get('region') == region]
    
    return {
        'instances': instances,
        'count': len(instances),
        'filters': filters
    }


def query_by_date(scan_date):
    """Query all instances for a specific date using GSI1"""
    print(f"Querying by date: {scan_date}")
    
    try:
        response = table.query(
            IndexName='GSI1',
            KeyConditionExpression=Key('GSI1PK').eq(f'DATE#{scan_date}'),
            ScanIndexForward=False  # Most recent first
        )
        
        items = response.get('Items', [])
        
        # Handle pagination
        while 'LastEvaluatedKey' in response:
            response = table.query(
                IndexName='GSI1',
                KeyConditionExpression=Key('GSI1PK').eq(f'DATE#{scan_date}'),
                ExclusiveStartKey=response['LastEvaluatedKey'],
                ScanIndexForward=False
            )
            items.extend(response.get('Items', []))
        
        # Get only the latest scan for each instance
        instances_map = {}
        for item in items:
            instance_id = item.get('id')
            if instance_id not in instances_map:
                instances_map[instance_id] = clean_instance_data(item)
        
        instances = list(instances_map.values())
        print(f"Found {len(instances)} instances for date {scan_date}")
        
        return instances
        
    except Exception as e:
        print(f"Error querying by date: {str(e)}")
        return []


def query_by_account(account_id):
    """Query instances for a specific account"""
    print(f"Querying by account: {account_id}")
    
    try:
        response = table.query(
            KeyConditionExpression=Key('PK').eq(f'ACCOUNT#{account_id}'),
            ScanIndexForward=False,
            Limit=100  # Get most recent 100
        )
        
        items = response.get('Items', [])
        
        # Get unique instances (latest only)
        instances_map = {}
        for item in items:
            instance_id = item.get('id')
            if instance_id not in instances_map:
                instances_map[instance_id] = clean_instance_data(item)
        
        instances = list(instances_map.values())
        print(f"Found {len(instances)} instances for account {account_id}")
        
        return instances
        
    except Exception as e:
        print(f"Error querying by account: {str(e)}")
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
