"""
AI Query Lambda with AWS Bedrock - FIXED VERSION
Uses existing RDS API endpoint for data
Improved error logging to diagnose Bedrock issues
"""

import json
import boto3
import urllib3
from datetime import datetime, timezone

# Initialize clients
http = urllib3.PoolManager()

# Your existing API endpoint
EXISTING_API_ENDPOINT = 'https://qknyl8fst0.execute-api.us-west-2.amazonaws.com/prod/instances'
EXISTING_API_KEY = 'pw9aJ94jdb2MEiM3m5R6b7RscmnqrFCY4TWf7Hga'

def lambda_handler(event, context):
    """Main handler for AI queries with Bedrock"""
    try:
        # Parse request
        if isinstance(event.get('body'), str):
            body = json.loads(event['body'])
        else:
            body = event.get('body', {})
        
        query = body.get('query', '')
        
        if not query:
            return create_response(400, {'error': 'Query parameter required'})
        
        print(f"Processing query: {query}")
        
        # Get data from existing RDS API
        instances_data = get_instances_from_api()
        
        if not instances_data:
            return create_response(500, {'error': 'Could not fetch instance data'})
        
        print(f"Fetched {len(instances_data.get('instances', []))} instances from API")
        
        # Query Bedrock with context
        ai_response = query_bedrock(query, instances_data)
        
        return create_response(200, {
            'success': True,
            'query': query,
            'response': ai_response,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'data_source': 'rds_api',
            'instance_count': len(instances_data.get('instances', []))
        })
        
    except Exception as e:
        print(f"Lambda handler error: {str(e)}")
        import traceback
        traceback.print_exc()
        return create_response(500, {'success': False, 'error': str(e)})

def create_response(status_code, body):
    """Create API Gateway response"""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,X-API-Key',
            'Access-Control-Allow-Methods': 'POST,OPTIONS'
        },
        'body': json.dumps(body, default=str)
    }

def get_instances_from_api():
    """Fetch instances from existing RDS API endpoint"""
    try:
        print(f"Calling RDS API: {EXISTING_API_ENDPOINT}")
        
        # Call existing API
        response = http.request(
            'POST',
            EXISTING_API_ENDPOINT,
            body=json.dumps({}).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'X-API-Key': EXISTING_API_KEY
            }
        )
        
        if response.status == 200:
            data = json.loads(response.data.decode('utf-8'))
            print(f"RDS API success: {len(data.get('instances', []))} instances")
            return data
        else:
            print(f"RDS API returned status {response.status}")
            return None
            
    except Exception as e:
        print(f"Error fetching from RDS API: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

def query_bedrock(query, instances_data):
    """Query AWS Bedrock with infrastructure context"""
    
    instances = instances_data.get('instances', [])
    print(f"Building context for {len(instances)} instances")
    
    # Build context summary
    context = build_context(instances)
    
    # Build prompt for Bedrock
    prompt = f"""You are a security analyst assistant for AWS infrastructure. 
You have access to the current state of RDS and EC2 instances in the organization.

Current Infrastructure Data:
{context}

User Question: {query}

Provide a clear, concise answer based on the data above. If the question asks for:
- Non-compliant instances: List instances where encryption or network security has issues
- Encryption status: Check encryption.atRest for RDS and encryption.ebs_encrypted for EC2
- Public access: Check network.publiclyAccessible for RDS and network.has_public_ssh/has_public_rdp for EC2
- Counts: Provide accurate counts from the data
- Summaries: Aggregate and present the information clearly

Format your response in a helpful, structured way. Use bullet points where appropriate.
Be concise and actionable. Focus on security risks and recommendations.
"""

    try:
        print("Attempting to call Bedrock...")
        
        # Initialize Bedrock client here (lazy loading)
        bedrock = boto3.client('bedrock-runtime', region_name='us-east-1')
        
        # Call Bedrock (Claude 3 Sonnet)
        print("Invoking Bedrock model: anthropic.claude-3-sonnet-20240229-v1:0")
        response = bedrock.invoke_model(
            modelId='anthropic.claude-3-sonnet-20240229-v1:0',
            body=json.dumps({
                'anthropic_version': 'bedrock-2023-05-31',
                'max_tokens': 2000,
                'messages': [
                    {
                        'role': 'user',
                        'content': prompt
                    }
                ],
                'temperature': 0.3,
                'top_p': 0.9
            })
        )
        
        print("Bedrock response received")
        response_body = json.loads(response['body'].read())
        ai_answer = response_body['content'][0]['text']
        
        print(f"Bedrock answer length: {len(ai_answer)} characters")
        return ai_answer
        
    except Exception as e:
        error_type = type(e).__name__
        error_msg = str(e)
        
        print(f"❌ BEDROCK ERROR ({error_type}): {error_msg}")
        
        # Log specific error types
        if 'AccessDeniedException' in error_type:
            print("⚠️  ACCESS DENIED: Check IAM role has bedrock:InvokeModel permission")
        elif 'ValidationException' in error_type:
            print("⚠️  VALIDATION ERROR: Model may not be enabled in Bedrock")
        elif 'ResourceNotFoundException' in error_type:
            print("⚠️  MODEL NOT FOUND: Enable Claude 3 Sonnet in Bedrock console")
        elif 'ThrottlingException' in error_type:
            print("⚠️  THROTTLING: Too many requests to Bedrock")
        
        import traceback
        traceback.print_exc()
        
        print("Falling back to rule-based response")
        # Fallback to rule-based response
        return generate_fallback_response(query, instances)

def build_context(instances):
    """Build structured context for Bedrock"""
    
    # Separate by type
    rds_instances = [i for i in instances if i.get('engine') and not i.get('instance_type')]
    ec2_instances = [i for i in instances if i.get('instance_type')]
    
    context = {
        'total_instances': len(instances),
        'rds_instances': len(rds_instances),
        'ec2_instances': len(ec2_instances),
        'summary': {
            'rds': [],
            'ec2': []
        },
        'compliance_stats': {
            'total_non_compliant': 0,
            'encryption_issues': 0,
            'public_access_issues': 0
        }
    }
    
    # RDS summary
    for inst in rds_instances:
        is_compliant = (
            inst.get('encryption', {}).get('atRest', False) and
            inst.get('encryption', {}).get('inTransit', False) and
            not inst.get('network', {}).get('publiclyAccessible', False)
        )
        
        if not is_compliant:
            context['compliance_stats']['total_non_compliant'] += 1
            
        if not inst.get('encryption', {}).get('atRest', False):
            context['compliance_stats']['encryption_issues'] += 1
            
        if inst.get('network', {}).get('publiclyAccessible', False):
            context['compliance_stats']['public_access_issues'] += 1
        
        context['summary']['rds'].append({
            'id': inst.get('id'),
            'name': inst.get('name'),
            'app_id': inst.get('tags', {}).get('app_id', 'N/A'),
            'engine': inst.get('engine'),
            'region': inst.get('region'),
            'encrypted': inst.get('encryption', {}).get('atRest', False),
            'ssl_tls': inst.get('encryption', {}).get('inTransit', False),
            'public': inst.get('network', {}).get('publiclyAccessible', False),
            'compliant': is_compliant
        })
    
    # EC2 summary
    for inst in ec2_instances:
        is_compliant = (
            inst.get('encryption', {}).get('ebs_encrypted', False) and
            not inst.get('network', {}).get('has_public_ssh', False) and
            not inst.get('network', {}).get('has_public_rdp', False)
        )
        
        if not is_compliant:
            context['compliance_stats']['total_non_compliant'] += 1
            
        if not inst.get('encryption', {}).get('ebs_encrypted', False):
            context['compliance_stats']['encryption_issues'] += 1
            
        if inst.get('network', {}).get('has_public_ssh') or inst.get('network', {}).get('has_public_rdp'):
            context['compliance_stats']['public_access_issues'] += 1
        
        context['summary']['ec2'].append({
            'id': inst.get('id') or inst.get('instance_id'),
            'name': inst.get('name'),
            'app_id': inst.get('tags', {}).get('app_id', 'N/A'),
            'type': inst.get('instance_type'),
            'region': inst.get('region'),
            'encrypted': inst.get('encryption', {}).get('ebs_encrypted', False),
            'public_ssh': inst.get('network', {}).get('has_public_ssh', False),
            'public_rdp': inst.get('network', {}).get('has_public_rdp', False),
            'compliant': is_compliant
        })
    
    return json.dumps(context, indent=2)

def generate_fallback_response(query, instances):
    """Generate rule-based response if Bedrock fails"""
    query_lower = query.lower()
    
    print(f"Generating fallback response for query: {query}")
    
    # Separate by type
    rds_instances = [i for i in instances if i.get('engine') and not i.get('instance_type')]
    ec2_instances = [i for i in instances if i.get('instance_type')]
    
    # Non-compliant
    if 'non-compliant' in query_lower or 'issue' in query_lower or 'problem' in query_lower:
        non_compliant = []
        
        for inst in rds_instances:
            issues = []
            if not inst.get('encryption', {}).get('atRest', False):
                issues.append('No encryption at rest')
            if not inst.get('encryption', {}).get('inTransit', False):
                issues.append('No SSL/TLS')
            if inst.get('network', {}).get('publiclyAccessible', False):
                issues.append('Publicly accessible')
            
            if issues:
                non_compliant.append({
                    'name': inst.get('name'),
                    'type': 'RDS',
                    'issues': issues,
                    'app_id': inst.get('tags', {}).get('app_id', 'N/A'),
                    'region': inst.get('region')
                })
        
        for inst in ec2_instances:
            issues = []
            if not inst.get('encryption', {}).get('ebs_encrypted', False):
                issues.append('EBS not encrypted')
            if inst.get('network', {}).get('has_public_ssh', False):
                issues.append('Public SSH access')
            if inst.get('network', {}).get('has_public_rdp', False):
                issues.append('Public RDP access')
            
            if issues:
                non_compliant.append({
                    'name': inst.get('name'),
                    'type': 'EC2',
                    'issues': issues,
                    'app_id': inst.get('tags', {}).get('app_id', 'N/A'),
                    'region': inst.get('region')
                })
        
        if not non_compliant:
            return "✅ Great news! All instances are compliant with security policies."
        
        response = f"⚠️ Found {len(non_compliant)} non-compliant instance(s):\n\n"
        for item in non_compliant[:10]:
            response += f"• {item['name']} ({item['type']})\n"
            response += f"  App: {item['app_id']} | Region: {item['region']}\n"
            response += f"  Issues: {', '.join(item['issues'])}\n\n"
        
        if len(non_compliant) > 10:
            response += f"...and {len(non_compliant) - 10} more instances\n"
        
        return response
    
    # Encryption
    if 'encrypt' in query_lower:
        unencrypted_rds = [i for i in rds_instances if not i.get('encryption', {}).get('atRest', False)]
        unencrypted_ec2 = [i for i in ec2_instances if not i.get('encryption', {}).get('ebs_encrypted', False)]
        
        total = len(unencrypted_rds) + len(unencrypted_ec2)
        
        if total == 0:
            return "✅ All instances have encryption enabled!"
        
        response = f"🔒 Found {total} unencrypted instance(s):\n\n"
        response += f"RDS without encryption: {len(unencrypted_rds)}\n"
        response += f"EC2 without encryption: {len(unencrypted_ec2)}\n\n"
        
        for inst in unencrypted_rds[:5]:
            response += f"• {inst.get('name')} (RDS {inst.get('engine')})\n"
        for inst in unencrypted_ec2[:5]:
            response += f"• {inst.get('name')} (EC2 {inst.get('instance_type')})\n"
        
        return response
    
    # Public access
    if 'public' in query_lower:
        public_rds = [i for i in rds_instances if i.get('network', {}).get('publiclyAccessible', False)]
        public_ec2 = [i for i in ec2_instances 
                      if i.get('network', {}).get('has_public_ssh') or i.get('network', {}).get('has_public_rdp')]
        
        total = len(public_rds) + len(public_ec2)
        
        if total == 0:
            return "✅ No publicly accessible instances found!"
        
        response = f"🌐 Found {total} publicly accessible instance(s):\n\n"
        for inst in public_rds[:5]:
            response += f"• {inst.get('name')} (RDS - publicly accessible)\n"
        for inst in public_ec2[:5]:
            response += f"• {inst.get('name')} (EC2 - public SSH/RDP)\n"
        
        return response
    
    # Count by app
    if 'count' in query_lower or 'app' in query_lower:
        app_counts = {}
        for inst in instances:
            app_id = inst.get('tags', {}).get('app_id', 'no-app-id')
            app_counts[app_id] = app_counts.get(app_id, 0) + 1
        
        response = "📊 Instance count by APP ID:\n\n"
        for app_id, count in sorted(app_counts.items(), key=lambda x: x[1], reverse=True):
            response += f"• {app_id}: {count}\n"
        
        response += f"\n📈 Total: {len(instances)} instances"
        return response
    
    # Default summary
    return f"""📊 Infrastructure Summary:

Total instances: {len(instances)}
• RDS: {len(rds_instances)}
• EC2: {len(ec2_instances)}

Try asking:
• "Show non-compliant instances"
• "Which instances are not encrypted?"
• "List public instances"
• "Count by app_id"
"""
