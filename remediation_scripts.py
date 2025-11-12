"""
AWS Config Auto-Remediation Lambda Functions
These functions automatically remediate non-compliant resources
"""

import boto3
import json
import os
from datetime import datetime

# Initialize AWS clients
ec2 = boto3.client('ec2')
rds = boto3.client('rds')
config = boto3.client('config')
sns = boto3.client('sns')

SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')

# ==========================================
# REMEDIATION 1: EBS Volume Encryption
# ==========================================

def remediate_ebs_encryption(event, context):
    """
    Remediates unencrypted EBS volumes by:
    1. Creating encrypted snapshot
    2. Creating encrypted volume from snapshot
    3. Tagging appropriately
    
    Note: Cannot automatically attach to running instances due to downtime
    """
    print(f"Event: {json.dumps(event)}")
    
    # Extract volume ID from Config event
    volume_id = None
    if 'configRuleNames' in event:
        # Called from Config Rule
        non_compliant_resources = event.get('detail', {}).get('newEvaluationResult', {}).get('complianceType')
        if non_compliant_resources == 'NON_COMPLIANT':
            volume_id = event['detail']['newEvaluationResult']['evaluationResultIdentifier']['evaluationResultQualifier']['resourceId']
    elif 'ResourceId' in event:
        # Direct invocation
        volume_id = event['ResourceId']
    
    if not volume_id:
        return {
            'statusCode': 400,
            'body': 'No volume ID provided'
        }
    
    try:
        # Check if volume exists and is unencrypted
        response = ec2.describe_volumes(VolumeIds=[volume_id])
        volume = response['Volumes'][0]
        
        if volume['Encrypted']:
            print(f"Volume {volume_id} is already encrypted")
            return {
                'statusCode': 200,
                'body': 'Volume already encrypted'
            }
        
        # Check if volume is attached
        attachments = volume.get('Attachments', [])
        if attachments:
            instance_id = attachments[0]['InstanceId']
            device = attachments[0]['Device']
            message = f"Volume {volume_id} is attached to instance {instance_id} as {device}. " \
                     f"Manual intervention required to avoid downtime. " \
                     f"Please create encrypted snapshot and replace volume during maintenance window."
            
            print(message)
            send_sns_notification(
                subject="EBS Encryption Remediation - Manual Action Required",
                message=message,
                volume_id=volume_id
            )
            
            # Tag volume for manual remediation
            ec2.create_tags(
                Resources=[volume_id],
                Tags=[
                    {'Key': 'ComplianceStatus', 'Value': 'RequiresManualRemediation'},
                    {'Key': 'RemediationDate', 'Value': datetime.utcnow().isoformat()},
                    {'Key': 'RemediationReason', 'Value': 'UnencryptedVolume-AttachedToInstance'}
                ]
            )
            
            return {
                'statusCode': 202,
                'body': message
            }
        
        # Volume is detached - safe to remediate automatically
        print(f"Creating encrypted snapshot of volume {volume_id}")
        
        snapshot_response = ec2.create_snapshot(
            VolumeId=volume_id,
            Description=f'Encrypted snapshot for compliance remediation of {volume_id}',
            TagSpecifications=[
                {
                    'ResourceType': 'snapshot',
                    'Tags': [
                        {'Key': 'Name', 'Value': f'Encrypted-{volume_id}'},
                        {'Key': 'OriginalVolumeId', 'Value': volume_id},
                        {'Key': 'RemediationType', 'Value': 'ComplianceRemediation'},
                        {'Key': 'CreatedBy', 'Value': 'AWSConfigRemediation'}
                    ]
                }
            ]
        )
        
        snapshot_id = snapshot_response['SnapshotId']
        print(f"Created snapshot: {snapshot_id}")
        
        # Wait for snapshot to complete (in production, use Step Functions)
        waiter = ec2.get_waiter('snapshot_completed')
        waiter.wait(SnapshotIds=[snapshot_id], WaiterConfig={'Delay': 15, 'MaxAttempts': 40})
        
        # Copy snapshot with encryption
        encrypted_snapshot_response = ec2.copy_snapshot(
            SourceSnapshotId=snapshot_id,
            SourceRegion=os.environ.get('AWS_REGION', 'us-east-1'),
            Description=f'Encrypted copy of {snapshot_id}',
            Encrypted=True,
            TagSpecifications=[
                {
                    'ResourceType': 'snapshot',
                    'Tags': [
                        {'Key': 'Name', 'Value': f'Encrypted-Copy-{volume_id}'},
                        {'Key': 'OriginalVolumeId', 'Value': volume_id},
                        {'Key': 'RemediationType', 'Value': 'EncryptedRemediation'}
                    ]
                }
            ]
        )
        
        encrypted_snapshot_id = encrypted_snapshot_response['SnapshotId']
        print(f"Created encrypted snapshot: {encrypted_snapshot_id}")
        
        # Tag original volume for deletion
        ec2.create_tags(
            Resources=[volume_id],
            Tags=[
                {'Key': 'ComplianceStatus', 'Value': 'ReplacedWithEncrypted'},
                {'Key': 'EncryptedSnapshotId', 'Value': encrypted_snapshot_id},
                {'Key': 'RemediationDate', 'Value': datetime.utcnow().isoformat()}
            ]
        )
        
        message = f"Successfully created encrypted snapshot {encrypted_snapshot_id} for volume {volume_id}. " \
                 f"Original volume tagged for review and potential deletion."
        
        send_sns_notification(
            subject="EBS Encryption Remediation - Successful",
            message=message,
            volume_id=volume_id
        )
        
        return {
            'statusCode': 200,
            'body': message,
            'encrypted_snapshot_id': encrypted_snapshot_id
        }
        
    except Exception as e:
        error_message = f"Error remediating volume {volume_id}: {str(e)}"
        print(error_message)
        send_sns_notification(
            subject="EBS Encryption Remediation - Failed",
            message=error_message,
            volume_id=volume_id
        )
        return {
            'statusCode': 500,
            'body': error_message
        }


# ==========================================
# REMEDIATION 2: Security Group Open Ports
# ==========================================

def remediate_security_group_open_access(event, context):
    """
    Remediates security groups with unrestricted SSH/RDP access (0.0.0.0/0)
    by removing the offending ingress rules
    """
    print(f"Event: {json.dumps(event)}")
    
    # Extract security group ID
    security_group_id = None
    if 'configRuleNames' in event:
        security_group_id = event['detail']['newEvaluationResult']['evaluationResultIdentifier']['evaluationResultQualifier']['resourceId']
    elif 'SecurityGroupId' in event:
        security_group_id = event['SecurityGroupId']
    
    if not security_group_id:
        return {
            'statusCode': 400,
            'body': 'No security group ID provided'
        }
    
    # Ports to check
    restricted_ports = [22, 3389]  # SSH and RDP
    
    try:
        # Get security group details
        response = ec2.describe_security_groups(GroupIds=[security_group_id])
        security_group = response['SecurityGroups'][0]
        
        ingress_rules = security_group.get('IpPermissions', [])
        rules_to_revoke = []
        
        # Find rules with 0.0.0.0/0 access on restricted ports
        for rule in ingress_rules:
            from_port = rule.get('FromPort')
            to_port = rule.get('ToPort')
            
            # Check if rule covers restricted ports
            for port in restricted_ports:
                if from_port and to_port and from_port <= port <= to_port:
                    # Check for 0.0.0.0/0
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            rules_to_revoke.append({
                                'IpProtocol': rule.get('IpProtocol', 'tcp'),
                                'FromPort': from_port,
                                'ToPort': to_port,
                                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                            })
                            break
        
        if not rules_to_revoke:
            print(f"No open access rules found for ports {restricted_ports}")
            return {
                'statusCode': 200,
                'body': 'No remediation needed'
            }
        
        # Revoke the rules
        for rule in rules_to_revoke:
            print(f"Revoking rule: {json.dumps(rule)}")
            ec2.revoke_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[rule]
            )
        
        # Tag the security group
        ec2.create_tags(
            Resources=[security_group_id],
            Tags=[
                {'Key': 'ComplianceRemediation', 'Value': 'OpenAccessRemoved'},
                {'Key': 'RemediationDate', 'Value': datetime.utcnow().isoformat()},
                {'Key': 'RevokedRules', 'Value': str(len(rules_to_revoke))}
            ]
        )
        
        message = f"Successfully removed {len(rules_to_revoke)} open access rule(s) from security group {security_group_id}"
        
        send_sns_notification(
            subject="Security Group Remediation - Successful",
            message=message,
            resource_id=security_group_id
        )
        
        return {
            'statusCode': 200,
            'body': message,
            'rules_revoked': len(rules_to_revoke)
        }
        
    except Exception as e:
        error_message = f"Error remediating security group {security_group_id}: {str(e)}"
        print(error_message)
        send_sns_notification(
            subject="Security Group Remediation - Failed",
            message=error_message,
            resource_id=security_group_id
        )
        return {
            'statusCode': 500,
            'body': error_message
        }


# ==========================================
# REMEDIATION 3: RDS Encryption at Rest
# ==========================================

def remediate_rds_storage_encryption(event, context):
    """
    Remediates unencrypted RDS instances by:
    1. Creating encrypted snapshot
    2. Tagging for manual restore (cannot automate without downtime)
    """
    print(f"Event: {json.dumps(event)}")
    
    # Extract DB instance ID
    db_instance_id = None
    if 'configRuleNames' in event:
        db_instance_id = event['detail']['newEvaluationResult']['evaluationResultIdentifier']['evaluationResultQualifier']['resourceId']
    elif 'DBInstanceId' in event:
        db_instance_id = event['DBInstanceId']
    
    if not db_instance_id:
        return {
            'statusCode': 400,
            'body': 'No DB instance ID provided'
        }
    
    try:
        # Get DB instance details
        response = rds.describe_db_instances(DBInstanceIdentifier=db_instance_id)
        db_instance = response['DBInstances'][0]
        
        if db_instance['StorageEncrypted']:
            print(f"DB instance {db_instance_id} is already encrypted")
            return {
                'statusCode': 200,
                'body': 'DB instance already encrypted'
            }
        
        # Create encrypted snapshot
        snapshot_id = f"{db_instance_id}-encrypted-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        
        print(f"Creating snapshot {snapshot_id} of DB instance {db_instance_id}")
        
        snapshot_response = rds.create_db_snapshot(
            DBSnapshotIdentifier=snapshot_id,
            DBInstanceIdentifier=db_instance_id,
            Tags=[
                {'Key': 'Purpose', 'Value': 'ComplianceRemediation'},
                {'Key': 'OriginalDBInstance', 'Value': db_instance_id},
                {'Key': 'CreatedBy', 'Value': 'AWSConfigRemediation'},
                {'Key': 'CreatedDate', 'Value': datetime.utcnow().isoformat()}
            ]
        )
        
        print(f"Created snapshot: {snapshot_id}")
        
        # Wait for snapshot to be available
        waiter = rds.get_waiter('db_snapshot_available')
        waiter.wait(DBSnapshotIdentifier=snapshot_id)
        
        # Copy snapshot with encryption
        encrypted_snapshot_id = f"{snapshot_id}-encrypted"
        
        print(f"Creating encrypted copy: {encrypted_snapshot_id}")
        
        encrypted_snapshot_response = rds.copy_db_snapshot(
            SourceDBSnapshotIdentifier=snapshot_id,
            TargetDBSnapshotIdentifier=encrypted_snapshot_id,
            KmsKeyId='alias/aws/rds',  # Use default RDS KMS key
            Tags=[
                {'Key': 'Purpose', 'Value': 'EncryptedComplianceRemediation'},
                {'Key': 'OriginalDBInstance', 'Value': db_instance_id},
                {'Key': 'OriginalSnapshot', 'Value': snapshot_id},
                {'Key': 'CreatedBy', 'Value': 'AWSConfigRemediation'}
            ]
        )
        
        message = f"""
RDS Encryption Remediation - Manual Action Required

DB Instance: {db_instance_id}
Encrypted Snapshot Created: {encrypted_snapshot_id}

ACTION REQUIRED:
1. Review the encrypted snapshot
2. During maintenance window, restore from encrypted snapshot
3. Update application connection strings to new DB instance
4. Delete old unencrypted DB instance

This process requires manual intervention to avoid application downtime.
        """
        
        send_sns_notification(
            subject="RDS Encryption Remediation - Manual Action Required",
            message=message,
            resource_id=db_instance_id
        )
        
        # Tag the DB instance
        rds.add_tags_to_resource(
            ResourceName=db_instance['DBInstanceArn'],
            Tags=[
                {'Key': 'ComplianceStatus', 'Value': 'RequiresManualRemediation'},
                {'Key': 'EncryptedSnapshotId', 'Value': encrypted_snapshot_id},
                {'Key': 'RemediationDate', 'Value': datetime.utcnow().isoformat()}
            ]
        )
        
        return {
            'statusCode': 202,
            'body': message,
            'encrypted_snapshot_id': encrypted_snapshot_id
        }
        
    except Exception as e:
        error_message = f"Error remediating RDS instance {db_instance_id}: {str(e)}"
        print(error_message)
        send_sns_notification(
            subject="RDS Encryption Remediation - Failed",
            message=error_message,
            resource_id=db_instance_id
        )
        return {
            'statusCode': 500,
            'body': error_message
        }


# ==========================================
# REMEDIATION 4: RDS Encryption in Transit
# ==========================================

def remediate_rds_transit_encryption(event, context):
    """
    Remediates RDS instances without SSL/TLS enforcement by:
    1. Modifying the DB parameter group to require SSL
    2. Applying the changes
    """
    print(f"Event: {json.dumps(event)}")
    
    # Extract DB instance ID
    db_instance_id = None
    if 'configRuleNames' in event:
        db_instance_id = event['detail']['newEvaluationResult']['evaluationResultIdentifier']['evaluationResultQualifier']['resourceId']
    elif 'DBInstanceId' in event:
        db_instance_id = event['DBInstanceId']
    
    if not db_instance_id:
        return {
            'statusCode': 400,
            'body': 'No DB instance ID provided'
        }
    
    try:
        # Get DB instance details
        response = rds.describe_db_instances(DBInstanceIdentifier=db_instance_id)
        db_instance = response['DBInstances'][0]
        
        engine = db_instance['Engine']
        db_parameter_groups = db_instance.get('DBParameterGroups', [])
        
        if not db_parameter_groups:
            return {
                'statusCode': 400,
                'body': 'No parameter group associated with DB instance'
            }
        
        parameter_group_name = db_parameter_groups[0]['DBParameterGroupName']
        
        # Determine SSL parameter based on engine
        ssl_parameters = []
        
        if engine.startswith('mysql') or engine.startswith('mariadb'):
            ssl_parameters = [
                {
                    'ParameterName': 'require_secure_transport',
                    'ParameterValue': '1',
                    'ApplyMethod': 'immediate'
                }
            ]
        elif engine.startswith('postgres'):
            ssl_parameters = [
                {
                    'ParameterName': 'rds.force_ssl',
                    'ParameterValue': '1',
                    'ApplyMethod': 'immediate'
                }
            ]
        else:
            message = f"SSL enforcement not implemented for engine: {engine}"
            print(message)
            return {
                'statusCode': 400,
                'body': message
            }
        
        # Modify parameter group
        print(f"Modifying parameter group {parameter_group_name}")
        
        rds.modify_db_parameter_group(
            DBParameterGroupName=parameter_group_name,
            Parameters=ssl_parameters
        )
        
        # Reboot instance to apply changes if needed
        # Note: In production, schedule during maintenance window
        print(f"Parameter group modified. Instance may need reboot for changes to take effect.")
        
        # Tag the DB instance
        rds.add_tags_to_resource(
            ResourceName=db_instance['DBInstanceArn'],
            Tags=[
                {'Key': 'ComplianceRemediation', 'Value': 'SSLEnforced'},
                {'Key': 'RemediationDate', 'Value': datetime.utcnow().isoformat()},
                {'Key': 'ModifiedParameterGroup', 'Value': parameter_group_name}
            ]
        )
        
        message = f"""
RDS SSL/TLS Enforcement Applied

DB Instance: {db_instance_id}
Engine: {engine}
Parameter Group: {parameter_group_name}
Parameter Modified: {ssl_parameters[0]['ParameterName']}

Note: A DB instance reboot may be required for changes to take effect.
Consider scheduling during the next maintenance window.
        """
        
        send_sns_notification(
            subject="RDS Transit Encryption Remediation - Successful",
            message=message,
            resource_id=db_instance_id
        )
        
        return {
            'statusCode': 200,
            'body': message
        }
        
    except Exception as e:
        error_message = f"Error remediating RDS instance {db_instance_id}: {str(e)}"
        print(error_message)
        send_sns_notification(
            subject="RDS Transit Encryption Remediation - Failed",
            message=error_message,
            resource_id=db_instance_id
        )
        return {
            'statusCode': 500,
            'body': error_message
        }


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def send_sns_notification(subject, message, resource_id=None, **kwargs):
    """Send SNS notification for remediation actions"""
    if not SNS_TOPIC_ARN:
        print("SNS_TOPIC_ARN not configured, skipping notification")
        return
    
    try:
        full_message = f"""
AWS Config Remediation Notification

{message}

Resource ID: {resource_id if resource_id else 'N/A'}
Timestamp: {datetime.utcnow().isoformat()}
Region: {os.environ.get('AWS_REGION', 'N/A')}
Account: {os.environ.get('AWS_ACCOUNT_ID', 'N/A')}

Additional Details:
{json.dumps(kwargs, indent=2)}
        """
        
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],  # SNS subject limit
            Message=full_message
        )
        print(f"SNS notification sent: {subject}")
    except Exception as e:
        print(f"Error sending SNS notification: {str(e)}")


# ==========================================
# LAMBDA HANDLER ROUTER
# ==========================================

def lambda_handler(event, context):
    """
    Main Lambda handler that routes to appropriate remediation function
    based on the remediation type specified in the event
    """
    remediation_type = event.get('RemediationType', '')
    
    if remediation_type == 'EBS_ENCRYPTION':
        return remediate_ebs_encryption(event, context)
    elif remediation_type == 'SECURITY_GROUP_OPEN_ACCESS':
        return remediate_security_group_open_access(event, context)
    elif remediation_type == 'RDS_STORAGE_ENCRYPTION':
        return remediate_rds_storage_encryption(event, context)
    elif remediation_type == 'RDS_TRANSIT_ENCRYPTION':
        return remediate_rds_transit_encryption(event, context)
    else:
        # Try to infer from Config event
        if 'configRuleNames' in event:
            rule_name = event.get('detail', {}).get('configRuleName', '')
            
            if 'encrypted-volumes' in rule_name:
                return remediate_ebs_encryption(event, context)
            elif 'restricted-ssh' in rule_name or 'restricted-rdp' in rule_name:
                return remediate_security_group_open_access(event, context)
            elif 'rds-storage-encrypted' in rule_name:
                return remediate_rds_storage_encryption(event, context)
            elif 'rds-transit-encryption' in rule_name:
                return remediate_rds_transit_encryption(event, context)
        
        return {
            'statusCode': 400,
            'body': f'Unknown remediation type: {remediation_type}'
        }