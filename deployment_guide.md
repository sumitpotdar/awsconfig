# AWS Config Multi-Account Deployment Guide

## Prerequisites

### 1. AWS Organizations Setup
- Ensure all 47 accounts are part of AWS Organizations
- Identify Management Account IDs:
  - Non-Prod Management Account: `111111111111`
  - Prod Management Account: `222222222222`

### 2. Required Permissions
- Administrative access to both management accounts
- CloudFormation StackSets permission
- AWS Organizations integration enabled

### 3. Tools Required
```bash
# Install/Update AWS CLI
aws --version  # Should be 2.x

# Configure AWS CLI profiles
aws configure --profile nonprod-mgmt
aws configure --profile prod-mgmt
```

---

## Phase 1: Deploy Management Account Infrastructure

### Step 1.1: Deploy Non-Prod Management Account

```bash
# Switch to non-prod management account
export AWS_PROFILE=nonprod-mgmt

# Deploy management account stack
aws cloudformation create-stack \
  --stack-name aws-config-management \
  --template-body file://cfn-management-account.yaml \
  --parameters \
    ParameterKey=Environment,ParameterValue=nonprod \
    ParameterKey=OrganizationId,ParameterValue=o-xxxxxxxxxx \
    ParameterKey=AggregatorRegions,ParameterValue="us-east-1,us-west-2" \
    ParameterKey=AlertEmail,ParameterValue=nonprod-compliance@company.com \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1

# Wait for stack completion
aws cloudformation wait stack-create-complete \
  --stack-name aws-config-management \
  --region us-east-1

# Get outputs
aws cloudformation describe-stacks \
  --stack-name aws-config-management \
  --query 'Stacks[0].Outputs' \
  --region us-east-1
```

### Step 1.2: Deploy Prod Management Account

```bash
# Switch to prod management account
export AWS_PROFILE=prod-mgmt

# Deploy management account stack
aws cloudformation create-stack \
  --stack-name aws-config-management \
  --template-body file://cfn-management-account.yaml \
  --parameters \
    ParameterKey=Environment,ParameterValue=prod \
    ParameterKey=OrganizationId,ParameterValue=o-xxxxxxxxxx \
    ParameterKey=AggregatorRegions,ParameterValue="us-east-1,us-west-2" \
    ParameterKey=AlertEmail,ParameterValue=prod-compliance@company.com \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1

# Wait for completion
aws cloudformation wait stack-create-complete \
  --stack-name aws-config-management \
  --region us-east-1
```

---

## Phase 2: Deploy Config to Member Accounts

### Step 2.1: Create StackSet for Non-Prod Accounts

```bash
# Switch to non-prod management account
export AWS_PROFILE=nonprod-mgmt

# Get the S3 bucket name from management stack
NONPROD_BUCKET=$(aws cloudformation describe-stacks \
  --stack-name aws-config-management \
  --query 'Stacks[0].Outputs[?OutputKey==`ConfigAggregatorBucketName`].OutputValue' \
  --output text \
  --region us-east-1)

# Create StackSet
aws cloudformation create-stack-set \
  --stack-set-name aws-config-member-accounts \
  --template-body file://cfn-member-account.yaml \
  --parameters \
    ParameterKey=Environment,ParameterValue=nonprod \
    ParameterKey=ManagementAccountId,ParameterValue=111111111111 \
    ParameterKey=ConfigBucketName,ParameterValue=$NONPROD_BUCKET \
    ParameterKey=EnableAutoRemediation,ParameterValue=false \
  --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --region us-east-1

# Deploy to non-prod accounts (list all 32 account IDs)
aws cloudformation create-stack-instances \
  --stack-set-name aws-config-member-accounts \
  --accounts 333333333333 444444444444 555555555555 \
  --regions us-east-1 us-west-2 \
  --operation-preferences \
    RegionConcurrencyType=PARALLEL \
    MaxConcurrentPercentage=50 \
    FailureTolerancePercentage=10 \
  --region us-east-1

# Monitor deployment
aws cloudformation describe-stack-set-operation \
  --stack-set-name aws-config-member-accounts \
  --operation-id <operation-id> \
  --region us-east-1
```

### Step 2.2: Create StackSet for Prod Accounts

```bash
# Switch to prod management account
export AWS_PROFILE=prod-mgmt

# Get the S3 bucket name
PROD_BUCKET=$(aws cloudformation describe-stacks \
  --stack-name aws-config-management \
  --query 'Stacks[0].Outputs[?OutputKey==`ConfigAggregatorBucketName`].OutputValue' \
  --output text \
  --region us-east-1)

# Create StackSet
aws cloudformation create-stack-set \
  --stack-set-name aws-config-member-accounts \
  --template-body file://cfn-member-account.yaml \
  --parameters \
    ParameterKey=Environment,ParameterValue=prod \
    ParameterKey=ManagementAccountId,ParameterValue=222222222222 \
    ParameterKey=ConfigBucketName,ParameterValue=$PROD_BUCKET \
    ParameterKey=EnableAutoRemediation,ParameterValue=false \
  --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --region us-east-1

# Deploy to prod accounts (list all 13 account IDs)
aws cloudformation create-stack-instances \
  --stack-set-name aws-config-member-accounts \
  --accounts 666666666666 777777777777 888888888888 \
  --regions us-east-1 us-west-2 \
  --operation-preferences \
    RegionConcurrencyType=SEQUENTIAL \
    MaxConcurrentPercentage=30 \
    FailureTolerancePercentage=0 \
  --region us-east-1
```

---

## Phase 3: Deploy Remediation Lambda Functions

### Step 3.1: Package Lambda Functions

```bash
# Create deployment package
mkdir lambda-package
cd lambda-package

# Copy remediation script
cp ../remediation-scripts.py lambda_function.py

# Create zip
zip -r remediation-functions.zip lambda_function.py

# Upload to S3 (create bucket if needed)
aws s3 mb s3://config-remediation-lambdas-nonprod --region us-east-1
aws s3 cp remediation-functions.zip s3://config-remediation-lambdas-nonprod/

cd ..
```

### Step 3.2: Deploy Lambda Functions via StackSet

Create a new CloudFormation template for Lambda deployment:

```yaml
# cfn-remediation-lambdas.yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Remediation Lambda Functions for AWS Config'

Parameters:
  Environment:
    Type: String
    Default: nonprod
  
  LambdaS3Bucket:
    Type: String
    Description: S3 bucket containing Lambda code
  
  SNSTopicArn:
    Type: String
    Description: SNS topic for notifications

Resources:
  # Lambda function definitions here
  # (Refer to remediation scripts for function code)
```

Deploy:

```bash
# Create StackSet for Lambda functions
aws cloudformation create-stack-set \
  --stack-set-name aws-config-remediation-lambdas \
  --template-body file://cfn-remediation-lambdas.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false

# Deploy to member accounts
aws cloudformation create-stack-instances \
  --stack-set-name aws-config-remediation-lambdas \
  --accounts <all-account-ids> \
  --regions us-east-1 us-west-2
```

---

## Phase 4: Verification and Testing

### Step 4.1: Verify Config Recorders

```bash
# Check Config recorder status across all accounts
for account in 333333333333 444444444444; do
  echo "Checking account: $account"
  aws configservice describe-configuration-recorder-status \
    --profile $account \
    --region us-east-1
done
```

### Step 4.2: Verify Aggregation

```bash
# Check aggregator status
aws configservice describe-configuration-aggregators \
  --region us-east-1

# Get aggregated compliance summary
aws configservice get-aggregate-compliance-details-by-config-rule \
  --configuration-aggregator-name nonprod-aggregator \
  --config-rule-name encrypted-volumes \
  --region us-east-1
```

### Step 4.3: Test Remediation (Non-Prod Only)

```bash
# Create a test non-compliant resource
# Example: Unencrypted EBS volume
aws ec2 create-volume \
  --size 10 \
  --availability-zone us-east-1a \
  --encrypted false \
  --tag-specifications 'ResourceType=volume,Tags=[{Key=Name,Value=test-unencrypted}]'

# Wait for Config to detect non-compliance (5-15 minutes)
# Monitor CloudWatch logs for remediation Lambda execution

# Check SNS notifications
```

---

## Phase 5: Enable Auto-Remediation

**IMPORTANT**: Only enable after successful testing in non-prod

### Step 5.1: Update Non-Prod StackSet

```bash
# Update StackSet to enable auto-remediation
aws cloudformation update-stack-set \
  --stack-set-name aws-config-member-accounts \
  --use-previous-template \
  --parameters \
    ParameterKey=Environment,UsePreviousValue=true \
    ParameterKey=ManagementAccountId,UsePreviousValue=true \
    ParameterKey=ConfigBucketName,UsePreviousValue=true \
    ParameterKey=EnableAutoRemediation,ParameterValue=true \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1

# Deploy updates
aws cloudformation create-stack-instances \
  --stack-set-name aws-config-member-accounts \
  --accounts <all-nonprod-account-ids> \
  --regions us-east-1 us-west-2 \
  --operation-preferences \
    RegionConcurrencyType=PARALLEL \
    MaxConcurrentPercentage=50
```

### Step 5.2: Gradually Enable for Prod (After 2 Weeks)

```bash
# Enable for prod accounts in batches
# Start with 3 accounts
aws cloudformation create-stack-instances \
  --stack-set-name aws-config-member-accounts \
  --accounts 666666666666 777777777777 888888888888 \
  --regions us-east-1 us-west-2 \
  --operation-preferences \
    RegionConcurrencyType=SEQUENTIAL \
    MaxConcurrentPercentage=100

# Monitor for 48 hours
# Then proceed with remaining accounts
```

---

## Monitoring and Operations

### Daily Checks

```bash
# Get compliance summary
aws configservice get-compliance-summary-by-config-rule \
  --region us-east-1

# Check failed remediations
aws logs filter-log-events \
  --log-group-name /aws/lambda/ConfigRemediation \
  --filter-pattern "ERROR" \
  --start-time $(date -d '1 day ago' +%s)000
```

### Weekly Reports

```bash
# Generate compliance report
aws configservice describe-aggregate-compliance-by-config-rules \
  --configuration-aggregator-name nonprod-aggregator \
  --filters '{"ConfigRuleName":"encrypted-volumes"}' \
  --region us-east-1 > compliance-report-$(date +%Y%m%d).json
```

### Monthly Cost Review

```bash
# Get Config costs
aws ce get-cost-and-usage \
  --time-period Start=$(date -d '1 month ago' +%Y-%m-%d),End=$(date +%Y-%m-%d) \
  --granularity MONTHLY \
  --metrics UnblendedCost \
  --filter file://config-cost-filter.json
```

---

## Troubleshooting

### Config Recorder Not Starting

```bash
# Check IAM role
aws iam get-role --role-name AWSConfigRole-us-east-1

# Check S3 bucket policy
aws s3api get-bucket-policy --bucket aws-config-<account-id>-us-east-1

# Manually start recorder
aws configservice start-configuration-recorder \
  --configuration-recorder-name default
```

### Aggregator Not Receiving Data

```bash
# Check aggregator authorization
aws configservice describe-aggregation-authorizations \
  --region us-east-1

# Check organization settings
aws organizations describe-organization
```

### Remediation Lambda Failures

```bash
# Check Lambda logs
aws logs tail /aws/lambda/ConfigRemediation --follow

# Check IAM permissions
aws lambda get-function \
  --function-name ConfigRemediation \
  --query 'Configuration.Role'

# Test Lambda manually
aws lambda invoke \
  --function-name ConfigRemediation \
  --payload '{"RemediationType":"SECURITY_GROUP_OPEN_ACCESS","SecurityGroupId":"sg-xxxxx"}' \
  response.json
```

---

## Rollback Procedures

### Emergency Disable Auto-Remediation

```bash
# Disable auto-remediation immediately
aws cloudformation update-stack-set \
  --stack-set-name aws-config-member-accounts \
  --use-previous-template \
  --parameters \
    ParameterKey=EnableAutoRemediation,ParameterValue=false \
  --capabilities CAPABILITY_NAMED_IAM

# Deploy to all accounts
aws cloudformation create-stack-instances \
  --stack-set-name aws-config-member-accounts \
  --accounts <all-account-ids> \
  --regions us-east-1 us-west-2 \
  --operation-preferences MaxConcurrentPercentage=100
```

### Complete Rollback

```bash
# Delete StackSet instances
aws cloudformation delete-stack-instances \
  --stack-set-name aws-config-member-accounts \
  --accounts <all-account-ids> \
  --regions us-east-1 us-west-2 \
  --no-retain-stacks

# Wait for deletion
aws cloudformation wait stack-delete-complete \
  --stack-name <stack-name>

# Delete StackSet
aws cloudformation delete-stack-set \
  --stack-set-name aws-config-member-accounts

# Delete management stack
aws cloudformation delete-stack \
  --stack-name aws-config-management
```

---

## Best Practices

1. **Phased Deployment**: Always test in non-prod first
2. **Backup Configuration**: Export Config rules and settings before major changes
3. **Cost Monitoring**: Set up budget alerts for Config costs
4. **Regular Reviews**: Review compliance dashboards weekly
5. **Documentation**: Keep account IDs and architecture docs updated
6. **Change Management**: Use maintenance windows for remediation changes
7. **Audit Logging**: Enable CloudTrail for all Config API calls

---

## Support Contacts

- **AWS Support**: Open ticket via AWS Console
- **Internal Team**: aws-compliance@company.com
- **On-Call Engineer**: Use PagerDuty escalation

---

## Appendix: Account IDs Reference

### Non-Prod Accounts (32)
```
# Update with actual account IDs
333333333333  # nonprod-dev-1
444444444444  # nonprod-dev-2
...
```

### Prod Accounts (13)
```
# Update with actual account IDs
666666666666  # prod-web-1
777777777777  # prod-api-1
...
```