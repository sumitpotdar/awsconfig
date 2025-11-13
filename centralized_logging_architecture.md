# AWS Config Centralized S3 Logging Architecture

## Overview: How All Account Data Goes to Centralized Bucket

There are **two approaches** to centralize AWS Config data:

1. **Direct Delivery to Central Bucket** (Recommended)
2. **S3 Replication from Member Buckets** (Alternative)

---

## Approach 1: Direct Delivery to Central Bucket (Recommended)

### Architecture Flow

```
┌──────────────────────────────────────────────────────────┐
│              Member Account (Account A)                   │
│                                                           │
│  ┌─────────────────────────────────────────────────┐    │
│  │         AWS Config Service                       │    │
│  │  - Configuration Recorder                        │    │
│  │  - Delivery Channel                              │    │
│  └─────────────────────────────────────────────────┘    │
│                        │                                  │
│                        │ Writes directly                  │
│                        ▼                                  │
└────────────────────────┼──────────────────────────────────┘
                         │
                         │ Cross-Account S3 PUT
                         │ (Using S3 Bucket Policy)
                         ▼
┌──────────────────────────────────────────────────────────┐
│         Management Account (Central Account)              │
│                                                           │
│  ┌─────────────────────────────────────────────────┐    │
│  │   Central S3 Bucket                              │    │
│  │   aws-config-central-nonprod-123456789012        │    │
│  │                                                   │    │
│  │   Structure:                                     │    │
│  │   /AWSLogs/111111111111/Config/us-east-1/...    │    │
│  │   /AWSLogs/222222222222/Config/us-east-1/...    │    │
│  │   /AWSLogs/333333333333/Config/us-west-2/...    │    │
│  └─────────────────────────────────────────────────┘    │
│                        │                                  │
│                        ▼                                  │
│  ┌─────────────────────────────────────────────────┐    │
│  │      Config Aggregator                           │    │
│  │  - Reads from central bucket                     │    │
│  │  - Aggregates compliance data                    │    │
│  └─────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────┘
```

### How It Works

#### Step 1: Central S3 Bucket Configuration

The management account creates a central S3 bucket with a policy that allows **all member accounts** to write their Config data:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSConfigBucketPermissionsCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::aws-config-central-nonprod-123456789012",
      "Condition": {
        "StringEquals": {
          "aws:SourceOrgID": "o-xxxxxxxxxx"
        }
      }
    },
    {
      "Sid": "AWSConfigBucketExistenceCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::aws-config-central-nonprod-123456789012",
      "Condition": {
        "StringEquals": {
          "aws:SourceOrgID": "o-xxxxxxxxxx"
        }
      }
    },
    {
      "Sid": "AWSConfigBucketPutObject",
      "Effect": "Allow",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::aws-config-central-nonprod-123456789012/AWSLogs/*/Config/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control",
          "aws:SourceOrgID": "o-xxxxxxxxxx"
        }
      }
    }
  ]
}
```

**Key Points**:
- `aws:SourceOrgID` condition ensures only accounts in your organization can write
- Each account writes to its own prefix: `/AWSLogs/{AccountId}/Config/`
- `bucket-owner-full-control` ACL ensures management account can read all data

#### Step 2: Member Account Config Delivery Channel

Each member account's Config service is configured to write directly to the central bucket:

```yaml
ConfigDeliveryChannel:
  Type: AWS::Config::DeliveryChannel
  Properties:
    Name: default
    # Point to CENTRAL bucket in management account
    S3BucketName: aws-config-central-nonprod-123456789012
    ConfigSnapshotDeliveryProperties:
      DeliveryFrequency: TwentyFour_Hours
```

#### Step 3: Data Organization

The central bucket organizes data by account and region:

```
aws-config-central-nonprod-123456789012/
├── AWSLogs/
│   ├── 111111111111/              # Account 1
│   │   └── Config/
│   │       ├── us-east-1/
│   │       │   ├── 2025/11/13/
│   │       │   │   ├── ConfigSnapshot/
│   │       │   │   ├── ConfigHistory/
│   │       │   │   └── ConfigWritableAPICallsPercentage/
│   │       └── us-west-2/
│   │           └── 2025/11/13/
│   ├── 222222222222/              # Account 2
│   │   └── Config/
│   │       ├── us-east-1/
│   │       └── us-west-2/
│   ├── 333333333333/              # Account 3
│   └── ...                        # All 45 member accounts
```

### Advantages
✅ **Real-time delivery** - No replication lag  
✅ **Cost-effective** - No data transfer charges within same region  
✅ **Simpler architecture** - One S3 bucket to manage  
✅ **Native Config integration** - No custom code needed  
✅ **Automatic organization** - Config service handles folder structure  

---

## Updated CloudFormation Templates

### Template 1: Management Account Central Bucket

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Central S3 Bucket for AWS Config Data from All Member Accounts'

Parameters:
  Environment:
    Type: String
    AllowedValues:
      - prod
      - nonprod
    Default: nonprod
  
  OrganizationId:
    Type: String
    Description: AWS Organization ID (e.g., o-xxxxxxxxxx)

Resources:
  # Central S3 Bucket - All accounts write here
  CentralConfigBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub 'aws-config-central-${Environment}-${AWS::AccountId}'
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: aws:kms
              KMSMasterKeyID: !GetAtt ConfigKMSKey.Arn
      VersioningConfiguration:
        Status: Enabled
      LifecycleConfiguration:
        Rules:
          - Id: TransitionToIA
            Status: Enabled
            Transitions:
              - TransitionInDays: 30
                StorageClass: STANDARD_IA
          - Id: TransitionToGlacier
            Status: Enabled
            Transitions:
              - TransitionInDays: 90
                StorageClass: GLACIER
          - Id: DeleteOldData
            Status: Enabled
            ExpirationInDays: 365
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      Tags:
        - Key: Purpose
          Value: CentralizedConfigLogging
        - Key: Environment
          Value: !Ref Environment

  # Bucket Policy - Allow all org accounts to write
  CentralConfigBucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref CentralConfigBucket
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          # Allow Config service to check bucket ACL
          - Sid: AWSConfigBucketPermissionsCheck
            Effect: Allow
            Principal:
              Service: config.amazonaws.com
            Action: s3:GetBucketAcl
            Resource: !GetAtt CentralConfigBucket.Arn
            Condition:
              StringEquals:
                aws:SourceOrgID: !Ref OrganizationId
          
          # Allow Config service to list bucket
          - Sid: AWSConfigBucketExistenceCheck
            Effect: Allow
            Principal:
              Service: config.amazonaws.com
            Action: s3:ListBucket
            Resource: !GetAtt CentralConfigBucket.Arn
            Condition:
              StringEquals:
                aws:SourceOrgID: !Ref OrganizationId
          
          # Allow Config service from all org accounts to write
          - Sid: AWSConfigBucketPutObject
            Effect: Allow
            Principal:
              Service: config.amazonaws.com
            Action: s3:PutObject
            Resource: !Sub '${CentralConfigBucket.Arn}/AWSLogs/*/Config/*'
            Condition:
              StringEquals:
                s3:x-amz-acl: bucket-owner-full-control
                aws:SourceOrgID: !Ref OrganizationId
          
          # Allow management account to read all data
          - Sid: ManagementAccountReadAccess
            Effect: Allow
            Principal:
              AWS: !Sub 'arn:aws:iam::${AWS::AccountId}:root'
            Action:
              - s3:GetObject
              - s3:ListBucket
            Resource:
              - !GetAtt CentralConfigBucket.Arn
              - !Sub '${CentralConfigBucket.Arn}/*'

  # KMS Key for encryption
  ConfigKMSKey:
    Type: AWS::KMS::Key
    Properties:
      Description: KMS key for central Config bucket encryption
      KeyPolicy:
        Version: '2012-10-17'
        Statement:
          - Sid: Enable IAM User Permissions
            Effect: Allow
            Principal:
              AWS: !Sub 'arn:aws:iam::${AWS::AccountId}:root'
            Action: 'kms:*'
            Resource: '*'
          
          # Allow Config from all org accounts to use key
          - Sid: AllowConfigServiceEncryption
            Effect: Allow
            Principal:
              Service: config.amazonaws.com
            Action:
              - kms:Decrypt
              - kms:GenerateDataKey
              - kms:CreateGrant
            Resource: '*'
            Condition:
              StringEquals:
                aws:SourceOrgID: !Ref OrganizationId

  ConfigKMSKeyAlias:
    Type: AWS::KMS::Alias
    Properties:
      AliasName: !Sub 'alias/config-central-${Environment}'
      TargetKeyId: !Ref ConfigKMSKey

  # Config Aggregator
  ConfigurationAggregator:
    Type: AWS::Config::ConfigurationAggregator
    Properties:
      ConfigurationAggregatorName: !Sub '${Environment}-organization-aggregator'
      OrganizationAggregationSource:
        RoleArn: !GetAtt ConfigAggregatorRole.Arn
        AllAwsRegions: false
        AwsRegions:
          - us-east-1
          - us-west-2

  ConfigAggregatorRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub 'AWSConfigAggregatorRole-${Environment}'
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: config.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSConfigRoleForOrganizations
      Policies:
        - PolicyName: ReadCentralBucket
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:ListBucket
                Resource:
                  - !GetAtt CentralConfigBucket.Arn
                  - !Sub '${CentralConfigBucket.Arn}/*'
              - Effect: Allow
                Action:
                  - kms:Decrypt
                Resource: !GetAtt ConfigKMSKey.Arn

Outputs:
  CentralBucketName:
    Description: Central S3 bucket for all Config data
    Value: !Ref CentralConfigBucket
    Export:
      Name: !Sub '${Environment}-CentralConfigBucket'
  
  CentralBucketArn:
    Description: ARN of central bucket
    Value: !GetAtt CentralConfigBucket.Arn
    Export:
      Name: !Sub '${Environment}-CentralConfigBucketArn'
  
  KMSKeyId:
    Description: KMS key for encryption
    Value: !Ref ConfigKMSKey
    Export:
      Name: !Sub '${Environment}-ConfigKMSKey'
  
  AggregatorName:
    Description: Config Aggregator name
    Value: !Ref ConfigurationAggregator
```

### Template 2: Member Account Config (Points to Central Bucket)

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'AWS Config for Member Account - Writes to Central Bucket'

Parameters:
  Environment:
    Type: String
    AllowedValues:
      - prod
      - nonprod
  
  CentralBucketName:
    Type: String
    Description: Central S3 bucket name in management account
    # Example: aws-config-central-nonprod-111111111111
  
  ManagementAccountId:
    Type: String
    Description: Management account ID

Resources:
  # SNS Topic for local notifications
  ConfigTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: !Sub 'aws-config-notifications-${AWS::Region}'

  # IAM Role for Config
  ConfigRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub 'AWSConfigRole-${AWS::Region}'
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: config.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/ConfigRole
      Policies:
        # Permission to write to CENTRAL bucket
        - PolicyName: WriteToCentralBucket
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetBucketVersioning
                  - s3:PutObject
                  - s3:GetObject
                Resource:
                  - !Sub 'arn:aws:s3:::${CentralBucketName}'
                  - !Sub 'arn:aws:s3:::${CentralBucketName}/*'
        - PolicyName: SNSPublish
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: sns:Publish
                Resource: !Ref ConfigTopic

  # Configuration Recorder
  ConfigRecorder:
    Type: AWS::Config::ConfigurationRecorder
    Properties:
      Name: default
      RoleArn: !GetAtt ConfigRole.Arn
      RecordingGroup:
        AllSupported: true
        IncludeGlobalResourceTypes: true

  # Delivery Channel - Points to CENTRAL bucket
  ConfigDeliveryChannel:
    Type: AWS::Config::DeliveryChannel
    Properties:
      Name: default
      # CRITICAL: This writes to central bucket in management account
      S3BucketName: !Ref CentralBucketName
      SnsTopicARN: !Ref ConfigTopic
      ConfigSnapshotDeliveryProperties:
        DeliveryFrequency: TwentyFour_Hours

  # Auto-start Config Recorder
  StartConfigRecorder:
    Type: Custom::StartConfigRecorder
    DependsOn:
      - ConfigRecorder
      - ConfigDeliveryChannel
    Properties:
      ServiceToken: !GetAtt StartConfigRecorderFunction.Arn
      ConfigRecorderName: !Ref ConfigRecorder

  StartConfigRecorderFunction:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.11
      Handler: index.handler
      Role: !GetAtt StartConfigRecorderRole.Arn
      Timeout: 60
      Code:
        ZipFile: |
          import boto3
          import cfnresponse
          
          config = boto3.client('config')
          
          def handler(event, context):
              try:
                  if event['RequestType'] in ['Create', 'Update']:
                      recorder_name = event['ResourceProperties']['ConfigRecorderName']
                      config.start_configuration_recorder(
                          ConfigurationRecorderName=recorder_name
                      )
                      print(f"Started Config Recorder: {recorder_name}")
                  
                  cfnresponse.send(event, context, cfnresponse.SUCCESS, {})
              except Exception as e:
                  print(f"Error: {str(e)}")
                  cfnresponse.send(event, context, cfnresponse.FAILED, {})

  StartConfigRecorderRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      Policies:
        - PolicyName: ConfigControl
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - config:StartConfigurationRecorder
                  - config:StopConfigurationRecorder
                Resource: '*'

  # Config Rules (same as before)
  EBSEncryptionRule:
    Type: AWS::Config::ConfigRule
    DependsOn: ConfigRecorder
    Properties:
      ConfigRuleName: encrypted-volumes
      Source:
        Owner: AWS
        SourceIdentifier: ENCRYPTED_VOLUMES

  RestrictedSSHRule:
    Type: AWS::Config::ConfigRule
    DependsOn: ConfigRecorder
    Properties:
      ConfigRuleName: restricted-ssh
      Source:
        Owner: AWS
        SourceIdentifier: INCOMING_SSH_DISABLED

Outputs:
  ConfigRecorderName:
    Value: !Ref ConfigRecorder
  
  DeliveryChannelBucket:
    Description: Where this account sends Config data
    Value: !Ref CentralBucketName
```

---

## Data Flow Example

### Example: Account 333333333333 in us-east-1

1. **Resource Change**: EBS volume created in Account 333333333333
2. **Config Records**: Configuration item captured
3. **Delivery**: Config writes to central bucket:
   ```
   s3://aws-config-central-nonprod-111111111111/
   AWSLogs/333333333333/Config/us-east-1/2025/11/13/
   ConfigSnapshot/snapshot-20251113T120000Z.json.gz
   ```
4. **Aggregator Reads**: Management account aggregator reads from this path
5. **Dashboard Updates**: Compliance data visible in central dashboard

---

## Verification Commands

### Check Member Account Config

```bash
# In member account
aws configservice describe-delivery-channels

# Output should show:
# s3BucketName: aws-config-central-nonprod-111111111111
```

### Check Central Bucket Contents

```bash
# In management account
aws s3 ls s3://aws-config-central-nonprod-111111111111/AWSLogs/ --recursive

# You should see folders for each account:
# AWSLogs/333333333333/Config/us-east-1/...
# AWSLogs/444444444444/Config/us-east-1/...
# AWSLogs/555555555555/Config/us-west-2/...
```

### Verify Aggregator Data

```bash
# Check aggregator is receiving data from all accounts
aws configservice describe-configuration-aggregators \
  --configuration-aggregator-names nonprod-organization-aggregator

# Get compliance data
aws configservice get-aggregate-compliance-details-by-config-rule \
  --configuration-aggregator-name nonprod-organization-aggregator \
  --config-rule-name encrypted-volumes \
  --account-id 333333333333 \
  --aws-region us-east-1
```

---

## Deployment Order (Updated)

### Step 1: Deploy Central Bucket (Management Account)
```bash
aws cloudformation create-stack \
  --stack-name config-central-bucket \
  --template-body file://central-bucket.yaml \
  --parameters \
    ParameterKey=Environment,ParameterValue=nonprod \
    ParameterKey=OrganizationId,ParameterValue=o-xxxxxxxxxx \
  --capabilities CAPABILITY_NAMED_IAM
```

### Step 2: Get Central Bucket Name
```bash
CENTRAL_BUCKET=$(aws cloudformation describe-stacks \
  --stack-name config-central-bucket \
  --query 'Stacks[0].Outputs[?OutputKey==`CentralBucketName`].OutputValue' \
  --output text)

echo $CENTRAL_BUCKET
# Output: aws-config-central-nonprod-111111111111
```

### Step 3: Deploy to Member Accounts via StackSet
```bash
aws cloudformation create-stack-set \
  --stack-set-name aws-config-member-central \
  --template-body file://member-account-central.yaml \
  --parameters \
    ParameterKey=Environment,ParameterValue=nonprod \
    ParameterKey=CentralBucketName,ParameterValue=$CENTRAL_BUCKET \
    ParameterKey=ManagementAccountId,ParameterValue=111111111111 \
  --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true

# Deploy to all 32 non-prod accounts
aws cloudformation create-stack-instances \
  --stack-set-name aws-config-member-central \
  --accounts 333333333333 444444444444 555555555555 ... \
  --regions us-east-1 us-west-2
```

---

## Cost Implications

### Centralized Bucket Approach
- **S3 Storage**: ~5GB per account per month = 160GB total (32 accounts)
- **S3 Cost**: 160GB × $0.023/GB = **$3.68/month**
- **PUT Requests**: ~1,000 per account per month = 32,000 total
- **PUT Cost**: 32,000 × $0.005/1000 = **$0.16/month**
- **Data Transfer**: FREE (within same region)
- **Total Additional Cost**: **~$4/month**

### Benefits Over Individual Buckets
- Single bucket to manage
- Easier lifecycle policies
- Centralized access control
- Simplified compliance reporting
- No replication costs

---

## Security Considerations

1. **Bucket Encryption**: All data encrypted with KMS
2. **Organization Boundary**: Only org accounts can write
3. **Least Privilege**: Member accounts can only write, not read others' data
4. **Audit Trail**: S3 access logging + CloudTrail
5. **Versioning**: Enabled for data recovery

---

## Troubleshooting

### Problem: Member account can't write to central bucket

```bash
# Check bucket policy
aws s3api get-bucket-policy \
  --bucket aws-config-central-nonprod-111111111111

# Check Config role permissions
aws iam get-role-policy \
  --role-name AWSConfigRole-us-east-1 \
  --policy-name WriteToCentralBucket

# Test Config delivery
aws configservice put-delivery-channel \
  --delivery-channel name=default,s3BucketName=aws-config-central-nonprod-111111111111

aws configservice start-configuration-recorder \
  --configuration-recorder-name default
```

### Problem: Aggregator not seeing data

```bash
# Check aggregator authorization
aws configservice describe-aggregation-authorizations

# Verify aggregator role can read bucket
aws sts assume-role \
  --role-arn arn:aws:iam::111111111111:role/AWSConfigAggregatorRole-nonprod \
  --role-session-name test

# List bucket contents as aggregator role
aws s3 ls s3://aws-config-central-nonprod-111111111111/AWSLogs/
```

This centralized approach is the **recommended and most efficient** way to collect AWS Config data from all your accounts into a single location for compliance monitoring and reporting.