# AWS Config Cost Analysis and Maintenance Guide

## Monthly Cost Breakdown

### Per-Account Cost Structure

#### Configuration Items Recording
- **Base Cost**: $0.003 per configuration item recorded
- **Estimated Items per Account**: 
  - Small account (~50 resources): 150 items/month = $0.45
  - Medium account (~200 resources): 600 items/month = $1.80
  - Large account (~500 resources): 1,500 items/month = $4.50

#### Config Rules
- **AWS Managed Rules**: $2.00 per rule per region per account
- **Custom Rules**: $0.10 per evaluation (first 100K), $0.05 per evaluation thereafter
- **Rules per Account**: 4 rules × 2 regions = 8 rule-region combinations
- **Cost**: 8 × $2.00 = **$16.00/month per account**

#### Configuration Recording
- **First 1,000 config items**: Free in first region
- **Additional items**: $0.003 per item
- **Estimated**: ~$2.00/month per account

#### S3 Storage
- **Configuration snapshots**: ~500MB/month per account
- **Cost**: $0.023/GB × 0.5GB = $0.01/month
- **Lifecycle to Glacier (90 days)**: $0.004/GB × 0.5GB = $0.002/month

#### Lambda Execution (Remediation)
- **Invocations**: ~100 invocations/month (varies by compliance issues)
- **Duration**: 30 seconds average per invocation
- **Memory**: 512MB
- **Cost**: ~$0.20/month per account

#### SNS Notifications
- **Messages**: ~50 notifications/month
- **Cost**: $0.50 per million requests = **negligible**

### Total Per Account (Average)
| Component | Cost/Month |
|-----------|-----------|
| Config Rules | $16.00 |
| Configuration Items | $2.00 |
| S3 Storage | $0.50 |
| Lambda Remediation | $0.20 |
| SNS | $0.10 |
| **Total** | **$18.80** |

### Total Environment Costs

#### Non-Production Environment
- **Member Accounts**: 32 accounts × $18.80 = $601.60/month
- **Management Account**: 
  - Config Aggregator: $0.001 per configuration item
  - Estimated: 32 accounts × 600 items = 19,200 items/month = $19.20
  - S3 Central Storage: ~10GB/month = $0.23
  - CloudWatch Dashboard: $3.00
  - Total Management: $22.43/month
- **Non-Prod Total**: $601.60 + $22.43 = **$624.03/month**

#### Production Environment
- **Member Accounts**: 13 accounts × $18.80 = $244.40/month
- **Management Account**: 
  - Config Aggregator: 13 accounts × 600 items = 7,800 items = $7.80
  - S3 Central Storage: ~5GB/month = $0.12
  - CloudWatch Dashboard: $3.00
  - Total Management: $10.92/month
- **Prod Total**: $244.40 + $10.92 = **$255.32/month**

### Annual Cost Summary
| Environment | Monthly | Annual |
|-------------|---------|--------|
| Non-Prod | $624.03 | $7,488.36 |
| Prod | $255.32 | $3,063.84 |
| **Total** | **$879.35** | **$10,552.20** |

---

## Cost Optimization Strategies

### 1. Configuration Item Filtering
Instead of recording all resource types, focus on compliance-critical resources:

```yaml
# In CloudFormation - ConfigRecorder
RecordingGroup:
  AllSupported: false
  IncludeGlobalResourceTypes: false
  ResourceTypes:
    - AWS::EC2::Volume
    - AWS::EC2::SecurityGroup
    - AWS::RDS::DBInstance
    - AWS::RDS::DBParameterGroup
```

**Savings**: ~30% reduction in configuration items = **$96/month**

### 2. Multi-Region Optimization
Deploy Config rules only in primary region for global resources:

```yaml
# Only deploy some rules in primary region
Conditions:
  IsPrimaryRegion: !Equals [!Ref AWS::Region, 'us-east-1']

# Apply condition to global resource rules
EBSEncryptionRule:
  Condition: IsPrimaryRegion
```

**Savings**: Reduce rule costs by 25% = **$204/month**

### 3. S3 Lifecycle Policies
Aggressive lifecycle management:

```yaml
LifecycleConfiguration:
  Rules:
    - Id: TransitionToIA
      Status: Enabled
      Transitions:
        - TransitionInDays: 7  # Instead of 30
          StorageClass: STANDARD_IA
    - Id: TransitionToGlacier
      Status: Enabled
      Transitions:
        - TransitionInDays: 30  # Instead of 90
          StorageClass: GLACIER
    - Id: DeleteOldData
      Status: Enabled
      ExpirationInDays: 180  # Instead of 365
```

**Savings**: ~60% reduction in S3 costs = **$10/month**

### 4. Lambda Optimization
- Reduce memory from 512MB to 256MB where possible
- Implement caching for common operations
- Use Step Functions for long-running remediations

**Savings**: ~40% reduction in Lambda costs = **$4/month**

### Total Potential Savings
- Configuration Items: $96/month
- Multi-Region: $204/month
- S3 Lifecycle: $10/month
- Lambda: $4/month
- **Total Savings**: **$314/month** (~36% reduction)
- **Optimized Monthly Cost**: **$565/month**
- **Optimized Annual Cost**: **$6,780/year**

---

## Daily Maintenance Checklist

### Morning Review (15 minutes)
```bash
#!/bin/bash
# daily-config-check.sh

# Check Config recorder status
echo "=== Config Recorder Status ==="
aws configservice describe-configuration-recorder-status \
  --query 'ConfigurationRecordersStatus[?recording==`false`]' \
  --output table

# Check compliance summary
echo "=== Compliance Summary ==="
aws configservice get-compliance-summary-by-config-rule \
  --output table

# Check failed remediations (last 24 hours)
echo "=== Failed Remediations ==="
aws logs filter-log-events \
  --log-group-name /aws/lambda/ConfigRemediation \
  --filter-pattern "ERROR" \
  --start-time $(($(date +%s) - 86400))000 \
  --query 'events[].message' \
  --output text

# Check high non-compliance accounts
echo "=== High Non-Compliance Accounts ==="
aws configservice describe-aggregate-compliance-by-config-rules \
  --configuration-aggregator-name nonprod-aggregator \
  --filters '{"ComplianceType":"NON_COMPLIANT"}' \
  --query 'AggregateComplianceByConfigRules[?Compliance.CompliantResourceCount.CappedCount<`10`]' \
  --output table
```

**Actions**:
- [ ] Run daily check script
- [ ] Review and document any failed recorders
- [ ] Investigate any failed remediations
- [ ] Check SNS email for overnight alerts

---

## Weekly Maintenance Tasks

### Monday: Compliance Review (30 minutes)
```bash
#!/bin/bash
# weekly-compliance-review.sh

# Generate compliance report
aws configservice get-aggregate-compliance-details-by-config-rule \
  --configuration-aggregator-name nonprod-aggregator \
  --config-rule-name encrypted-volumes \
  --query 'AggregateEvaluationResults[].[AccountId,EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId,ComplianceType]' \
  --output table > compliance-report-$(date +%Y%m%d).txt

# Repeat for each rule
for rule in restricted-ssh restricted-rdp rds-storage-encrypted rds-transit-encryption; do
  aws configservice get-aggregate-compliance-details-by-config-rule \
    --configuration-aggregator-name nonprod-aggregator \
    --config-rule-name $rule \
    --output table >> compliance-report-$(date +%Y%m%d).txt
done
```

**Actions**:
- [ ] Generate weekly compliance report
- [ ] Identify trends in non-compliance
- [ ] Document any persistent non-compliant resources
- [ ] Schedule remediation for items requiring manual intervention
- [ ] Update stakeholders on compliance posture

### Wednesday: Cost Review (20 minutes)
```bash
#!/bin/bash
# weekly-cost-review.sh

# Get Config service costs for last 7 days
aws ce get-cost-and-usage \
  --time-period Start=$(date -d '7 days ago' +%Y-%m-%d),End=$(date +%Y-%m-%d) \
  --granularity DAILY \
  --metrics UnblendedCost \
  --group-by Type=SERVICE \
  --filter file://config-cost-filter.json \
  --output table
```

**Actions**:
- [ ] Review Config service costs
- [ ] Compare against budget
- [ ] Identify cost anomalies
- [ ] Check for runaway Lambda invocations
- [ ] Review S3 storage growth

### Friday: System Health Check (30 minutes)
```bash
#!/bin/bash
# weekly-health-check.sh

# Check CloudWatch alarms
aws cloudwatch describe-alarms \
  --state-value ALARM \
  --query 'MetricAlarms[?Namespace==`AWS/Config`]' \
  --output table

# Check S3 bucket sizes
for bucket in $(aws s3 ls | grep aws-config | awk '{print $3}'); do
  echo "Bucket: $bucket"
  aws cloudwatch get-metric-statistics \
    --namespace AWS/S3 \
    --metric-name BucketSizeBytes \
    --dimensions Name=BucketName,Value=$bucket Name=StorageType,Value=StandardStorage \
    --start-time $(date -d '7 days ago' -u +%Y-%m-%dT%H:%M:%S) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
    --period 86400 \
    --statistics Average \
    --query 'Datapoints[-1].Average' \
    --output text | awk '{print $1/1024/1024/1024 " GB"}'
done

# Check Lambda function health
aws lambda list-functions \
  --query 'Functions[?contains(FunctionName, `Config`) || contains(FunctionName, `Remediation`)]' \
  --output table
```

**Actions**:
- [ ] Review and resolve CloudWatch alarms
- [ ] Check S3 bucket growth trends
- [ ] Verify Lambda function health metrics
- [ ] Test Lambda functions in non-prod
- [ ] Review aggregator performance

---

## Monthly Maintenance Tasks

### First Monday: Configuration Audit (1 hour)
**Actions**:
- [ ] Review all Config rules for effectiveness
- [ ] Analyze remediation success rates
- [ ] Identify frequently non-compliant resource types
- [ ] Review and update exception lists
- [ ] Check for new AWS Config managed rules
- [ ] Update documentation

### Second Monday: Cost Optimization Review (1 hour)
**Actions**:
- [ ] Generate monthly cost report
- [ ] Analyze cost trends
- [ ] Identify opportunities for optimization
- [ ] Review S3 lifecycle policies effectiveness
- [ ] Check for unused resources
- [ ] Update budget forecasts

### Third Monday: Security Review (1 hour)
**Actions**:
- [ ] Review IAM roles and permissions
- [ ] Audit CloudTrail logs for Config API calls
- [ ] Review SNS topic subscriptions
- [ ] Check S3 bucket policies
- [ ] Verify KMS key policies
- [ ] Review cross-account access

### Fourth Monday: Disaster Recovery Test (2 hours)
**Actions**:
- [ ] Test Config recorder recovery in non-prod
- [ ] Verify backup procedures
- [ ] Test StackSet redeployment
- [ ] Verify aggregator data integrity
- [ ] Test Lambda function recovery
- [ ] Document any issues found

---

## Quarterly Maintenance Tasks

### Q1, Q2, Q3, Q4: Comprehensive Review (4 hours)

#### Architecture Review
- [ ] Review overall architecture design
- [ ] Evaluate new AWS Config features
- [ ] Assess scalability for new accounts
- [ ] Review multi-region strategy
- [ ] Update architecture diagrams

#### Compliance Assessment
- [ ] Generate quarterly compliance report
- [ ] Compare against SLAs/KPIs
- [ ] Identify compliance gaps
- [ ] Review regulatory requirements
- [ ] Update compliance policies

#### Cost Analysis
- [ ] Analyze quarterly spending trends
- [ ] Compare against annual budget
- [ ] Identify cost optimization opportunities
- [ ] Review resource utilization
- [ ] Update cost forecasts

#### Training and Documentation
- [ ] Update runbooks
- [ ] Review and update documentation
- [ ] Conduct team training sessions
- [ ] Share lessons learned
- [ ] Update disaster recovery procedures

---

## Annual Maintenance Tasks

### January: Annual Planning (8 hours)
- [ ] Review previous year's performance
- [ ] Set compliance goals for new year
- [ ] Update budget and cost forecasts
- [ ] Plan architecture improvements
- [ ] Review and update SLAs
- [ ] Conduct team retrospective

### June: Mid-Year Review (4 hours)
- [ ] Review progress against annual goals
- [ ] Adjust forecasts and budgets
- [ ] Evaluate new technologies
- [ ] Update roadmap
- [ ] Conduct stakeholder review

---

## Key Performance Indicators (KPIs)

### Compliance Metrics
| Metric | Target | Measurement |
|--------|--------|-------------|
| Overall Compliance Rate | >95% | Monthly |
| Time to Compliance | <24 hours | Per incident |
| Remediation Success Rate | >90% | Weekly |
| Mean Time to Detect (MTTD) | <15 minutes | Continuous |
| Mean Time to Remediate (MTTR) | <1 hour | Per incident |

### Operational Metrics
| Metric | Target | Measurement |
|--------|--------|-------------|
| Config Recorder Uptime | 99.9% | Monthly |
| Lambda Success Rate | >95% | Weekly |
| Aggregator Data Freshness | <6 hours | Daily |
| False Positive Rate | <5% | Monthly |

### Cost Metrics
| Metric | Target | Measurement |
|--------|--------|-------------|
| Cost per Account | <$20/month | Monthly |
| Total Environment Cost | <$900/month | Monthly |
| Cost per Compliance Issue | <$5 | Quarterly |
| ROI on Remediation | >200% | Annual |

---

## Alerting and Escalation

### Alert Severity Levels

#### P0 - Critical (Immediate Response)
- Config recorder stopped in >10 accounts
- Aggregator failure
- Mass compliance failures (>100 resources)
- Security breach detected

**Response**: 
- Page on-call engineer immediately
- Engage management within 15 minutes
- Begin incident response procedures

#### P1 - High (Response within 1 hour)
- Config recorder stopped in 5-10 accounts
- Remediation Lambda failures >50%
- S3 bucket access denied
- KMS key issues

**Response**:
- Alert on-call engineer
- Begin troubleshooting
- Update stakeholders

#### P2 - Medium (Response within 4 hours)
- Config recorder stopped in 1-4 accounts
- Compliance score drop >10%
- S3 storage exceeding budget by 20%
- Individual Lambda failures

**Response**:
- Create ticket
- Schedule during business hours
- Monitor for escalation

#### P3 - Low (Response within 24 hours)
- Minor compliance issues
- Cost variance <10%
- Documentation updates needed

**Response**:
- Add to backlog
- Address during maintenance window

---

## Contact Information

### Internal Team
- **Primary Contact**: aws-compliance@company.com
- **On-Call Engineer**: PagerDuty rotation
- **Manager**: compliance-manager@company.com

### AWS Support
- **Support Plan**: Enterprise
- **TAM**: assigned-tam@amazon.com
- **Support Case**: AWS Console

### Escalation Path
1. On-Call Engineer (0-15 min)
2. Team Lead (15-30 min)
3. Engineering Manager (30-60 min)
4. Director of Cloud Operations (1-2 hours)
5. CTO (>2 hours for critical incidents)