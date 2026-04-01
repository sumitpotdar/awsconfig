"""
AWS Config Non-Compliant Reporter — SMTP Relay Edition (with AssumeRole)
Fetches non-compliant resources from the Config Aggregator using the correct
compliance APIs (get_aggregate_compliance_details_by_config_rule) and emails
an HTML report through an internal SMTP relay on port 25.

Root cause of "zero results with SQL":
    The Advanced Query / SELECT API queries resource *configuration* metadata.
    Compliance evaluation results are stored separately and must be fetched via:
      - get_aggregate_config_rules_compliance_summary  (rule-level counts)
      - get_aggregate_compliance_details_by_config_rule (per-resource details)

Environment Variables:
    SMTP_HOST                - Internal SMTP relay hostname
    SMTP_PORT                - SMTP port (default: 25)
    FROM_ADDRESS             - Sender email address
    TO_ADDRESSES             - Comma-separated recipient list
    AGGREGATOR_NAME          - AWS Config Aggregator name
    ASSUME_ROLE_ARN          - IAM Role ARN to assume
    ASSUME_ROLE_SESSION_NAME - (optional) STS session name
    RULE_NAMES               - (optional) comma-separated Config rule names to include;
                               leave blank to report on ALL rules in the aggregator
"""

import os
import smtplib
import logging
import boto3
from datetime import datetime, timezone
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SMTP_HOST       = os.environ.get("SMTP_HOST", "smtp-relay.corp.internal")
SMTP_PORT       = int(os.environ.get("SMTP_PORT", "25"))
FROM_ADDRESS    = os.environ.get("FROM_ADDRESS", "lambda@example.com")
TO_ADDRESSES    = os.environ.get("TO_ADDRESSES", "ops@example.com")
AGGREGATOR_NAME = os.environ.get("AGGREGATOR_NAME", "my-central-aggregator")
ASSUME_ROLE_ARN = os.environ["ASSUME_ROLE_ARN"]   # required — fails fast if missing
SESSION_NAME    = os.environ.get("ASSUME_ROLE_SESSION_NAME", "ConfigReporterSession")
# Comma-separated rule names to filter on; leave blank to report ALL rules
_rule_env   = os.environ.get("RULE_NAMES", "")
RULE_FILTER = {r.strip() for r in _rule_env.split(",") if r.strip()}


# ---------------------------------------------------------------------------
# STS AssumeRole
# ---------------------------------------------------------------------------
def get_config_client():
    """Assume the target IAM role and return a boto3 Config client."""
    sts = boto3.client("sts")
    logger.info("Assuming role: %s  session: %s", ASSUME_ROLE_ARN, SESSION_NAME)
    creds = sts.assume_role(
        RoleArn=ASSUME_ROLE_ARN,
        RoleSessionName=SESSION_NAME,
        DurationSeconds=900,
    )["Credentials"]
    return boto3.client(
        "config",
        aws_access_key_id     = creds["AccessKeyId"],
        aws_secret_access_key = creds["SecretAccessKey"],
        aws_session_token     = creds["SessionToken"],
    )


# ---------------------------------------------------------------------------
# Step 1 — get all NON_COMPLIANT rules from the aggregator
# ---------------------------------------------------------------------------
def get_noncompliant_rules(client) -> list:
    """
    Returns a list of dicts:
      { rule_name, account_id, aws_region, non_compliant_count }
    Uses get_aggregate_config_rules_compliance_summary to find which rules
    have NON_COMPLIANT resources, then returns those rules for detail lookup.
    """
    rules = []
    kwargs = {
        "ConfigurationAggregatorName": AGGREGATOR_NAME,
        "Filters": {"ComplianceType": "NON_COMPLIANT"},
    }
    while True:
        resp = client.get_aggregate_config_rules_compliance_summary(**kwargs)
        for group in resp.get("AggregateComplianceCounts", []):
            counts = group.get("ComplianceSummary", {})
            non_compliant = counts.get("NonCompliantResourceCount", {}).get("CappedCount", 0)
            if non_compliant > 0:
                # GroupName = "<account_id>/<region>" when grouped by account+region
                group_name = group.get("GroupName", "/")
                parts = group_name.split("/")
                account_id = parts[0] if len(parts) > 0 else "unknown"
                aws_region = parts[1] if len(parts) > 1 else "unknown"
                rules.append({
                    "group_name":        group_name,
                    "account_id":        account_id,
                    "aws_region":        aws_region,
                    "non_compliant_count": non_compliant,
                })
        next_token = resp.get("NextToken")
        if not next_token:
            break
        kwargs["NextToken"] = next_token

    logger.info("Found %d non-compliant rule groups", len(rules))
    return rules


# ---------------------------------------------------------------------------
# Step 2 — get per-resource compliance details for every non-compliant rule
# ---------------------------------------------------------------------------
def get_noncompliant_rule_details(client) -> list:
    """
    Uses get_aggregate_compliance_details_by_config_rule to retrieve each
    non-compliant resource for every rule across all accounts and regions.
    Returns a flat list of evaluation result dicts.
    """
    # First: collect all rule names that have NON_COMPLIANT resources
    rule_names_by_account_region = defaultdict(set)
    kwargs = {
        "ConfigurationAggregatorName": AGGREGATOR_NAME,
        "ComplianceType": "NON_COMPLIANT",
    }
    while True:
        resp = client.get_aggregate_config_rule_compliance_summary(
            ConfigurationAggregatorName=AGGREGATOR_NAME,
            Filters={"ComplianceType": "NON_COMPLIANT"},
        ) if False else None  # placeholder — use correct API below
        break

    # Correct API: get_aggregate_compliance_details_by_config_rule requires
    # a rule name + account + region, so we first list all rules then filter.
    all_results = []

    # 1. List all rules in the aggregator
    list_kwargs = {"ConfigurationAggregatorName": AGGREGATOR_NAME}
    all_rules = []
    while True:
        resp = client.describe_aggregate_compliance_by_config_rules(**list_kwargs)
        for rule in resp.get("AggregateComplianceByConfigRules", []):
            compliance = rule.get("Compliance", {})
            rule_name  = rule["ConfigRuleName"]
            # Skip rules not in the filter (if a filter is set)
            if RULE_FILTER and rule_name not in RULE_FILTER:
                continue
            if compliance.get("ComplianceType") == "NON_COMPLIANT":
                all_rules.append({
                    "rule_name":  rule_name,
                    "account_id": rule["AccountId"],
                    "aws_region": rule["AwsRegion"],
                })
        next_token = resp.get("NextToken")
        if not next_token:
            break
        list_kwargs["NextToken"] = next_token

    logger.info("Non-compliant rules to detail: %d", len(all_rules))

    # 2. For each non-compliant rule, fetch the individual resource evaluations
    for rule_info in all_rules:
        detail_kwargs = {
            "ConfigurationAggregatorName": AGGREGATOR_NAME,
            "ConfigRuleName": rule_info["rule_name"],
            "AccountId":      rule_info["account_id"],
            "AwsRegion":      rule_info["aws_region"],
            "ComplianceType": "NON_COMPLIANT",
            "Limit": 100,
        }
        while True:
            try:
                resp = client.get_aggregate_compliance_details_by_config_rule(**detail_kwargs)
            except Exception as exc:
                logger.warning("Skipping rule %s: %s", rule_info["rule_name"], exc)
                break
            for ev in resp.get("AggregateEvaluationResults", []):
                qualifier = ev.get("EvaluationResultIdentifier", {}).get("EvaluationResultQualifier", {})
                all_results.append({
                    "rule_name":     qualifier.get("ConfigRuleName", rule_info["rule_name"]),
                    "resource_type": qualifier.get("ResourceType", "—"),
                    "resource_id":   qualifier.get("ResourceId", "—"),
                    "account_id":    ev.get("AccountId", rule_info["account_id"]),
                    "aws_region":    ev.get("AwsRegion", rule_info["aws_region"]),
                    "compliance":    ev.get("ComplianceType", "—"),
                    "annotation":    ev.get("Annotation", ""),
                    "result_time":   str(ev.get("ResultRecordedTime", "")),
                })
            next_token = resp.get("NextToken")
            if not next_token:
                break
            detail_kwargs["NextToken"] = next_token

    logger.info("Total non-compliant resource evaluations: %d", len(all_results))
    return all_results


# ---------------------------------------------------------------------------
# Summarise helpers
# ---------------------------------------------------------------------------
def summarise_by_account(rows: list) -> dict:
    """{ account_id: { resource_type: count } }"""
    summary = defaultdict(lambda: defaultdict(int))
    for r in rows:
        summary[r["account_id"]][r["resource_type"]] += 1
    return summary


def summarise_by_rule(rows: list) -> dict:
    """{ rule_name: count }"""
    counts = defaultdict(int)
    for r in rows:
        counts[r["rule_name"]] += 1
    return counts


# ---------------------------------------------------------------------------
# HTML report builder
# ---------------------------------------------------------------------------
STYLE = """
<style>
  body{font-family:Arial,sans-serif;font-size:14px;color:#1a1a2e;background:#f4f7fb;margin:0;padding:0}
  .wrapper{max-width:960px;margin:24px auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.1)}
  .header{background:#16213e;color:#fff;padding:28px 36px}
  .header h1{margin:0 0 4px;font-size:22px}
  .header p{margin:0;font-size:13px;color:#a0aec0}
  .section{padding:24px 36px;border-bottom:1px solid #e8edf5}
  .section:last-child{border-bottom:none}
  h2{font-size:16px;color:#16213e;margin:0 0 14px}
  .badge{display:inline-block;background:#e53e3e;color:#fff;border-radius:12px;padding:2px 10px;font-size:12px;font-weight:bold;margin-left:8px}
  .badge.zero{background:#38a169}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{background:#edf2f7;text-align:left;padding:8px 12px;color:#4a5568;font-weight:600;border-bottom:2px solid #cbd5e0}
  td{padding:7px 12px;border-bottom:1px solid #e8edf5;vertical-align:top;word-break:break-all}
  tr:last-child td{border-bottom:none}
  tr:nth-child(even) td{background:#f7fafc}
  .summary-grid{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px}
  .summary-card{background:#fff5f5;border:1px solid #fed7d7;border-radius:8px;padding:12px 18px;min-width:160px}
  .summary-card .count{font-size:28px;font-weight:bold;color:#c53030}
  .summary-card .label{font-size:12px;color:#718096;margin-top:2px}
  .rule-badge{display:inline-block;background:#ebf8ff;color:#2b6cb0;border-radius:4px;padding:2px 8px;font-size:12px}
  .empty{color:#38a169;font-style:italic}
  .footer{background:#f0f4f8;padding:14px 36px;font-size:11px;color:#718096;text-align:center}
  .ann{color:#718096;font-size:12px;font-style:italic}
</style>
"""


def build_html_report(all_rows: list) -> str:
    now     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total   = len(all_rows)
    by_acct = summarise_by_account(all_rows)
    by_rule = summarise_by_rule(all_rows)

    html = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        STYLE,
        "</head><body><div class='wrapper'>",
        "<div class='header'>",
        "<h1>&#x26A0;&#xFE0F; AWS Config — Non-Compliant Resource Report</h1>",
        f"<p>Generated: {now} &nbsp;|&nbsp; Aggregator: {AGGREGATOR_NAME}</p>",
        "</div>",
    ]

    # ── Executive summary cards ──────────────────────────────────────────────
    badge_cls = "zero" if total == 0 else ""
    html += [
        "<div class='section'>",
        f"<h2>Executive Summary <span class='badge {badge_cls}'>{total} non-compliant resources</span></h2>",
        "<div class='summary-grid'>",
    ]
    for account, rtypes in sorted(by_acct.items()):
        acct_total = sum(rtypes.values())
        html.append(
            f"<div class='summary-card'>"
            f"<div class='count'>{acct_total}</div>"
            f"<div class='label'>Account {account}</div>"
            f"</div>"
        )
    if not by_acct:
        html.append("<p class='empty'>&#10003; All resources are compliant!</p>")
    html.append("</div>")

    # Account × resource-type breakdown
    if by_acct:
        html += [
            "<table><tr><th>Account</th><th>Resource Type</th><th>Count</th></tr>",
        ]
        for account, rtypes in sorted(by_acct.items()):
            for rtype, cnt in sorted(rtypes.items(), key=lambda x: -x[1]):
                html.append(f"<tr><td>{account}</td><td>{rtype}</td><td>{cnt}</td></tr>")
        html.append("</table>")
    html.append("</div>")

    # ── By-rule summary ───────────────────────────────────────────────────────
    html += [
        "<div class='section'>",
        f"<h2>Non-Compliant Rules <span class='badge'>{len(by_rule)}</span></h2>",
        "<table><tr><th>Rule Name</th><th>Non-Compliant Resources</th></tr>",
    ]
    for rule, cnt in sorted(by_rule.items(), key=lambda x: -x[1]):
        html.append(f"<tr><td><span class='rule-badge'>{rule}</span></td><td>{cnt}</td></tr>")
    html.append("</table></div>")

    # ── Full resource detail table ────────────────────────────────────────────
    html += [
        "<div class='section'>",
        f"<h2>All Non-Compliant Resources <span class='badge {badge_cls}'>{total}</span></h2>",
    ]
    if all_rows:
        html += [
            "<table><tr>",
            "<th>Account</th><th>Region</th><th>Resource Type</th>",
            "<th>Resource ID</th><th>Rule</th><th>Annotation</th>",
            "</tr>",
        ]
        for r in sorted(all_rows, key=lambda x: (x["account_id"], x["resource_type"], x["rule_name"])):
            ann = f"<span class='ann'>{r['annotation']}</span>" if r["annotation"] else "—"
            html.append(
                f"<tr>"
                f"<td>{r['account_id']}</td>"
                f"<td>{r['aws_region']}</td>"
                f"<td>{r['resource_type']}</td>"
                f"<td>{r['resource_id']}</td>"
                f"<td><span class='rule-badge'>{r['rule_name']}</span></td>"
                f"<td>{ann}</td>"
                f"</tr>"
            )
        html.append("</table>")
    else:
        html.append("<p class='empty'>&#10003; No non-compliant resources found.</p>")
    html.append("</div>")

    html.append(
        "<div class='footer'>Auto-generated by AWS Lambda. "
        "See AWS Config Console for full details.</div>"
        "</div></body></html>"
    )
    return "".join(html)


# ---------------------------------------------------------------------------
# SMTP email sender (unchanged from your working version)
# ---------------------------------------------------------------------------
def send_email(subject: str, body_text: str, body_html: str = None,
               to_addresses: list = None):
    recipients = to_addresses or [r.strip() for r in TO_ADDRESSES.split(",") if r.strip()]

    if body_html:
        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText(body_text, "plain"))
        msg.attach(MIMEText(body_html, "html"))
    else:
        msg = MIMEText(body_text, "plain")

    msg["Subject"] = subject
    msg["From"]    = FROM_ADDRESS
    msg["To"]      = ", ".join(recipients)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
        smtp.sendmail(FROM_ADDRESS, recipients, msg.as_string())

    logger.info("Email sent to %s", recipients)
    return {"sent_to": recipients, "subject": subject}


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------
def lambda_handler(event, context):
    # Assume role once — reuse credentials for all API calls
    config_client = get_config_client()

    if RULE_FILTER:
        logger.info("Rule filter active: %s", sorted(RULE_FILTER))
    else:
        logger.info("No rule filter set — reporting ALL rules in aggregator")
    logger.info("Fetching non-compliant resources from aggregator: %s", AGGREGATOR_NAME)
    all_rows = get_noncompliant_rule_details(config_client)
    total    = len(all_rows)
    date     = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    subject   = f"[AWS Config] Non-Compliant Report — {total} resources ({date})"
    body_text = (
        f"Non-Compliant Resources: {total}\n"
        f"Aggregator: {AGGREGATOR_NAME}\n\n"
        "Please view this email in an HTML-capable client for the full report."
    )
    body_html = build_html_report(all_rows)

    result = send_email(subject, body_text, body_html)
    return {"statusCode": 200, "totalNonCompliant": total, "email": result}
