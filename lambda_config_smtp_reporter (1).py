"""
AWS Config Non-Compliant Reporter — SMTP Relay Edition (with AssumeRole)
Queries the Config Aggregator via an assumed IAM role and emails an HTML
report through an internal SMTP relay on port 25.

Environment Variables:
    SMTP_HOST        - Internal SMTP relay hostname (e.g. smtp-relay.corp.internal)
    SMTP_PORT        - SMTP port (default: 25)
    FROM_ADDRESS     - Sender email address
    TO_ADDRESSES     - Comma-separated recipient list
    AGGREGATOR_NAME  - AWS Config Aggregator name
    ASSUME_ROLE_ARN  - IAM Role ARN to assume (e.g. arn:aws:iam::123456789012:role/ConfigReaderRole)
    ASSUME_ROLE_SESSION_NAME - (optional) STS session name (default: ConfigReporterSession)
"""

import json
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
# Config
# ---------------------------------------------------------------------------
SMTP_HOST       = os.environ.get("SMTP_HOST", "smtp-relay.corp.internal")
SMTP_PORT       = int(os.environ.get("SMTP_PORT", "25"))
FROM_ADDRESS    = os.environ.get("FROM_ADDRESS", "lambda@example.com")
TO_ADDRESSES    = os.environ.get("TO_ADDRESSES", "ops@example.com")
AGGREGATOR_NAME = os.environ.get("AGGREGATOR_NAME", "my-central-aggregator")
ASSUME_ROLE_ARN = os.environ["ASSUME_ROLE_ARN"]   # required — fails fast if missing
SESSION_NAME    = os.environ.get("ASSUME_ROLE_SESSION_NAME", "ConfigReporterSession")


# ---------------------------------------------------------------------------
# STS AssumeRole — returns a fresh Config client with temporary credentials
# ---------------------------------------------------------------------------
def get_config_client():
    """Assume the target IAM role and return a boto3 Config client."""
    sts = boto3.client("sts")
    logger.info("Assuming role: %s  session: %s", ASSUME_ROLE_ARN, SESSION_NAME)
    resp  = sts.assume_role(
        RoleArn=ASSUME_ROLE_ARN,
        RoleSessionName=SESSION_NAME,
        DurationSeconds=900,  # 15 min — enough for all paginated queries
    )
    creds = resp["Credentials"]
    return boto3.client(
        "config",
        aws_access_key_id     = creds["AccessKeyId"],
        aws_secret_access_key = creds["SecretAccessKey"],
        aws_session_token     = creds["SessionToken"],
    )

# ---------------------------------------------------------------------------
# SQL queries against the Config Aggregator
# ---------------------------------------------------------------------------
QUERIES = [
    (
        "All Non-Compliant Resources",
        """
        SELECT accountId, awsRegion, resourceType, resourceId, resourceName,
               configuration.complianceType, configuration.configRuleList
        WHERE  configuration.complianceType = 'NON_COMPLIANT'
        ORDER BY accountId, awsRegion, resourceType
        LIMIT 500
        """,
    ),
    (
        "Non-Compliant S3 Buckets",
        """
        SELECT accountId, awsRegion, resourceId, resourceName,
               configuration.complianceType, configuration.configRuleList
        WHERE  resourceType = 'AWS::S3::Bucket'
          AND  configuration.complianceType = 'NON_COMPLIANT'
        ORDER BY accountId, resourceName
        LIMIT 200
        """,
    ),
    (
        "Non-Compliant IAM Resources",
        """
        SELECT accountId, awsRegion, resourceType, resourceId, resourceName,
               configuration.complianceType, configuration.configRuleList
        WHERE  resourceType IN ('AWS::IAM::User','AWS::IAM::Role',
                                'AWS::IAM::Policy','AWS::IAM::Group')
          AND  configuration.complianceType = 'NON_COMPLIANT'
        ORDER BY accountId, resourceType, resourceName
        LIMIT 200
        """,
    ),
    (
        "Non-Compliant Network Resources",
        """
        SELECT accountId, awsRegion, resourceType, resourceId, resourceName,
               configuration.complianceType, configuration.configRuleList
        WHERE  resourceType IN ('AWS::EC2::SecurityGroup',
                                'AWS::EC2::NetworkAcl','AWS::EC2::VPC')
          AND  configuration.complianceType = 'NON_COMPLIANT'
        ORDER BY accountId, awsRegion, resourceType
        LIMIT 200
        """,
    ),
]

# ---------------------------------------------------------------------------
# Config Aggregator query
# ---------------------------------------------------------------------------
def run_query(client, sql: str) -> list:
    """Paginate through all results for a single SQL query."""
    results, kwargs = [], {
        "ConfigurationAggregatorName": AGGREGATOR_NAME,
        "Expression": sql.strip(),
        "Limit": 100,
    }
    while True:
        response = client.select_aggregate_resource_config(**kwargs)
        for item in response.get("Results", []):
            results.append(json.loads(item))
        next_token = response.get("NextToken")
        if not next_token:
            break
        kwargs["NextToken"] = next_token
    return results


def summarise(rows: list) -> dict:
    summary = defaultdict(lambda: defaultdict(int))
    for row in rows:
        summary[row.get("accountId", "unknown")][row.get("resourceType", "unknown")] += 1
    return summary


# ---------------------------------------------------------------------------
# HTML report builder
# ---------------------------------------------------------------------------
STYLE = """
<style>
  body{font-family:Arial,sans-serif;font-size:14px;color:#1a1a2e;background:#f4f7fb;margin:0;padding:0}
  .wrapper{max-width:900px;margin:24px auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.1)}
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
  .rule-tag{display:inline-block;background:#ebf8ff;color:#2b6cb0;border-radius:4px;padding:1px 6px;font-size:11px;margin:1px}
  .summary-grid{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px}
  .summary-card{background:#fff5f5;border:1px solid #fed7d7;border-radius:8px;padding:12px 18px;min-width:160px}
  .summary-card .count{font-size:28px;font-weight:bold;color:#c53030}
  .summary-card .label{font-size:12px;color:#718096;margin-top:2px}
  .empty{color:#38a169;font-style:italic;font-size:13px}
  .footer{background:#f0f4f8;padding:14px 36px;font-size:11px;color:#718096;text-align:center}
</style>
"""


def format_rules(config_rule_list) -> str:
    if not config_rule_list:
        return "<span style='color:#a0aec0'>—</span>"
    if isinstance(config_rule_list, str):
        try:
            config_rule_list = json.loads(config_rule_list)
        except Exception:
            return f'<span class="rule-tag">{config_rule_list}</span>'
    tags = []
    for r in config_rule_list:
        if isinstance(r, dict):
            if r.get("complianceType") == "NON_COMPLIANT":
                tags.append(f'<span class="rule-tag">{r.get("configRuleName", r)}</span>')
        else:
            tags.append(f'<span class="rule-tag">{r}</span>')
    return " ".join(tags) or "<span style='color:#a0aec0'>—</span>"


def build_table(rows: list, columns: list) -> str:
    if not rows:
        return '<p class="empty">&#10003; No non-compliant resources found.</p>'
    html = ["<table><tr>"] + [f"<th>{h}</th>" for h, _ in columns] + ["</tr>"]
    for row in rows:
        html.append("<tr>")
        for _, key in columns:
            val = key(row) if callable(key) else row.get(key, "—")
            html.append(f"<td>{val}</td>")
        html.append("</tr>")
    html.append("</table>")
    return "".join(html)


def build_html_report(section_results: list) -> str:
    now   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    all_rows = section_results[0][2] if section_results else []
    summary  = summarise(all_rows)
    total    = sum(sum(v.values()) for v in summary.values())

    html = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        STYLE,
        "</head><body><div class='wrapper'>",
        "<div class='header'>",
        "<h1>&#x26A0;&#xFE0F; AWS Config — Non-Compliant Resource Report</h1>",
        f"<p>Generated: {now} &nbsp;|&nbsp; Aggregator: {AGGREGATOR_NAME}</p>",
        "</div>",
    ]

    # Executive summary
    badge_cls = "zero" if total == 0 else ""
    html.append("<div class='section'>")
    html.append(f"<h2>Executive Summary <span class='badge {badge_cls}'>{total} total</span></h2>")
    if summary:
        html.append("<div class='summary-grid'>")
        for account, rtypes in sorted(summary.items()):
            acct_total = sum(rtypes.values())
            html.append(
                f"<div class='summary-card'>"
                f"<div class='count'>{acct_total}</div>"
                f"<div class='label'>Account {account}</div>"
                f"</div>"
            )
        html.append("</div>")
        html.append("<table><tr><th>Account</th><th>Resource Type</th><th>Count</th></tr>")
        for account, rtypes in sorted(summary.items()):
            for rtype, count in sorted(rtypes.items()):
                html.append(f"<tr><td>{account}</td><td>{rtype}</td><td>{count}</td></tr>")
        html.append("</table>")
    else:
        html.append('<p class="empty">&#10003; All resources are compliant!</p>')
    html.append("</div>")

    # Per-section detail tables
    section_columns = {
        "All Non-Compliant Resources": [
            ("Account",       "accountId"),
            ("Region",        "awsRegion"),
            ("Resource Type", "resourceType"),
            ("Resource ID",   "resourceId"),
            ("Resource Name", "resourceName"),
            ("Non-Compliant Rules", lambda r: format_rules(r.get("configuration", {}).get("configRuleList"))),
        ],
        "Non-Compliant S3 Buckets": [
            ("Account",      "accountId"),
            ("Region",       "awsRegion"),
            ("Bucket Name",  "resourceName"),
            ("Bucket ID",    "resourceId"),
            ("Non-Compliant Rules", lambda r: format_rules(r.get("configuration", {}).get("configRuleList"))),
        ],
    }
    default_columns = [
        ("Account",       "accountId"),
        ("Region",        "awsRegion"),
        ("Resource Type", "resourceType"),
        ("Resource Name", "resourceName"),
        ("Resource ID",   "resourceId"),
        ("Non-Compliant Rules", lambda r: format_rules(r.get("configuration", {}).get("configRuleList"))),
    ]

    for title, _, rows in section_results:
        badge_cls = "zero" if len(rows) == 0 else ""
        columns   = section_columns.get(title, default_columns)
        html.append("<div class='section'>")
        html.append(f"<h2>{title} <span class='badge {badge_cls}'>{len(rows)}</span></h2>")
        html.append(build_table(rows, columns))
        html.append("</div>")

    html.append(
        "<div class='footer'>Auto-generated by AWS Lambda. "
        "See AWS Config Console for full details.</div>"
        "</div></body></html>"
    )
    return "".join(html)


# ---------------------------------------------------------------------------
# SMTP email sender (your working function — unchanged)
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
    # Assume the role once per invocation — all queries share these temp creds
    config_client = get_config_client()
    logger.info("Querying Config Aggregator: %s", AGGREGATOR_NAME)

    section_results = []
    for title, sql in QUERIES:
        logger.info("Running: %s", title)
        try:
            rows = run_query(config_client, sql)
            logger.info("  -> %d rows", len(rows))
        except Exception as exc:
            logger.error("Query failed [%s]: %s", title, exc)
            rows = []
        section_results.append((title, sql, rows))

    total = len(section_results[0][2]) if section_results else 0
    date  = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    subject   = f"[AWS Config] Non-Compliant Report — {total} resources ({date})"
    body_text = (
        f"Non-Compliant Resources: {total}\n"
        f"Aggregator: {AGGREGATOR_NAME}\n\n"
        "Please view this email in an HTML-capable client for the full report."
    )
    body_html = build_html_report(section_results)

    result = send_email(subject, body_text, body_html)

    return {"statusCode": 200, "totalNonCompliant": total, "email": result}
