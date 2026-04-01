import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# ---------------------------------------------------------------------------
# Configuration — set these as Lambda environment variables
# ---------------------------------------------------------------------------
SMTP_HOST    = os.environ.get("SMTP_HOST", "your-smtp-relay.internal")
SMTP_PORT    = int(os.environ.get("SMTP_PORT", "25"))
FROM_ADDRESS = os.environ.get("FROM_ADDRESS", "lambda@example.com")
TO_ADDRESSES = os.environ.get("TO_ADDRESSES", "recipient@example.com")  # comma-separated


def send_email(subject: str, body_text: str, body_html: str = None,
               to_addresses: list = None) -> dict:
    """
    Send an email through the internal SMTP relay.

    Args:
        subject:      Email subject line
        body_text:    Plain-text fallback body
        body_html:    Optional HTML body (recommended)
        to_addresses: List of recipient addresses; falls back to TO_ADDRESSES env var
    """
    recipients = to_addresses or [r.strip() for r in TO_ADDRESSES.split(",") if r.strip()]

    # Build message
    if body_html:
        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText(body_text, "plain"))
        msg.attach(MIMEText(body_html, "html"))
    else:
        msg = MIMEText(body_text, "plain")

    msg["Subject"] = subject
    msg["From"]    = FROM_ADDRESS
    msg["To"]      = ", ".join(recipients)

    # Connect and send — no auth, no TLS (plain port 25 relay)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
        smtp.sendmail(FROM_ADDRESS, recipients, msg.as_string())

    return {"sent_to": recipients, "subject": subject}


def lambda_handler(event, context):
    """
    Invoke directly or via EventBridge / SNS / SQS.

    Supported event keys (all optional — fall back to defaults):
        subject      - email subject
        body         - plain text body
        html         - HTML body
        to           - list or comma-string of recipients
    """
    subject = event.get("subject", "Lambda Notification")
    body    = event.get("body",    "This is an automated notification from AWS Lambda.")
    html    = event.get("html")    # None = plain-text only

    to = event.get("to")
    if isinstance(to, str):
        to = [t.strip() for t in to.split(",") if t.strip()]

    result = send_email(subject, body, html, to)
    print(f"Email sent: {result}")
    return {"statusCode": 200, "result": result}
