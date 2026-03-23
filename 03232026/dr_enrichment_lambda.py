"""
dr_enrichment_lambda.py
────────────────────────────────────────────────────────────────────────────────
Separate Lambda function that enriches existing RDS audit records in DynamoDB
with Disaster Recovery (DR) test data pulled from an external Aurora/RDS database.

Runs on its own EventBridge schedule (e.g. weekly/monthly) — completely
independent of the main RDS security audit Lambda.

Environment variables required:
  DYNAMODB_TABLE        – DynamoDB table name (same as audit Lambda)
  DR_SECRET_ARN         – Secrets Manager ARN for DR database credentials
                          Secret must contain: host, port, dbname, username, password
  DR_DB_TABLE           – Table/view name in the DR database
                            (default: 'dr_application_tests')
  DR_APP_ID_COLUMN      – Column name for Application ID
                            (default: 'Application ID')
  DR_LAST_TEST_COLUMN   – Column name for last test datetime
                            (default: 'Last application test date/time')
  DR_DB_ENGINE          – 'mysql' or 'postgresql' (default: 'postgresql')

VPC note:
  This Lambda MUST be deployed in the same VPC as the Aurora/RDS DR database.
  Add the DB security group (or a dedicated Lambda SG) to the inbound rules.

IAM permissions required:
  - dynamodb:Query on the DynamoDB table + GSI (GSI1)
  - dynamodb:UpdateItem on the DynamoDB table
  - secretsmanager:GetSecretValue for DR_SECRET_ARN
  - (if cross-account DR DB) sts:AssumeRole for the DR account role
"""

import json
import os
import re
import boto3
import logging
from datetime import datetime, timedelta
from decimal import Decimal

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ── Environment variables ─────────────────────────────────────────────────────
DYNAMODB_TABLE     = os.environ.get('DYNAMODB_TABLE', 'RDSSecurityAudit')
DR_SECRET_ARN      = os.environ.get('DR_SECRET_ARN', '')
DR_DB_TABLE        = os.environ.get('DR_DB_TABLE', 'dr_application_tests')
DR_APP_ID_COLUMN   = os.environ.get('DR_APP_ID_COLUMN', 'Application ID')
DR_LAST_TEST_COL   = os.environ.get('DR_LAST_TEST_COLUMN', 'Last application test date/time')
DR_DB_ENGINE       = os.environ.get('DR_DB_ENGINE', 'postgresql').lower()  # 'mysql' or 'postgresql'

# ── AWS clients ───────────────────────────────────────────────────────────────
dynamodb = boto3.resource('dynamodb')
table    = dynamodb.Table(DYNAMODB_TABLE)
sm       = boto3.client('secretsmanager')


# ─────────────────────────────────────────────────────────────────────────────
# Lambda entry point
# ─────────────────────────────────────────────────────────────────────────────

def lambda_handler(event, context):
    """
    1. Fetch all DR test records from the external Aurora/RDS database.
    2. For each DR record, find matching DynamoDB RDS audit items by app_id.
    3. UpdateItem on each match — adds/overwrites the 'dr' attribute block.
    """
    logger.info(f"DR enrichment started at {datetime.now().isoformat()}")

    enriched_count = 0
    skipped_count  = 0
    error_count    = 0

    try:
        # ── Step 1: load DR data from external database ───────────────────────
        dr_records = fetch_dr_records()
        logger.info(f"Fetched {len(dr_records)} DR records from external database")

        if not dr_records:
            logger.warning("No DR records returned — nothing to enrich")
            return _response(200, "No DR records found — nothing to enrich", 0, 0, 0)

        # ── Step 2: enrich DynamoDB records ──────────────────────────────────
        enriched_at = datetime.now().isoformat()

        for dr in dr_records:
            app_id         = dr.get('app_id')
            last_test_dt   = dr.get('last_test_datetime')
            raw_row        = dr.get('raw', {})

            if not app_id:
                logger.warning(f"DR record missing app_id — skipping: {dr}")
                skipped_count += 1
                continue

            # Find all DynamoDB items whose app_id tag matches this DR app_id
            matched_items = query_dynamo_by_app_id(app_id)

            if not matched_items:
                logger.info(f"  [DR] No DynamoDB items found for app_id={app_id}")
                skipped_count += 1
                continue

            for item in matched_items:
                pk = item['PK']
                sk = item['SK']
                try:
                    update_item_with_dr(pk, sk, app_id, last_test_dt, enriched_at, raw_row)
                    logger.info(f"  [DR] Enriched PK={pk} SK={sk} "
                                f"app_id={app_id} last_test={last_test_dt}")
                    enriched_count += 1
                except Exception as e:
                    logger.error(f"  [DR] Failed to update PK={pk} SK={sk}: {e}")
                    error_count += 1

        logger.info(
            f"DR enrichment complete — "
            f"enriched={enriched_count}, skipped={skipped_count}, errors={error_count}"
        )
        return _response(200, "Enrichment complete", enriched_count, skipped_count, error_count)

    except Exception as e:
        logger.error(f"DR enrichment failed: {e}")
        raise


# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Fetch DR records
#
# ⚠️  TESTING MODE — real database connection is commented out.
#     Hardcoded sample rows below simulate what the DR database would return.
#     Each row must have the same two columns your real DB has:
#       • "Application ID"                   → maps to app_id tag on RDS instances
#       • "Last application test date/time"  → ISO-8601 string or datetime
#
#     To switch back to the real DB:
#       1. Delete / comment out the TEST DATA block below
#       2. Uncomment the real DB block that starts with  get_db_credentials()
# ─────────────────────────────────────────────────────────────────────────────

# ── TEST DATA ─────────────────────────────────────────────────────────────────
# Mirrors the exact two columns from the external DR database.
# "Application ID" values here must match the app_id tag on your RDS instances
# (matching is case/hyphen/underscore insensitive, so "poc-app", "pocapp",
#  "POC_APP" all resolve to the same instance).
# Add / edit rows freely for testing.
_TEST_DR_ROWS = [
    {
        "Application ID":                  "pocapp",
        "Last application test date/time": "2025-03-01T14:30:00",
    },
    {
        "Application ID":                  "myapp",
        "Last application test date/time": "2025-02-15T09:00:00",
    },
    {
        "Application ID":                  "financeapp",
        "Last application test date/time": "2025-01-20T18:45:00",
    },
    {
        "Application ID":                  "hrportal",
        "Last application test date/time": "2024-12-10T11:00:00",
    },
    {
        "Application ID":                  "data-platform",   # hyphens normalised automatically
        "Last application test date/time": "2025-03-10T08:00:00",
    },
]
# ── END TEST DATA ─────────────────────────────────────────────────────────────


def fetch_dr_records() -> list:
    """
    Return DR test records normalised into:
        [
          {
            'app_id':             'pocapp',          # normalised (lower, no hyphens)
            'last_test_datetime': '2025-03-01T14:30:00',
            'raw':                { ... original row ... }
          },
          ...
        ]

    ── TESTING MODE ──────────────────────────────────────────────────────────
    Reads from the hardcoded _TEST_DR_ROWS list above instead of the real DB.
    ──────────────────────────────────────────────────────────────────────────

    ── PRODUCTION (commented out) ────────────────────────────────────────────
    Uncomment the block below and delete the test-data block to connect to the
    real Aurora/RDS DR database via Secrets Manager credentials.
    ──────────────────────────────────────────────────────────────────────────
    """

    # ══════════════════════════════════════════════════════════════════════════
    # TESTING MODE — read from hardcoded list
    # ══════════════════════════════════════════════════════════════════════════
    logger.info("[TEST MODE] Loading DR records from hardcoded test data "
                f"({len(_TEST_DR_ROWS)} rows) — real DB connection is disabled")

    records = []
    for raw in _TEST_DR_ROWS:
        app_id       = _coerce_str(raw.get(DR_APP_ID_COLUMN))
        last_test_dt = _coerce_datetime(raw.get(DR_LAST_TEST_COL))

        if not app_id:
            logger.warning(f"  [TEST] Row missing '{DR_APP_ID_COLUMN}' — skipping: {raw}")
            continue

        records.append({
            'app_id':            _normalise_app_id(app_id),
            'last_test_datetime': last_test_dt,
            'raw':               {k: _serialisable(v) for k, v in raw.items()}
        })

    logger.info(f"[TEST MODE] Returning {len(records)} DR records")
    return records

    # ══════════════════════════════════════════════════════════════════════════
    # PRODUCTION — uncomment below and delete everything above this block
    # ══════════════════════════════════════════════════════════════════════════
    #
    # creds    = get_db_credentials()
    # host     = creds['host']
    # port     = int(creds.get('port', 5432 if DR_DB_ENGINE == 'postgresql' else 3306))
    # dbname   = creds['dbname']
    # username = creds['username']
    # password = creds['password']
    #
    # logger.info(f"Connecting to DR database {host}:{port}/{dbname} (engine={DR_DB_ENGINE})")
    #
    # if DR_DB_ENGINE == 'postgresql':
    #     q = '"'    # identifier quoting char for PostgreSQL
    # else:
    #     q = '`'    # identifier quoting char for MySQL
    #
    # query = (
    #     f"SELECT {q}{DR_APP_ID_COLUMN}{q}, "
    #     f"{q}{DR_LAST_TEST_COL}{q} "
    #     f"FROM {DR_DB_TABLE}"
    # )
    #
    # records = []
    #
    # if DR_DB_ENGINE == 'postgresql':
    #     import psycopg2
    #     conn = psycopg2.connect(
    #         host=host, port=port, dbname=dbname,
    #         user=username, password=password,
    #         connect_timeout=10,
    #         sslmode='require'
    #     )
    # else:
    #     import pymysql
    #     conn = pymysql.connect(
    #         host=host, port=port, db=dbname,
    #         user=username, password=password,
    #         connect_timeout=10,
    #         ssl={'ssl': True}
    #     )
    #
    # try:
    #     with conn.cursor() as cur:
    #         cur.execute(query)
    #         columns = [desc[0] for desc in cur.description]
    #         rows    = cur.fetchall()
    #
    #     logger.info(f"DR database returned {len(rows)} rows")
    #
    #     for row in rows:
    #         raw          = dict(zip(columns, row))
    #         app_id       = _coerce_str(raw.get(DR_APP_ID_COLUMN))
    #         last_test_dt = _coerce_datetime(raw.get(DR_LAST_TEST_COL))
    #         if not app_id:
    #             continue
    #         records.append({
    #             'app_id':            _normalise_app_id(app_id),
    #             'last_test_datetime': last_test_dt,
    #             'raw':               {k: _serialisable(v) for k, v in raw.items()}
    #         })
    # finally:
    #     conn.close()
    #
    # return records


def get_db_credentials() -> dict:
    """
    Retrieve DB credentials from Secrets Manager.
    Secret JSON must contain: host, port, dbname, username, password

    Not called in testing mode — only used by the commented-out production block.
    """
    if not DR_SECRET_ARN:
        raise ValueError("DR_SECRET_ARN environment variable is not set")

    response = sm.get_secret_value(SecretId=DR_SECRET_ARN)
    secret   = json.loads(response['SecretString'])
    return secret


# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — Query DynamoDB for all audit items matching an app_id
# ─────────────────────────────────────────────────────────────────────────────

def query_dynamo_by_app_id(app_id: str) -> list:
    """
    Scan DynamoDB for RDS audit records whose tags.app_id (or tags.APP_ID /
    tags.AppId) matches the given app_id.

    Strategy: use a GSI scan with a FilterExpression. 
    
    IMPORTANT: If your table grows large, consider adding a GSI on app_id
    or using DynamoDB Streams + a secondary index. For typical RDS fleet
    sizes (tens to low hundreds of instances) a filtered scan is fine.

    Returns list of {PK, SK} dicts for UpdateItem calls.
    """
    from boto3.dynamodb.conditions import Key, Attr

    normalised = _normalise_app_id(app_id)

    # Query the GSI1 index — all RDS records share GSI1PK = 'RDS#DATE#...'
    # We instead do a scan with a filter because app_id is buried inside
    # the 'tags' map attribute.  For larger fleets, add a dedicated GSI.
    matched = []
    try:
        paginator = dynamodb.meta.client.get_paginator('scan')
        filter_expr = (
            "begins_with(#pk, :pk_prefix) AND ("
            "contains(#tags.app_id, :app_id) OR "
            "contains(#tags.APP_ID, :app_id) OR "
            "contains(#tags.AppId, :app_id)"
            ")"
        )

        pages = paginator.paginate(
            TableName=DYNAMODB_TABLE,
            FilterExpression=filter_expr,
            ExpressionAttributeNames={
                '#pk':   'PK',
                '#tags': 'tags'
            },
            ExpressionAttributeValues={
                ':pk_prefix': 'RDS#ACCOUNT#',
                ':app_id':    app_id           # try original casing first
            }
        )

        for page in pages:
            for item in page.get('Items', []):
                # Double-check with normalised comparison (handles hyphen/underscore drift)
                item_tags   = item.get('tags', {})
                item_app_id = (item_tags.get('app_id') or item_tags.get('APP_ID')
                               or item_tags.get('AppId') or '')
                if _normalise_app_id(str(item_app_id)) == normalised:
                    matched.append({'PK': item['PK'], 'SK': item['SK']})

    except Exception as e:
        logger.error(f"DynamoDB query error for app_id={app_id}: {e}")

    logger.info(f"  app_id={app_id} → {len(matched)} DynamoDB items matched")
    return matched


# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — Write DR data back to the matched DynamoDB item
# ─────────────────────────────────────────────────────────────────────────────

def update_item_with_dr(pk: str, sk: str, app_id: str,
                        last_test_datetime, enriched_at: str, raw_row: dict):
    """
    Adds / overwrites a 'dr' attribute block on an existing DynamoDB item.

    The block looks like:
    {
        "dr": {
            "app_id":            "pocapp",
            "last_test_datetime": "2025-03-01T14:30:00",
            "enriched_at":       "2026-03-23T10:00:00",
            "source_table":      "dr_application_tests",
            "raw":               { ... original row from DR DB ... }
        }
    }

    Uses UpdateItem (not PutItem) so all existing audit fields are preserved.
    """
    dr_block = _strip_none({
        'app_id':            app_id,
        'last_test_datetime': last_test_datetime,
        'enriched_at':       enriched_at,
        'source_table':      DR_DB_TABLE,
        'raw':               raw_row or None
    })

    table.update_item(
        Key={'PK': pk, 'SK': sk},
        UpdateExpression='SET #dr = :dr_block, #dr_enriched_at = :enriched_at',
        ExpressionAttributeNames={
            '#dr':            'dr',
            '#dr_enriched_at': 'dr_last_enriched_at'
        },
        ExpressionAttributeValues={
            ':dr_block':    dr_block,
            ':enriched_at': enriched_at
        }
    )


# ─────────────────────────────────────────────────────────────────────────────
# Utility helpers
# ─────────────────────────────────────────────────────────────────────────────

def _normalise_app_id(value: str) -> str:
    """Lower-case, strip hyphens/underscores — consistent with audit Lambda."""
    return re.sub(r'[-_\s]', '', str(value).lower())


def _coerce_str(value) -> str:
    """Safely convert any DB value to a stripped string."""
    if value is None:
        return ''
    return str(value).strip()


def _coerce_datetime(value) -> str | None:
    """
    Coerce a DB datetime value to an ISO-8601 string.
    Handles: datetime objects, date objects, strings, None.
    """
    if value is None:
        return None
    if hasattr(value, 'isoformat'):        # datetime / date object
        return value.isoformat()
    s = str(value).strip()
    if not s or s.lower() in ('none', 'null', 'n/a', ''):
        return None
    return s


def _serialisable(value):
    """Make a DB row value safe for DynamoDB / JSON (no datetime objects)."""
    if value is None:
        return None
    if hasattr(value, 'isoformat'):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    return value


def _strip_none(obj):
    """Recursively remove None values — DynamoDB rejects them."""
    if isinstance(obj, dict):
        return {k: _strip_none(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_strip_none(i) for i in obj if i is not None]
    return obj


def _response(status, message, enriched, skipped, errors):
    return {
        'statusCode': status,
        'body': json.dumps({
            'message':       message,
            'enriched_count': enriched,
            'skipped_count':  skipped,
            'error_count':    errors
        })
    }
