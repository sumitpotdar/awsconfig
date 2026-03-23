"""
dr_enrichment_lambda.py
────────────────────────────────────────────────────────────────────────────────
Separate Lambda function that enriches existing RDS audit records in DynamoDB
with Disaster Recovery (DR) test data pulled from an external Aurora/RDS database.

Runs on its own EventBridge schedule (e.g. weekly/monthly) — completely
independent of the main RDS security audit Lambda.

Connection model
────────────────
  DB endpoint  →  DR_DB_ENDPOINT  (Lambda env var)
                  e.g. mydr-cluster.cluster-xyz.us-east-1.rds.amazonaws.com
                  NOTE: the host/endpoint is intentionally kept in an env var
                  (NOT inside the secret) so the same Secret can be shared
                  across dev / staging / prod by simply swapping DR_DB_ENDPOINT.

  Credentials  →  DR_SECRET_ARN   (Lambda env var — Secrets Manager ARN)
                  The secret value must be a JSON object:
                  {
                    "username": "druser",
                    "password": "s3cr3t!",
                    "dbname":   "drdb",
                    "port":     5432        <- optional, defaults 5432/3306
                  }

Environment variables
─────────────────────
  DYNAMODB_TABLE    – DynamoDB table name              (default: RDSSecurityAudit)
  DR_DB_ENDPOINT    – DR database hostname / endpoint  (REQUIRED for production)
  DR_SECRET_ARN     – Secrets Manager ARN              (REQUIRED for production)
  DR_DB_TABLE       – Table/view name in DR database   (default: dr_application_tests)
  DR_APP_ID_COLUMN  – Column name for Application ID   (default: Application ID)
  DR_LAST_TEST_COL  – Column name for last test dt     (default: Last application test date/time)
  DR_DB_ENGINE      – mysql | postgresql                (default: postgresql)

VPC note
────────
  This Lambda MUST be in the same VPC as the Aurora/RDS DR database.
  Attach a security group that has inbound access on the DB port.

IAM permissions required
────────────────────────
  - secretsmanager:GetSecretValue  for DR_SECRET_ARN
  - dynamodb:Scan                  on DYNAMODB_TABLE
  - dynamodb:UpdateItem            on DYNAMODB_TABLE
"""

import json
import os
import re
import boto3
import logging
from datetime import datetime
from decimal import Decimal

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ── Environment variables ─────────────────────────────────────────────────────
DYNAMODB_TABLE   = os.environ.get('DYNAMODB_TABLE',   'RDSSecurityAudit')
DR_DB_ENDPOINT   = os.environ.get('DR_DB_ENDPOINT',   '')   # hostname only — no port
DR_SECRET_ARN    = os.environ.get('DR_SECRET_ARN',    '')   # SM ARN → username/password/dbname
DR_DB_TABLE      = os.environ.get('DR_DB_TABLE',      'dr_application_tests')
DR_APP_ID_COLUMN = os.environ.get('DR_APP_ID_COLUMN', 'Application ID')
DR_LAST_TEST_COL = os.environ.get('DR_LAST_TEST_COL', 'Last application test date/time')
DR_DB_ENGINE     = os.environ.get('DR_DB_ENGINE',     'postgresql').lower()

# ── AWS clients ───────────────────────────────────────────────────────────────
dynamodb = boto3.resource('dynamodb')
table    = dynamodb.Table(DYNAMODB_TABLE)
sm       = boto3.client('secretsmanager')


# ─────────────────────────────────────────────────────────────────────────────
# Lambda entry point
# ─────────────────────────────────────────────────────────────────────────────

def lambda_handler(event, context):
    """
    1. Fetch DR test records (test data OR real DB — see fetch_dr_records).
    2. For each DR record, find matching DynamoDB RDS audit items by app_id.
    3. UpdateItem on each match — adds/overwrites the 'dr' attribute block.
    """
    logger.info(f"DR enrichment started at {datetime.now().isoformat()}")

    enriched_count = 0
    skipped_count  = 0
    error_count    = 0

    try:
        dr_records = fetch_dr_records()
        logger.info(f"Fetched {len(dr_records)} DR records")

        if not dr_records:
            logger.warning("No DR records returned — nothing to enrich")
            return _response(200, "No DR records found — nothing to enrich", 0, 0, 0)

        enriched_at = datetime.now().isoformat()

        for dr in dr_records:
            app_id       = dr.get('app_id')
            last_test_dt = dr.get('last_test_datetime')
            raw_row      = dr.get('raw', {})

            if not app_id:
                logger.warning(f"DR record missing app_id — skipping: {dr}")
                skipped_count += 1
                continue

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

        logger.info(f"DR enrichment complete — "
                    f"enriched={enriched_count}, skipped={skipped_count}, errors={error_count}")
        return _response(200, "Enrichment complete", enriched_count, skipped_count, error_count)

    except Exception as e:
        logger.error(f"DR enrichment failed: {e}")
        raise


# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Fetch DR records
#
# ⚠️  TESTING MODE is currently active.
#     The real DB connection is fully built below but commented out.
#     _TEST_DR_ROWS simulates what the real DR table would return.
#
#     To go live:
#       1. Comment out / delete the TESTING MODE block inside fetch_dr_records
#       2. Uncomment the PRODUCTION block inside fetch_dr_records
#       3. Set DR_DB_ENDPOINT and DR_SECRET_ARN as Lambda environment variables
# ─────────────────────────────────────────────────────────────────────────────

# ── Hardcoded test rows ───────────────────────────────────────────────────────
# Column names match exactly what the real DR database table has.
# "Application ID" values must match the app_id tag on your RDS instances
# (case / hyphens / underscores are ignored during matching).
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
# ─────────────────────────────────────────────────────────────────────────────


def fetch_dr_records() -> list:
    """
    Returns normalised DR records:
        [
          {
            'app_id':             'pocapp',
            'last_test_datetime': '2025-03-01T14:30:00',
            'raw':                { ... original row ... }
          },
          ...
        ]
    """

    # ══════════════════════════════════════════════════════════════════════════
    # TESTING MODE — reads from _TEST_DR_ROWS, no DB or AWS calls needed.
    # Comment out this entire block and uncomment PRODUCTION below when ready.
    # ══════════════════════════════════════════════════════════════════════════
    logger.info(f"[TEST MODE] Using hardcoded test data ({len(_TEST_DR_ROWS)} rows) "
                "— real DB connection is disabled")

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
    # END TESTING MODE
    # ══════════════════════════════════════════════════════════════════════════


    # ══════════════════════════════════════════════════════════════════════════
    # PRODUCTION — uncomment this entire block when going live.
    #
    # Connection params are resolved by _get_connection_params():
    #   endpoint  ← DR_DB_ENDPOINT  (env var, hostname only)
    #   port      ← secret JSON     (or engine default 5432 / 3306)
    #   dbname    ← secret JSON
    #   username  ← secret JSON
    #   password  ← secret JSON
    #
    # Secret at DR_SECRET_ARN must contain:
    #   { "username": "...", "password": "...", "dbname": "...", "port": 5432 }
    # ══════════════════════════════════════════════════════════════════════════
    #
    # endpoint, port, dbname, username, password = _get_connection_params()
    # conn = _open_db_connection(endpoint, port, dbname, username, password)
    #
    # # Identifier quoting: double-quotes for PostgreSQL, backticks for MySQL
    # q     = '"' if DR_DB_ENGINE == 'postgresql' else '`'
    # query = (f"SELECT {q}{DR_APP_ID_COLUMN}{q}, "
    #          f"{q}{DR_LAST_TEST_COL}{q} "
    #          f"FROM {DR_DB_TABLE}")
    #
    # records = []
    # try:
    #     with conn.cursor() as cur:
    #         cur.execute(query)
    #         columns = [desc[0] for desc in cur.description]
    #         rows    = cur.fetchall()
    #     logger.info(f"DR database returned {len(rows)} rows from {DR_DB_TABLE}")
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
    # ══════════════════════════════════════════════════════════════════════════
    # END PRODUCTION
    # ══════════════════════════════════════════════════════════════════════════


# ─────────────────────────────────────────────────────────────────────────────
# DB connection helpers  (used only by the PRODUCTION block above)
# ─────────────────────────────────────────────────────────────────────────────

def _get_connection_params() -> tuple:
    """
    Resolve all DB connection parameters and return them as a tuple:
        (endpoint, port, dbname, username, password)

    Source of each parameter:
      endpoint  →  DR_DB_ENDPOINT  env var          (hostname only, no port)
      port      →  secret JSON field 'port'         (optional — falls back to engine default)
      dbname    →  secret JSON field 'dbname'       (required)
      username  →  secret JSON field 'username'     (required)
      password  →  secret JSON field 'password'     (required)

    Secret JSON example (stored at DR_SECRET_ARN):
      {
        "username": "druser",
        "password": "s3cr3t!",
        "dbname":   "drdb",
        "port":     5432
      }
    """
    if not DR_DB_ENDPOINT:
        raise ValueError(
            "DR_DB_ENDPOINT env var is not set. "
            "Set it to the Aurora/RDS cluster endpoint hostname, e.g. "
            "mydr.cluster-xyz.us-east-1.rds.amazonaws.com"
        )
    if not DR_SECRET_ARN:
        raise ValueError(
            "DR_SECRET_ARN env var is not set. "
            "Set it to the Secrets Manager ARN containing username/password/dbname."
        )

    # ── Retrieve credentials from Secrets Manager ─────────────────────────────
    logger.info(f"Fetching DB credentials from Secrets Manager ARN: {DR_SECRET_ARN}")
    try:
        response = sm.get_secret_value(SecretId=DR_SECRET_ARN)
        secret   = json.loads(response['SecretString'])
    except Exception as e:
        raise RuntimeError(
            f"Failed to retrieve secret from Secrets Manager ({DR_SECRET_ARN}): {e}"
        ) from e

    # ── Validate required fields ──────────────────────────────────────────────
    missing = [k for k in ('username', 'password', 'dbname') if k not in secret]
    if missing:
        raise ValueError(
            f"Secret {DR_SECRET_ARN} is missing required field(s): {missing}. "
            "Secret must contain: username, password, dbname, (optional) port."
        )

    default_port = 5432 if DR_DB_ENGINE == 'postgresql' else 3306
    port         = int(secret.get('port', default_port))
    dbname       = secret['dbname']
    username     = secret['username']
    password     = secret['password']

    logger.info(f"Connection params resolved — "
                f"endpoint={DR_DB_ENDPOINT} port={port} dbname={dbname} user={username}")

    return DR_DB_ENDPOINT, port, dbname, username, password


def _open_db_connection(endpoint: str, port: int, dbname: str,
                        username: str, password: str):
    """
    Open and return a DB-API 2.0 connection.  TLS enforced on both engines.

    Lambda layer required:
      PostgreSQL → psycopg2-binary
      MySQL      → PyMySQL
    """
    if DR_DB_ENGINE == 'postgresql':
        import psycopg2
        logger.info(f"Opening PostgreSQL connection → {endpoint}:{port}/{dbname}")
        return psycopg2.connect(
            host=endpoint,
            port=port,
            dbname=dbname,
            user=username,
            password=password,
            connect_timeout=10,
            sslmode='require'       # enforce TLS to DR DB
        )

    elif DR_DB_ENGINE == 'mysql':
        import pymysql
        logger.info(f"Opening MySQL connection → {endpoint}:{port}/{dbname}")
        return pymysql.connect(
            host=endpoint,
            port=port,
            db=dbname,
            user=username,
            password=password,
            connect_timeout=10,
            ssl={'ssl': True}       # enforce TLS to DR DB
        )

    else:
        raise ValueError(
            f"Unsupported DR_DB_ENGINE='{DR_DB_ENGINE}'. Use 'postgresql' or 'mysql'."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — Query DynamoDB for all audit items matching an app_id
# ─────────────────────────────────────────────────────────────────────────────

def query_dynamo_by_app_id(app_id: str) -> list:
    """
    Scan DynamoDB for RDS audit records whose tags.app_id (or tags.APP_ID /
    tags.AppId) matches the given app_id (normalised comparison).

    Returns list of {PK, SK} dicts for use in UpdateItem calls.
    """
    normalised = _normalise_app_id(app_id)
    matched    = []

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
                ':app_id':    app_id
            }
        )

        for page in pages:
            for item in page.get('Items', []):
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
    Uses UpdateItem (not PutItem) so all existing audit fields are preserved.

    Resulting 'dr' block in DynamoDB:
    {
        "app_id":             "pocapp",
        "last_test_datetime": "2025-03-01T14:30:00",
        "enriched_at":        "2026-03-23T10:00:00",
        "source_table":       "dr_application_tests",
        "raw":                { ... original columns from DR DB row ... }
    }
    """
    dr_block = _strip_none({
        'app_id':             app_id,
        'last_test_datetime': last_test_datetime,
        'enriched_at':        enriched_at,
        'source_table':       DR_DB_TABLE,
        'raw':                raw_row or None
    })

    table.update_item(
        Key={'PK': pk, 'SK': sk},
        UpdateExpression='SET #dr = :dr_block, #dr_enriched_at = :enriched_at',
        ExpressionAttributeNames={
            '#dr':             'dr',
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
    """Lower-case and strip hyphens/underscores — consistent with audit Lambda."""
    return re.sub(r'[-_\s]', '', str(value).lower())


def _coerce_str(value) -> str:
    if value is None:
        return ''
    return str(value).strip()


def _coerce_datetime(value) -> str | None:
    """Coerce a DB datetime value to an ISO-8601 string."""
    if value is None:
        return None
    if hasattr(value, 'isoformat'):     # datetime / date object from DB driver
        return value.isoformat()
    s = str(value).strip()
    if not s or s.lower() in ('none', 'null', 'n/a', ''):
        return None
    return s


def _serialisable(value):
    """Convert a DB row value to something safe for DynamoDB storage."""
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
            'message':        message,
            'enriched_count': enriched,
            'skipped_count':  skipped,
            'error_count':    errors
        })
    }
