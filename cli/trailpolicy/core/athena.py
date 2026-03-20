"""Athena backend for querying CloudTrail logs at scale."""

from __future__ import annotations

import json
import logging
import re
import time

import boto3

from ..config import BOTO_CONFIG

logger = logging.getLogger(__name__)

_ARN_PATTERN = re.compile(
    r"^arn:[a-z\-]+:iam::\d{12}:(role|user)/[\w+=,.@/\-]+$"
)
_SAFE_IDENTIFIER = re.compile(r"^[a-zA-Z0-9_]+$")
_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _validate_athena_inputs(
    role_arn: str,
    database: str,
    table: str,
    start_date: str,
    end_date: str,
) -> None:
    """Validate inputs before interpolating into SQL to prevent injection."""
    if not _ARN_PATTERN.match(role_arn):
        raise ValueError(f"Invalid role ARN format: {role_arn}")
    if not _SAFE_IDENTIFIER.match(database):
        raise ValueError(
            f"Invalid database name: {database!r}. "
            "Must be alphanumeric with underscores only."
        )
    if not _SAFE_IDENTIFIER.match(table):
        raise ValueError(
            f"Invalid table name: {table!r}. "
            "Must be alphanumeric with underscores only."
        )
    if not _DATE_PATTERN.match(start_date):
        raise ValueError(f"Invalid start_date format: {start_date!r}. Use YYYY-MM-DD.")
    if not _DATE_PATTERN.match(end_date):
        raise ValueError(f"Invalid end_date format: {end_date!r}. Use YYYY-MM-DD.")


def fetch_events_athena(
    role_arn: str,
    database: str,
    table: str,
    workgroup: str,
    start_date: str,
    end_date: str,
    region: str | None = None,
) -> list[dict]:
    """Query CloudTrail events via Athena for large-scale analysis.

    Args:
        role_arn: IAM role ARN to filter events by.
        database: Glue catalog database name.
        table: Glue catalog table name.
        workgroup: Athena workgroup name.
        start_date: Start date in YYYY-MM-DD format.
        end_date: End date in YYYY-MM-DD format.
        region: AWS region.

    Returns:
        List of event dicts matching the CloudTrail event format.
    """
    _validate_athena_inputs(role_arn, database, table, start_date, end_date)

    client = boto3.client("athena", region_name=region, config=BOTO_CONFIG)

    query = f"""
        SELECT eventsource, eventname, resources, requestparameters,
               useridentity, errorcode, readonly, eventtime, awsregion,
               recipientaccountid
        FROM {database}.{table}
        WHERE useridentity.sessioncontext.sessionissuer.arn = '{role_arn}'
          AND concat(year, '-', month, '-', day) BETWEEN '{start_date}' AND '{end_date}'
          AND (errorcode IS NULL OR errorcode = '')
    """

    logger.info("Starting Athena query for %s (%s to %s)", role_arn, start_date, end_date)

    # Start query execution
    response = client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={"Database": database, "Catalog": "AwsDataCatalog"},
        WorkGroup=workgroup,
    )
    query_execution_id = response["QueryExecutionId"]
    logger.info("Athena query ID: %s", query_execution_id)

    # Poll for completion (300s timeout)
    timeout_secs = 300
    start_time = time.monotonic()
    while True:
        status_response = client.get_query_execution(
            QueryExecutionId=query_execution_id
        )
        state = status_response["QueryExecution"]["Status"]["State"]
        if state == "SUCCEEDED":
            break
        elif state in ("FAILED", "CANCELLED"):
            reason = (
                status_response["QueryExecution"]["Status"]
                .get("StateChangeReason", "Unknown")
            )
            logger.error("Athena query %s: %s", state, reason)
            return []
        if time.monotonic() - start_time > timeout_secs:
            logger.error(
                "Athena query %s timed out after %ds",
                query_execution_id, timeout_secs,
            )
            raise TimeoutError(
                f"Athena query did not complete within {timeout_secs}s"
            )
        time.sleep(2)

    # Fetch results
    events = []
    kwargs = {"QueryExecutionId": query_execution_id, "MaxResults": 1000}
    first_page = True

    while True:
        result = client.get_query_results(**kwargs)
        rows = result["ResultSet"]["Rows"]

        # Skip header row on first page
        start_idx = 1 if first_page else 0
        first_page = False

        columns = [
            "eventSource", "eventName", "resources", "requestParameters",
            "userIdentity", "errorCode", "readOnly", "eventTime", "awsRegion",
            "recipientAccountId",
        ]

        for row in rows[start_idx:]:
            values = [col.get("VarCharValue", "") for col in row["Data"]]
            event = dict(zip(columns, values))

            # Parse JSON fields
            for field in ("resources", "requestParameters", "userIdentity"):
                if event.get(field):
                    try:
                        event[field] = json.loads(event[field])
                    except (json.JSONDecodeError, TypeError):
                        pass

            events.append(event)

        next_token = result.get("NextToken")
        if not next_token:
            break
        kwargs["NextToken"] = next_token

    logger.info("Athena returned %d events", len(events))
    return events
