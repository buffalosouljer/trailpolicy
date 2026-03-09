"""Athena backend for querying CloudTrail logs at scale."""

from __future__ import annotations

import json
import logging
import time

import boto3

from ..config import BOTO_CONFIG

logger = logging.getLogger(__name__)


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
        WorkGroup=workgroup,
    )
    query_execution_id = response["QueryExecutionId"]
    logger.info("Athena query ID: %s", query_execution_id)

    # Poll for completion
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
