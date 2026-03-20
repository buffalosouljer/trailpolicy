"""Fetch CloudTrail management events for a specific IAM principal."""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone

import boto3

from ..config import BOTO_CONFIG, LOOKUP_EVENTS_PAGE_SIZE, LOOKUP_EVENTS_TPS

logger = logging.getLogger(__name__)


def fetch_events(
    role_arn: str,
    days: int = 30,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    region: str | None = None,
) -> list[dict]:
    """Fetch CloudTrail events for a role using LookupEvents API.

    Args:
        role_arn: IAM role ARN to look up events for.
        days: Lookback period in days (used if start_date not provided).
        start_date: Explicit start date (overrides days).
        end_date: Explicit end date (default: now).
        region: AWS region for the CloudTrail client.

    Returns:
        List of raw CloudTrail event dicts (parsed from CloudTrailEvent JSON).
    """
    if not end_date:
        end_date = datetime.now(timezone.utc)
    if not start_date:
        start_date = end_date - timedelta(days=days)

    client = boto3.client("cloudtrail", region_name=region, config=BOTO_CONFIG)

    # Extract role name for Username lookup
    role_name = _role_name_from_arn(role_arn)

    all_events = []

    # Strategy 1: Look up by Username (covers role session events)
    logger.info(
        "Fetching CloudTrail events for %s from %s to %s",
        role_arn,
        start_date.isoformat(),
        end_date.isoformat(),
    )
    events_by_user = _paginate_lookup(
        client,
        lookup_attributes=[
            {"AttributeKey": "Username", "AttributeValue": role_name}
        ],
        start_time=start_date,
        end_time=end_date,
    )
    all_events.extend(events_by_user)

    # Strategy 2: Look up by ResourceName (catches events where role is a resource)
    events_by_resource = _paginate_lookup(
        client,
        lookup_attributes=[
            {"AttributeKey": "ResourceName", "AttributeValue": role_arn}
        ],
        start_time=start_date,
        end_time=end_date,
    )
    all_events.extend(events_by_resource)

    # Deduplicate by eventId
    seen_ids: set[str] = set()
    unique_events: list[dict] = []
    for event in all_events:
        event_id = event.get("EventId", "")
        if event_id and event_id not in seen_ids:
            seen_ids.add(event_id)
            unique_events.append(event)

    if not unique_events:
        logger.warning(
            "No CloudTrail events found for %s in the last %d days. "
            "Verify the trail is active and logging management events.",
            role_arn,
            days,
        )

    logger.info("Found %d unique events", len(unique_events))
    return unique_events


def _paginate_lookup(
    client,
    lookup_attributes: list[dict],
    start_time: datetime,
    end_time: datetime,
) -> list[dict]:
    """Paginate through CloudTrail LookupEvents with rate limiting."""
    events = []
    kwargs = {
        "LookupAttributes": lookup_attributes,
        "StartTime": start_time,
        "EndTime": end_time,
        "MaxResults": LOOKUP_EVENTS_PAGE_SIZE,
    }

    while True:
        response = client.lookup_events(**kwargs)
        page_events = response.get("Events", [])
        events.extend(page_events)

        next_token = response.get("NextToken")
        if not next_token:
            break

        kwargs["NextToken"] = next_token
        # Rate limit: LookupEvents is limited to 2 TPS
        time.sleep(1.0 / LOOKUP_EVENTS_TPS)

    return events


def _role_name_from_arn(role_arn: str) -> str:
    """Extract the role name from an IAM role ARN.

    arn:aws:iam::123456789012:role/path/RoleName -> RoleName
    """
    resource = role_arn.split(":")[-1]  # role/path/RoleName or role/RoleName
    return resource.split("/")[-1]
