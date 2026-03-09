"""Parse raw CloudTrail events into structured records."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ParsedEvent:
    """A single parsed CloudTrail event."""

    event_source: str
    event_name: str
    iam_action: str = ""
    resources: list[str] = field(default_factory=list)
    read_only: bool = False
    event_time: datetime | None = None
    error_code: str | None = None
    request_parameters: dict | None = None
    aws_region: str = ""
    account_id: str = ""


def parse_events(raw_events: list[dict]) -> list[ParsedEvent]:
    """Parse raw CloudTrail event dicts into ParsedEvent objects.

    Filters out:
    - Events with error codes (failed attempts, not actual permissions used)
    - sts:AssumeRole events where the principal IS the role being assumed
    """
    parsed = []
    skipped_errors = 0
    skipped_assume = 0

    for event in raw_events:
        # Handle both raw event dicts and LookupEvents-style wrappers
        if "CloudTrailEvent" in event:
            ct_event = json.loads(event["CloudTrailEvent"])
        else:
            ct_event = event

        error_code = ct_event.get("errorCode")
        if error_code:
            skipped_errors += 1
            continue

        event_source = ct_event.get("eventSource", "")
        event_name = ct_event.get("eventName", "")

        # Skip sts:AssumeRole for the role itself
        if event_source == "sts.amazonaws.com" and event_name == "AssumeRole":
            user_identity = ct_event.get("userIdentity", {})
            request_params = ct_event.get("requestParameters", {})
            principal_arn = user_identity.get("arn", "")
            role_arn = request_params.get("roleArn", "") if isinstance(request_params, dict) else ""
            # If the principal is assuming its own role, skip
            if role_arn and principal_arn and _is_same_role(principal_arn, role_arn):
                skipped_assume += 1
                continue

        # Parse event time
        event_time = None
        if "eventTime" in ct_event:
            try:
                event_time = datetime.fromisoformat(
                    ct_event["eventTime"].replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass

        # Extract resource ARNs from the resources array
        resource_arns = []
        for resource in ct_event.get("resources", []) or []:
            if isinstance(resource, dict) and resource.get("ARN"):
                resource_arns.append(resource["ARN"])

        # Parse request parameters
        request_parameters = ct_event.get("requestParameters")
        if isinstance(request_parameters, str):
            try:
                request_parameters = json.loads(request_parameters)
            except (json.JSONDecodeError, TypeError):
                request_parameters = None

        # Get account ID from userIdentity or recipientAccountId
        account_id = ct_event.get("recipientAccountId", "")
        if not account_id:
            account_id = (
                ct_event.get("userIdentity", {}).get("accountId", "")
            )

        parsed.append(
            ParsedEvent(
                event_source=event_source,
                event_name=event_name,
                resources=resource_arns,
                read_only=ct_event.get("readOnly", False) is True
                or str(ct_event.get("readOnly", "")).lower() == "true",
                event_time=event_time,
                error_code=None,
                request_parameters=request_parameters,
                aws_region=ct_event.get("awsRegion", ""),
                account_id=account_id,
            )
        )

    if skipped_errors:
        logger.info("Skipped %d events with error codes", skipped_errors)
    if skipped_assume:
        logger.info("Skipped %d self-AssumeRole events", skipped_assume)

    return parsed


def _is_same_role(principal_arn: str, role_arn: str) -> bool:
    """Check if a principal ARN corresponds to the same role as role_arn.

    principal_arn may be arn:...:assumed-role/RoleName/SessionName
    role_arn is arn:...:role/RoleName
    """
    try:
        principal_parts = principal_arn.split(":")
        role_parts = role_arn.split(":")
        if len(principal_parts) < 6 or len(role_parts) < 6:
            return False
        principal_resource = principal_parts[5]
        role_resource = role_parts[5]
        # Extract role name from assumed-role/RoleName/Session or role/RoleName
        if principal_resource.startswith("assumed-role/"):
            principal_role = principal_resource.split("/")[1]
        elif principal_resource.startswith("role/"):
            principal_role = principal_resource.split("/", 1)[1]
        else:
            return False
        if role_resource.startswith("role/"):
            target_role = role_resource.split("/")[-1]
        else:
            return False
        return principal_role == target_role
    except (IndexError, AttributeError):
        return False
