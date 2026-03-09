"""Lambda handler for trailpolicy SNS notification test.

Runs the core pipeline against a single role, computes a diff, and
publishes a formatted email via SNS.
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone

import boto3

from trailpolicy.config import detect_partition
from trailpolicy.core.action_mapper import ActionMapper
from trailpolicy.core.cloudtrail import fetch_events
from trailpolicy.core.event_parser import parse_events
from trailpolicy.core.policy_builder import build_policy
from trailpolicy.core.resource_extractor import extract_resources
from trailpolicy.output.diff_reporter import compute_diff, format_diff_text
from trailpolicy.output.json_formatter import format_policy_json

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns = boto3.client("sns")
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]


def handler(event, context):
    """Lambda entry point.

    Expected event:
        {
            "role_arn": "arn:aws:iam::123456789012:role/MyRole",
            "days": 30,
            "source": "api"
        }
    """
    role_arn = event["role_arn"]
    days = event.get("days", 30)
    source = event.get("source", "api")
    region = os.environ.get("AWS_REGION", "us-east-1")

    logger.info("Processing role_arn=%s days=%d source=%s", role_arn, days, source)

    # Detect partition
    try:
        partition = detect_partition(region)
    except Exception:
        partition = "aws"

    # 1. Fetch CloudTrail events
    if source == "athena":
        from trailpolicy.core.athena import fetch_events_athena

        now = datetime.now(timezone.utc)
        start = (now - timedelta(days=days)).strftime("%Y-%m-%d")
        end = now.strftime("%Y-%m-%d")
        raw_events = fetch_events_athena(
            role_arn=role_arn,
            database=os.environ.get("ATHENA_DATABASE", ""),
            table=os.environ.get("ATHENA_TABLE", ""),
            workgroup=os.environ.get("ATHENA_WORKGROUP", ""),
            start_date=start,
            end_date=end,
            region=region,
        )
    else:
        raw_events = fetch_events(role_arn=role_arn, days=days, region=region)

    if not raw_events:
        logger.warning("No CloudTrail events found for %s", role_arn)
        return {
            "statusCode": 200,
            "role": role_arn,
            "message": "No events found",
        }

    # 2. Parse, map, extract, build
    parsed = parse_events(raw_events)
    mapper = ActionMapper()
    for evt in parsed:
        evt.iam_action = mapper.resolve(evt.event_source, evt.event_name)
    enriched = extract_resources(parsed, partition=partition)
    policy, metadata = build_policy(enriched)

    # 3. Compute diff against current policies
    diff_result = compute_diff(role_arn, policy, region=region)

    # 4. Format and send email
    role_name = role_arn.split("/")[-1]
    subject = f"trailpolicy Diff: {role_name} ({diff_result.coverage_pct}% coverage)"

    body = format_email(role_arn, days, diff_result, policy)

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject[:100],
        Message=body,
    )

    logger.info(
        "Published SNS notification for %s: coverage=%d%% unused=%d missing=%d matched=%d",
        role_name,
        diff_result.coverage_pct,
        len(diff_result.unused),
        len(diff_result.missing),
        len(diff_result.matched),
    )

    return {
        "statusCode": 200,
        "role": role_arn,
        "coverage_pct": diff_result.coverage_pct,
        "unused_count": len(diff_result.unused),
        "missing_count": len(diff_result.missing),
        "matched_count": len(diff_result.matched),
    }


def format_email(role_arn, days, diff, policy):
    """Build the 3-section email body."""
    sections = []

    # Section 1: Summary
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sections.append(
        f"=== trailpolicy Policy Diff Report ===\n"
        f"Role: {role_arn}\n"
        f"Lookback: {days} days\n"
        f"Generated: {now}\n"
        f"\n"
        f"Coverage: {diff.coverage_pct}% of granted permissions observed\n"
        f"Current Policy Actions: {diff.current_action_count}\n"
        f"Observed Actions: {diff.observed_action_count}\n"
    )

    # Section 2: Comparison grouped by service
    sections.append("--- CURRENT POLICY vs OBSERVED USAGE ---\n")
    sections.append(format_diff_text(diff))

    # Section 3: Recommended policy JSON
    sections.append("\n--- RECOMMENDED POLICY ---\n")
    sections.append(format_policy_json(policy, pretty=True))

    return "\n".join(sections)
