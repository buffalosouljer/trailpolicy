"""Lambda handler for trailpolicy automation.

Processes a list of IAM roles: generates least-privilege policies, stores
them in S3, computes diffs, and optionally sends SNS notifications.
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

s3 = boto3.client("s3")
OUTPUT_BUCKET = os.environ["OUTPUT_BUCKET"]
KMS_KEY_ARN = os.environ.get("KMS_KEY_ARN", "")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")


def handler(event, context):
    """Lambda entry point.

    Expected event (from EventBridge or manual invoke):
        {
            "role_arns": ["arn:aws:iam::123456789012:role/MyRole", ...],
            "days": 30,
            "source": "api"
        }
    """
    role_arns = event.get("role_arns", [])
    days = event.get("days", 30)
    source = event.get("source", "api")
    region = os.environ.get("AWS_REGION", "us-east-1")

    if not role_arns:
        logger.error("No role_arns provided in event")
        return {"statusCode": 400, "error": "No role_arns provided"}

    logger.info("Processing %d roles, days=%d, source=%s", len(role_arns), days, source)

    try:
        partition = detect_partition(region)
    except Exception:
        partition = "aws"

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    results = []

    for role_arn in role_arns:
        role_name = role_arn.split("/")[-1]
        logger.info("Processing role: %s", role_name)

        try:
            result = _process_role(role_arn, role_name, days, source, region, partition, today)
            results.append(result)
        except Exception as e:
            logger.error("Failed to process %s: %s", role_name, e, exc_info=True)
            results.append({
                "role": role_arn,
                "role_name": role_name,
                "status": "error",
                "error": str(e),
            })

    # Send summary notification
    if SNS_TOPIC_ARN:
        _send_summary(results, days, today)

    return {
        "statusCode": 200,
        "date": today,
        "roles_processed": len(results),
        "roles_succeeded": sum(1 for r in results if r.get("status") == "success"),
        "roles_failed": sum(1 for r in results if r.get("status") == "error"),
        "results": results,
    }


def _process_role(role_arn, role_name, days, source, region, partition, today):
    """Run the full pipeline for a single role."""
    # 1. Fetch events
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
        logger.warning("No events found for %s", role_name)
        return {
            "role": role_arn,
            "role_name": role_name,
            "status": "success",
            "events_found": 0,
            "message": "No events found",
        }

    # 2. Parse, map, extract, build
    parsed = parse_events(raw_events)
    mapper = ActionMapper()
    for evt in parsed:
        evt.iam_action = mapper.resolve(evt.event_source, evt.event_name)
    enriched = extract_resources(parsed, partition=partition)
    policy, metadata = build_policy(enriched)

    # 3. Store policy in S3
    policy_json = format_policy_json(policy, pretty=True)
    s3_key = f"{role_name}/{today}/policy.json"

    put_kwargs = {
        "Bucket": OUTPUT_BUCKET,
        "Key": s3_key,
        "Body": policy_json,
        "ContentType": "application/json",
    }
    if KMS_KEY_ARN:
        put_kwargs["ServerSideEncryption"] = "aws:kms"
        put_kwargs["SSEKMSKeyId"] = KMS_KEY_ARN

    s3.put_object(**put_kwargs)
    logger.info("Stored policy at s3://%s/%s", OUTPUT_BUCKET, s3_key)

    # 4. Compute diff
    diff_result = compute_diff(role_arn, policy, region=region)

    # 5. Store diff report in S3
    diff_text = format_diff_text(diff_result)
    diff_key = f"{role_name}/{today}/diff_report.txt"
    s3.put_object(
        Bucket=OUTPUT_BUCKET,
        Key=diff_key,
        Body=diff_text,
        ContentType="text/plain",
    )

    return {
        "role": role_arn,
        "role_name": role_name,
        "status": "success",
        "events_found": len(raw_events),
        "events_parsed": len(parsed),
        "total_actions": metadata.total_actions,
        "total_services": metadata.total_services,
        "policy_size": metadata.policy_size,
        "coverage_pct": diff_result.coverage_pct,
        "unused_count": len(diff_result.unused),
        "missing_count": len(diff_result.missing),
        "matched_count": len(diff_result.matched),
        "s3_policy_key": s3_key,
        "s3_diff_key": diff_key,
    }


def _send_summary(results, days, today):
    """Send an SNS summary notification."""
    sns = boto3.client("sns")

    succeeded = [r for r in results if r.get("status") == "success"]
    failed = [r for r in results if r.get("status") == "error"]

    lines = [
        f"=== trailpolicy Automation Report ===",
        f"Date: {today}",
        f"Lookback: {days} days",
        f"Roles processed: {len(results)}",
        f"Succeeded: {len(succeeded)}",
        f"Failed: {len(failed)}",
        "",
    ]

    if succeeded:
        lines.append("--- RESULTS ---")
        for r in succeeded:
            if r.get("events_found", 0) == 0:
                lines.append(f"  {r['role_name']}: No events found")
            else:
                lines.append(
                    f"  {r['role_name']}: "
                    f"coverage={r.get('coverage_pct', 0)}% "
                    f"unused={r.get('unused_count', 0)} "
                    f"missing={r.get('missing_count', 0)} "
                    f"matched={r.get('matched_count', 0)} "
                    f"actions={r.get('total_actions', 0)}"
                )
        lines.append("")

    if failed:
        lines.append("--- FAILURES ---")
        for r in failed:
            lines.append(f"  {r['role_name']}: {r.get('error', 'Unknown')}")
        lines.append("")

    lines.append(f"Policies stored in s3://{OUTPUT_BUCKET}/{today}/")

    subject = f"trailpolicy: {len(succeeded)}/{len(results)} roles processed ({today})"

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject[:100],
        Message="\n".join(lines),
    )
    logger.info("Published summary notification")
