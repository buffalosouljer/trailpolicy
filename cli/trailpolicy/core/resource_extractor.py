"""Extract and normalize resource ARNs from CloudTrail events."""

from __future__ import annotations

import logging
from .event_parser import ParsedEvent

logger = logging.getLogger(__name__)

# Actions that only support Resource: "*" (no resource-level permissions)
WILDCARD_ONLY_PREFIXES = (
    "Describe",
    "List",
    "Get",
)

# Service-specific extractors for events that don't populate resources[]
_S3_PARAM_KEYS = ("bucketName", "bucket")
_DYNAMODB_PARAM_KEYS = ("tableName",)
_LAMBDA_PARAM_KEYS = ("functionName",)
_SQS_PARAM_KEYS = ("queueUrl",)


def extract_resources(
    events: list[ParsedEvent],
    partition: str = "aws",
) -> list[ParsedEvent]:
    """Enrich ParsedEvents with resource ARNs extracted from request parameters.

    Primary source: event.resources (already populated by event_parser)
    Secondary source: service-specific requestParameters parsing
    """
    for event in events:
        if not event.resources:
            extracted = _extract_from_params(event, partition)
            if extracted:
                event.resources = extracted
            else:
                # Wildcard for actions that can't be resource-scoped
                event.resources = ["*"]

        # Deduplicate
        event.resources = list(dict.fromkeys(event.resources))

    return events


def _extract_from_params(event: ParsedEvent, partition: str) -> list[str]:
    """Extract ARNs from requestParameters for services that don't populate resources[]."""
    params = event.request_parameters
    if not params or not isinstance(params, dict):
        return []

    service = event.event_source.replace(".amazonaws.com", "")
    region = event.aws_region
    account = event.account_id

    if service == "s3":
        return _extract_s3(params, partition)
    elif service == "dynamodb":
        return _extract_dynamodb(params, partition, region, account)
    elif service == "lambda":
        return _extract_lambda(params, partition, region, account)
    elif service == "sqs":
        return _extract_sqs(params, partition, region, account)

    return []


def _extract_s3(params: dict, partition: str) -> list[str]:
    """Extract S3 bucket and object ARNs."""
    arns = []
    bucket = None
    for key in _S3_PARAM_KEYS:
        if key in params:
            bucket = params[key]
            break
    if not bucket:
        return []

    bucket_arn = f"arn:{partition}:s3:::{bucket}"
    arns.append(bucket_arn)

    obj_key = params.get("key")
    if obj_key:
        arns.append(f"{bucket_arn}/{obj_key}")
    else:
        # Include wildcard for object-level access
        arns.append(f"{bucket_arn}/*")

    return arns


def _extract_dynamodb(
    params: dict, partition: str, region: str, account: str
) -> list[str]:
    """Extract DynamoDB table ARN."""
    for key in _DYNAMODB_PARAM_KEYS:
        if key in params:
            table_name = params[key]
            return [
                f"arn:{partition}:dynamodb:{region}:{account}:table/{table_name}"
            ]
    return []


def _extract_lambda(
    params: dict, partition: str, region: str, account: str
) -> list[str]:
    """Extract Lambda function ARN."""
    for key in _LAMBDA_PARAM_KEYS:
        if key in params:
            func_name = params[key]
            # If already an ARN, use as-is
            if func_name.startswith("arn:"):
                return [func_name]
            return [
                f"arn:{partition}:lambda:{region}:{account}:function:{func_name}"
            ]
    return []


def _extract_sqs(
    params: dict, partition: str, region: str, account: str
) -> list[str]:
    """Extract SQS queue ARN from queue URL."""
    for key in _SQS_PARAM_KEYS:
        if key in params:
            queue_url = params[key]
            # Queue URL format: https://sqs.{region}.amazonaws.com/{account}/{name}
            try:
                parts = queue_url.rstrip("/").split("/")
                queue_name = parts[-1]
                return [
                    f"arn:{partition}:sqs:{region}:{account}:{queue_name}"
                ]
            except (IndexError, AttributeError):
                pass
    return []
