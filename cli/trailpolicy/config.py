"""Partition & endpoint configuration for trailpolicy."""

from __future__ import annotations

import boto3
from botocore.config import Config

# Constants
MAX_LOOKBACK_DAYS = 90
MAX_POLICY_SIZE = 10240
LOOKUP_EVENTS_PAGE_SIZE = 50
LOOKUP_EVENTS_TPS = 2

# Partition mapping
REGION_PARTITION_MAP = {
    "us-gov-west-1": "aws-us-gov",
    "us-gov-east-1": "aws-us-gov",
    "cn-north-1": "aws-cn",
    "cn-northwest-1": "aws-cn",
}

BOTO_CONFIG = Config(
    retries={"max_attempts": 10, "mode": "adaptive"},
    connect_timeout=5,
    read_timeout=30,
)


def detect_partition(region: str | None = None) -> str:
    """Detect AWS partition from region or STS GetCallerIdentity."""
    if region and region in REGION_PARTITION_MAP:
        return REGION_PARTITION_MAP[region]

    if region:
        # Default to commercial for standard regions
        return "aws"

    # Auto-detect from credentials
    sts = boto3.client("sts", config=BOTO_CONFIG)
    identity = sts.get_caller_identity()
    arn = identity["Arn"]
    # ARN format: arn:{partition}:iam::...
    return arn.split(":")[1]


def get_boto_session(region: str | None = None) -> boto3.Session:
    """Create a boto3 session for the given region."""
    return boto3.Session(region_name=region)


def get_boto_config() -> Config:
    """Return the standard botocore config with adaptive retries."""
    return BOTO_CONFIG
