"""Tests for JSON output formatter."""

import json

from trailpolicy.output.json_formatter import format_policy_json


SAMPLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "S3Access",
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::my-bucket/*",
        }
    ],
}


def test_format_json_pretty():
    result = format_policy_json(SAMPLE_POLICY, pretty=True)
    parsed = json.loads(result)
    assert parsed == SAMPLE_POLICY
    assert "\n" in result  # Pretty-printed


def test_format_json_compact():
    result = format_policy_json(SAMPLE_POLICY, pretty=False)
    parsed = json.loads(result)
    assert parsed == SAMPLE_POLICY
    assert "\n" not in result


def test_format_json_with_policy_name():
    result = format_policy_json(SAMPLE_POLICY, policy_name="MyPolicy")
    parsed = json.loads(result)
    assert parsed["PolicyName"] == "MyPolicy"
    assert parsed["PolicyDocument"] == SAMPLE_POLICY


def test_format_json_without_policy_name():
    result = format_policy_json(SAMPLE_POLICY)
    parsed = json.loads(result)
    assert "PolicyName" not in parsed
    assert parsed == SAMPLE_POLICY


def test_format_json_empty_policy():
    empty = {"Version": "2012-10-17", "Statement": []}
    result = format_policy_json(empty)
    parsed = json.loads(result)
    assert parsed["Statement"] == []
