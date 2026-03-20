"""Tests for diff reporter."""

import json

import boto3
import pytest
from moto import mock_aws

from trailpolicy.output.diff_reporter import (
    DiffResult,
    compute_diff,
    format_diff_text,
    _extract_actions,
)


def test_extract_actions_allow():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "*",
            }
        ]
    }
    actions = _extract_actions(policy)
    assert actions == {"s3:GetObject", "s3:PutObject"}


def test_extract_actions_deny_skipped():
    policy = {
        "Statement": [
            {
                "Effect": "Deny",
                "Action": ["s3:DeleteBucket"],
                "Resource": "*",
            }
        ]
    }
    actions = _extract_actions(policy)
    assert actions == set()


def test_extract_actions_string_action():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "ec2:DescribeInstances",
                "Resource": "*",
            }
        ]
    }
    actions = _extract_actions(policy)
    assert actions == {"ec2:DescribeInstances"}


def test_extract_actions_mixed_effects():
    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"},
            {"Effect": "Deny", "Action": ["s3:DeleteBucket"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["ec2:RunInstances"], "Resource": "*"},
        ]
    }
    actions = _extract_actions(policy)
    assert actions == {"s3:GetObject", "ec2:RunInstances"}


def test_format_diff_text_all_matched():
    diff = DiffResult(
        matched=["s3:GetObject", "s3:PutObject"],
        unused=[],
        missing=[],
        current_action_count=2,
        observed_action_count=2,
        coverage_pct=100,
    )
    text = format_diff_text(diff)
    assert "MATCHED:" in text
    assert "UNUSED:" not in text.split("SUMMARY")[0]
    assert "0 actions are UNUSED" in text


def test_format_diff_text_with_unused():
    diff = DiffResult(
        matched=["s3:GetObject"],
        unused=["s3:PutObject", "s3:DeleteObject"],
        missing=[],
        current_action_count=3,
        observed_action_count=1,
        coverage_pct=33,
    )
    text = format_diff_text(diff)
    assert "UNUSED:" in text
    assert "2 actions are UNUSED" in text


def test_format_diff_text_with_missing():
    diff = DiffResult(
        matched=["s3:GetObject"],
        unused=[],
        missing=["ec2:RunInstances"],
        current_action_count=1,
        observed_action_count=2,
        coverage_pct=100,
    )
    text = format_diff_text(diff)
    assert "MISSING:" in text
    assert "1 actions are MISSING" in text


def test_format_diff_text_groups_by_service():
    diff = DiffResult(
        matched=["s3:GetObject", "ec2:DescribeInstances"],
        unused=["s3:PutObject"],
        missing=["lambda:InvokeFunction"],
        current_action_count=3,
        observed_action_count=3,
        coverage_pct=67,
    )
    text = format_diff_text(diff)
    # Should have sections for ec2, lambda, s3
    assert "[ec2]" in text
    assert "[lambda]" in text
    assert "[s3]" in text


def test_format_diff_text_passrole_note():
    diff = DiffResult()
    text = format_diff_text(diff)
    assert "iam:PassRole" in text
    assert "not tracked by CloudTrail" in text


def test_extract_actions_not_action_logged():
    """NotAction statements should not crash; they are logged as warnings."""
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "NotAction": ["iam:*"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "*",
            },
        ]
    }
    actions = _extract_actions(policy)
    # NotAction doesn't contribute explicit actions but shouldn't crash
    assert "s3:GetObject" in actions
    # iam:* should NOT be in the set (it's excluded, not included)
    assert "iam:*" not in actions


def test_extract_actions_empty_statement():
    """Statement with no Action or NotAction should be handled gracefully."""
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Resource": "*",
            }
        ]
    }
    actions = _extract_actions(policy)
    assert actions == set()


def test_format_diff_text_summary_section():
    diff = DiffResult(
        matched=["a:B", "c:D"],
        unused=["e:F"],
        missing=["g:H", "i:J", "k:L"],
    )
    text = format_diff_text(diff)
    assert "--- SUMMARY ---" in text
    assert "1 actions are UNUSED" in text
    assert "3 actions are MISSING" in text
    assert "2 actions MATCHED" in text


# --- compute_diff integration tests using moto ---


def _create_role_with_inline_policy(iam, role_name, policy_name, actions):
    """Helper: create an IAM role with an inline policy."""
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }),
        Path="/",
    )
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}],
        }),
    )


@mock_aws
def test_compute_diff_matched_and_unused():
    """compute_diff identifies matched and unused actions via real IAM mock."""
    iam = boto3.client("iam", region_name="us-east-1")
    _create_role_with_inline_policy(
        iam, "TestRole", "TestPolicy",
        ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
    )

    generated_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*"}
        ],
    }

    result = compute_diff(
        "arn:aws:iam::123456789012:role/TestRole",
        generated_policy,
        region="us-east-1",
    )

    assert sorted(result.matched) == ["s3:GetObject", "s3:PutObject"]
    assert result.unused == ["s3:DeleteObject"]
    assert result.missing == []
    assert result.current_action_count == 3
    assert result.observed_action_count == 2
    assert result.coverage_pct == 66  # 2/3


@mock_aws
def test_compute_diff_with_missing():
    """compute_diff identifies actions in generated but not in current policy."""
    iam = boto3.client("iam", region_name="us-east-1")
    _create_role_with_inline_policy(
        iam, "TestRole", "TestPolicy",
        ["s3:GetObject"],
    )

    generated_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "ec2:DescribeInstances"], "Resource": "*"}
        ],
    }

    result = compute_diff(
        "arn:aws:iam::123456789012:role/TestRole",
        generated_policy,
        region="us-east-1",
    )

    assert result.matched == ["s3:GetObject"]
    assert result.unused == []
    assert result.missing == ["ec2:DescribeInstances"]


@mock_aws
def test_compute_diff_zero_current_actions():
    """compute_diff handles a role with no policies (zero-division guard)."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(
        RoleName="EmptyRole",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }),
        Path="/",
    )

    generated_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        ],
    }

    result = compute_diff(
        "arn:aws:iam::123456789012:role/EmptyRole",
        generated_policy,
        region="us-east-1",
    )

    assert result.matched == []
    assert result.unused == []
    assert result.missing == ["s3:GetObject"]
    assert result.coverage_pct == 0
    assert result.current_action_count == 0


@mock_aws
def test_compute_diff_with_managed_policy():
    """compute_diff reads actions from managed (customer) policies."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(
        RoleName="ManagedRole",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }),
        Path="/",
    )

    policy_resp = iam.create_policy(
        PolicyName="TestManagedPolicy",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["kms:Decrypt", "kms:DescribeKey"], "Resource": "*"}],
        }),
    )
    iam.attach_role_policy(
        RoleName="ManagedRole",
        PolicyArn=policy_resp["Policy"]["Arn"],
    )

    generated_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"}
        ],
    }

    result = compute_diff(
        "arn:aws:iam::123456789012:role/ManagedRole",
        generated_policy,
        region="us-east-1",
    )

    assert "kms:Decrypt" in result.matched
    assert "kms:DescribeKey" in result.unused
