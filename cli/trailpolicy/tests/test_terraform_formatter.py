"""Tests for Terraform output formatter."""

from trailpolicy.output.terraform_formatter import format_policy_terraform


def test_basic_statement():
    policy = {
        "Statement": [
            {
                "Sid": "S3Read",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::bucket/*"],
            }
        ]
    }
    result = format_policy_terraform(policy)
    assert 'data "aws_iam_policy_document" "generated"' in result
    assert "statement {" in result
    assert 'sid    = "S3Read"' in result
    assert 'effect = "Allow"' in result
    assert '"s3:GetObject",' in result
    assert '"arn:aws:s3:::bucket/*",' in result


def test_multiple_actions_sorted():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
                "Resource": ["*"],
            }
        ]
    }
    result = format_policy_terraform(policy)
    lines = result.split("\n")
    action_lines = [l.strip() for l in lines if "s3:" in l]
    # Actions should be sorted
    assert action_lines[0] == '"s3:DeleteObject",'
    assert action_lines[1] == '"s3:GetObject",'
    assert action_lines[2] == '"s3:PutObject",'


def test_condition_block():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:RequestedRegion": ["us-east-1", "us-west-2"]
                    }
                },
            }
        ]
    }
    result = format_policy_terraform(policy)
    assert "condition {" in result
    assert 'test     = "StringEquals"' in result
    assert 'variable = "aws:RequestedRegion"' in result
    assert '"us-east-1",' in result
    assert '"us-west-2",' in result


def test_string_action_and_resource():
    """Action/Resource as single strings instead of lists."""
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "ec2:DescribeInstances",
                "Resource": "*",
            }
        ]
    }
    result = format_policy_terraform(policy)
    assert '"ec2:DescribeInstances",' in result
    assert '"*",' in result


def test_empty_policy():
    policy = {"Statement": []}
    result = format_policy_terraform(policy)
    assert 'data "aws_iam_policy_document" "generated"' in result
    assert "statement {" not in result


def test_no_sid():
    policy = {
        "Statement": [
            {
                "Effect": "Deny",
                "Action": ["s3:*"],
                "Resource": ["*"],
            }
        ]
    }
    result = format_policy_terraform(policy)
    assert "sid" not in result
    assert 'effect = "Deny"' in result
