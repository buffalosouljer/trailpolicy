"""Tests for diff reporter."""

from trailpolicy.output.diff_reporter import DiffResult, format_diff_text, _extract_actions


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
