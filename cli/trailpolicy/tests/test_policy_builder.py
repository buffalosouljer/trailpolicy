"""Tests for policy_builder module."""

import json

from trailpolicy.core.event_parser import ParsedEvent
from trailpolicy.core.policy_builder import (
    build_policy,
    PolicyMetadata,
    _compress_policy,
    _find_common_prefixes,
)


def _make_event(service: str, action: str, resources: list[str] | None = None) -> ParsedEvent:
    """Helper to create a ParsedEvent with iam_action pre-set."""
    return ParsedEvent(
        event_source=f"{service}.amazonaws.com",
        event_name=action,
        iam_action=f"{service}:{action}",
        resources=resources or ["*"],
    )


class TestBuildPolicy:
    def test_empty_events(self):
        """No events should produce an empty policy with a warning."""
        policy, meta = build_policy([])
        assert policy["Version"] == "2012-10-17"
        assert policy["Statement"] == []
        assert any("empty" in w.lower() for w in meta.warnings)

    def test_single_action(self):
        """Single action produces one statement."""
        events = [_make_event("s3", "GetObject", ["arn:aws:s3:::bucket/*"])]
        policy, meta = build_policy(events)
        assert len(policy["Statement"]) == 1
        stmt = policy["Statement"][0]
        assert stmt["Effect"] == "Allow"
        assert "s3:GetObject" in (stmt["Action"] if isinstance(stmt["Action"], list) else [stmt["Action"]])

    def test_groups_actions_by_resource_set(self):
        """Actions with identical resources go in the same statement."""
        events = [
            _make_event("s3", "GetObject", ["arn:aws:s3:::bucket/*"]),
            _make_event("s3", "PutObject", ["arn:aws:s3:::bucket/*"]),
        ]
        policy, meta = build_policy(events)
        # Both S3 actions share the same resource, should be grouped
        s3_stmts = [
            s for s in policy["Statement"]
            if "s3:" in str(s["Action"])
        ]
        assert len(s3_stmts) == 1
        actions = s3_stmts[0]["Action"]
        if isinstance(actions, str):
            actions = [actions]
        assert "s3:GetObject" in actions
        assert "s3:PutObject" in actions

    def test_separates_different_resource_sets(self):
        """Actions with different resources go in separate statements."""
        events = [
            _make_event("s3", "GetObject", ["arn:aws:s3:::bucket-a/*"]),
            _make_event("s3", "PutObject", ["arn:aws:s3:::bucket-b/*"]),
        ]
        policy, meta = build_policy(events)
        assert len(policy["Statement"]) == 2

    def test_wildcard_actions_tracked(self):
        """Actions with Resource: * are noted in metadata."""
        events = [_make_event("ec2", "DescribeInstances")]
        policy, meta = build_policy(events)
        assert "ec2:DescribeInstances" in meta.wildcard_actions

    def test_sid_generation(self):
        """Statements should have Sid labels."""
        events = [
            _make_event("ec2", "DescribeInstances"),
            _make_event("s3", "GetObject", ["arn:aws:s3:::bucket/*"]),
        ]
        policy, meta = build_policy(events)
        sids = [s["Sid"] for s in policy["Statement"]]
        assert len(sids) == 2
        assert all(sids)  # All non-empty
        assert len(set(sids)) == 2  # All unique

    def test_statements_sorted_by_sid(self):
        """Statements should be sorted alphabetically by Sid."""
        events = [
            _make_event("s3", "GetObject", ["arn:aws:s3:::b/*"]),
            _make_event("ec2", "DescribeInstances"),
            _make_event("iam", "CreateRole", ["arn:aws:iam::123:role/R"]),
        ]
        policy, meta = build_policy(events)
        sids = [s["Sid"] for s in policy["Statement"]]
        assert sids == sorted(sids)

    def test_pass_role_warning(self):
        """Metadata should always include iam:PassRole warning."""
        events = [_make_event("s3", "GetObject", ["arn:aws:s3:::b/*"])]
        policy, meta = build_policy(events)
        assert any("PassRole" in w for w in meta.warnings)

    def test_advisor_only_services(self):
        """Services in Access Advisor but not CloudTrail should be flagged."""
        events = [_make_event("s3", "GetObject", ["arn:aws:s3:::b/*"])]
        policy, meta = build_policy(events, advisor_services=["s3", "dynamodb", "lambda"])
        assert "dynamodb" in meta.advisor_only_services
        assert "lambda" in meta.advisor_only_services
        assert "s3" not in meta.advisor_only_services

    def test_policy_is_valid_json(self):
        """Generated policy should be valid JSON with correct structure."""
        events = [
            _make_event("ec2", "DescribeInstances"),
            _make_event("s3", "GetObject", ["arn:aws:s3:::bucket/*"]),
            _make_event("kms", "Decrypt", ["arn:aws:kms:us-east-1:123:key/abc"]),
        ]
        policy, meta = build_policy(events)
        # Should be serializable
        policy_json = json.dumps(policy, indent=2)
        reparsed = json.loads(policy_json)
        assert reparsed["Version"] == "2012-10-17"
        assert len(reparsed["Statement"]) > 0

    def test_metadata_stats(self):
        """Metadata should contain correct stats."""
        events = [
            _make_event("s3", "GetObject", ["arn:aws:s3:::b/*"]),
            _make_event("s3", "PutObject", ["arn:aws:s3:::b/*"]),
            _make_event("ec2", "DescribeInstances"),
        ]
        policy, meta = build_policy(events)
        assert meta.total_actions == 3
        assert meta.total_services == 2
        assert meta.policy_size > 0

    def test_deduplicates_actions(self):
        """Duplicate actions across events should be deduplicated."""
        events = [
            _make_event("s3", "GetObject", ["arn:aws:s3:::b/*"]),
            _make_event("s3", "GetObject", ["arn:aws:s3:::b/*"]),
        ]
        policy, meta = build_policy(events)
        assert meta.total_actions == 1

    def test_empty_events_no_passrole_warning(self):
        """Empty-policy early-return should not emit the PassRole warning."""
        policy, meta = build_policy([])
        assert not any("PassRole" in w for w in meta.warnings)


class TestCompressPolicy:
    def test_compresses_many_actions(self):
        """When >5 actions share a service, they should be compressed."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "S3Access",
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:GetBucketAcl",
                        "s3:GetBucketPolicy",
                        "s3:GetBucketLocation",
                        "s3:GetObjectVersion",
                        "s3:GetObjectAcl",
                        "s3:PutObject",
                        "s3:PutBucketPolicy",
                    ],
                    "Resource": "*",
                }
            ],
        }
        compressed, size, wildcards = _compress_policy(policy)
        actions = compressed["Statement"][0]["Action"]
        if isinstance(actions, str):
            actions = [actions]
        # Get* should be compressed to Get* since there are 5 Get actions
        assert any("*" in a for a in actions)
        assert len(wildcards) > 0

    def test_compress_returns_introduced_wildcards(self):
        """Wildcards list should contain the exact patterns introduced."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:GetBucketAcl",
                        "s3:GetBucketPolicy",
                        "s3:GetBucketLocation",
                        "s3:GetObjectVersion",
                        "s3:GetObjectAcl",
                    ],
                    "Resource": "*",
                }
            ],
        }
        _, _, wildcards = _compress_policy(policy)
        assert "s3:Get*" in wildcards

    def test_no_compress_few_actions(self):
        """Fewer than 6 actions should not be compressed."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "*",
                }
            ],
        }
        compressed, size, wildcards = _compress_policy(policy)
        actions = compressed["Statement"][0]["Action"]
        if isinstance(actions, str):
            actions = [actions]
        assert not any("*" in a for a in actions)
        assert len(wildcards) == 0


class TestFindCommonPrefixes:
    def test_groups_get_prefix(self):
        names = ["GetObject", "GetBucketAcl", "GetBucketPolicy"]
        result = _find_common_prefixes(names)
        assert result == ["Get"]

    def test_no_group_small_count(self):
        names = ["GetObject", "PutObject"]
        result = _find_common_prefixes(names)
        assert sorted(result) == sorted(["GetObject", "PutObject"])
