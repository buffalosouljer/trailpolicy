"""Tests for event_parser module."""

import json
from pathlib import Path

from trailpolicy.core.event_parser import ParsedEvent, parse_events, _is_same_role

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load_sample_events() -> list[dict]:
    with open(FIXTURES_DIR / "sample_events.json") as f:
        return json.load(f)


class TestParseEvents:
    def test_filters_error_events(self):
        """Events with errorCode should be filtered out."""
        events = _load_sample_events()
        parsed = parse_events(events)
        # event-011 has AccessDenied, should be filtered
        error_events = [e for e in parsed if e.error_code is not None]
        assert len(error_events) == 0
        # We started with 11, one has error, one is self-AssumeRole
        assert len(parsed) == 9

    def test_filters_self_assume_role(self):
        """sts:AssumeRole where principal is the role itself should be filtered."""
        events = _load_sample_events()
        parsed = parse_events(events)
        assume_events = [
            e for e in parsed
            if e.event_source == "sts.amazonaws.com" and e.event_name == "AssumeRole"
        ]
        assert len(assume_events) == 0

    def test_parses_event_fields(self):
        """Verify key fields are extracted correctly."""
        events = _load_sample_events()
        parsed = parse_events(events)
        # Find the EC2 DescribeInstances event
        ec2_events = [e for e in parsed if e.event_name == "DescribeInstances"]
        assert len(ec2_events) == 1
        event = ec2_events[0]
        assert event.event_source == "ec2.amazonaws.com"
        assert event.read_only is True
        assert event.aws_region == "us-east-1"
        assert event.account_id == "123456789012"
        assert event.event_time is not None

    def test_extracts_resource_arns(self):
        """Resources from the resources[] array should be extracted."""
        events = _load_sample_events()
        parsed = parse_events(events)
        # IAM CreateRole has resources[] with an ARN
        iam_events = [e for e in parsed if e.event_name == "CreateRole"]
        assert len(iam_events) == 1
        assert "arn:aws:iam::123456789012:role/NewRole" in iam_events[0].resources

    def test_kms_event_has_resource(self):
        """KMS Decrypt event should have key ARN from resources[]."""
        events = _load_sample_events()
        parsed = parse_events(events)
        kms_events = [e for e in parsed if e.event_name == "Decrypt"]
        assert len(kms_events) == 1
        assert any("kms" in r for r in kms_events[0].resources)

    def test_parses_request_parameters(self):
        """S3 events should have request_parameters with bucketName."""
        events = _load_sample_events()
        parsed = parse_events(events)
        s3_get = [e for e in parsed if e.event_name == "GetObject"]
        assert len(s3_get) == 1  # one filtered by error
        assert s3_get[0].request_parameters is not None
        assert s3_get[0].request_parameters.get("bucketName") == "my-app-bucket"


    def test_cross_role_assume_kept(self):
        """AssumeRole for a DIFFERENT role should not be filtered."""
        raw_event = {
            "eventSource": "sts.amazonaws.com",
            "eventName": "AssumeRole",
            "awsRegion": "us-east-1",
            "recipientAccountId": "123456789012",
            "userIdentity": {
                "arn": "arn:aws:sts::123456789012:assumed-role/SourceRole/session",
                "accountId": "123456789012",
            },
            "requestParameters": {
                "roleArn": "arn:aws:iam::123456789012:role/TargetRole",
                "roleSessionName": "session",
            },
        }
        parsed = parse_events([raw_event])
        assert len(parsed) == 1
        assert parsed[0].event_name == "AssumeRole"

    def test_raw_dict_event_parsing(self):
        """Events without CloudTrailEvent wrapper (Athena format) should parse."""
        raw_event = {
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "awsRegion": "us-east-1",
            "recipientAccountId": "123456789012",
            "requestParameters": {"bucketName": "test-bucket", "key": "file.txt"},
            "readOnly": "true",
            "eventTime": "2026-03-01T10:00:00Z",
        }
        parsed = parse_events([raw_event])
        assert len(parsed) == 1
        assert parsed[0].event_source == "s3.amazonaws.com"
        assert parsed[0].event_name == "GetObject"
        assert parsed[0].request_parameters["bucketName"] == "test-bucket"
        assert parsed[0].read_only is True

    def test_request_parameters_as_json_string(self):
        """requestParameters that is a JSON string should be parsed to dict."""
        raw_event = {
            "eventSource": "s3.amazonaws.com",
            "eventName": "ListBuckets",
            "awsRegion": "us-east-1",
            "recipientAccountId": "123456789012",
            "requestParameters": '{"bucketName": "my-bucket"}',
        }
        parsed = parse_events([raw_event])
        assert len(parsed) == 1
        assert isinstance(parsed[0].request_parameters, dict)
        assert parsed[0].request_parameters["bucketName"] == "my-bucket"


class TestIsSameRole:
    def test_same_role_assumed(self):
        assert _is_same_role(
            "arn:aws:sts::123456789012:assumed-role/MyRole/session",
            "arn:aws:iam::123456789012:role/MyRole",
        )

    def test_different_roles(self):
        assert not _is_same_role(
            "arn:aws:sts::123456789012:assumed-role/OtherRole/session",
            "arn:aws:iam::123456789012:role/MyRole",
        )

    def test_role_with_path(self):
        assert _is_same_role(
            "arn:aws:sts::123456789012:assumed-role/MyRole/session",
            "arn:aws:iam::123456789012:role/path/MyRole",
        )
