"""Tests for the Click CLI commands."""

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from trailpolicy.cli import main


# Sample data for mocking
SAMPLE_RAW_EVENTS = [
    {
        "CloudTrailEvent": json.dumps(
            {
                "eventSource": "s3.amazonaws.com",
                "eventName": "GetObject",
                "requestParameters": {"bucketName": "my-bucket", "key": "data.csv"},
                "awsRegion": "us-east-1",
                "recipientAccountId": "123456789012",
                "eventTime": "2025-01-01T00:00:00Z",
                "readOnly": True,
            }
        ),
        "EventId": "event-1",
    },
    {
        "CloudTrailEvent": json.dumps(
            {
                "eventSource": "ec2.amazonaws.com",
                "eventName": "DescribeInstances",
                "requestParameters": {},
                "awsRegion": "us-east-1",
                "recipientAccountId": "123456789012",
                "eventTime": "2025-01-01T01:00:00Z",
                "readOnly": True,
            }
        ),
        "EventId": "event-2",
    },
]

ROLE_ARN = "arn:aws:iam::123456789012:role/TestRole"


class TestGenerate:
    """Tests for the generate command."""

    @patch("trailpolicy.cli.detect_partition", return_value="aws")
    @patch("trailpolicy.cli.fetch_events", return_value=SAMPLE_RAW_EVENTS)
    def test_generate_json_output(self, mock_fetch, mock_partition):
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(
            main, ["generate", "--role-arn", ROLE_ARN, "--no-advisor"]
        )
        assert result.exit_code == 0
        # stdout should contain valid JSON policy
        output = result.output
        policy = json.loads(output)
        assert "Version" in policy
        assert "Statement" in policy

    @patch("trailpolicy.cli.detect_partition", return_value="aws")
    @patch("trailpolicy.cli.fetch_events", return_value=SAMPLE_RAW_EVENTS)
    def test_generate_terraform_output(self, mock_fetch, mock_partition):
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["generate", "--role-arn", ROLE_ARN, "--no-advisor", "-f", "tf"],
        )
        assert result.exit_code == 0
        assert 'data "aws_iam_policy_document"' in result.output

    @patch("trailpolicy.cli.detect_partition", return_value="aws")
    @patch("trailpolicy.cli.fetch_events", return_value=SAMPLE_RAW_EVENTS)
    def test_generate_output_file(self, mock_fetch, mock_partition):
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            outpath = f.name
        try:
            result = runner.invoke(
                main,
                [
                    "generate",
                    "--role-arn",
                    ROLE_ARN,
                    "--no-advisor",
                    "-o",
                    outpath,
                ],
            )
            assert result.exit_code == 0
            content = open(outpath).read()
            policy = json.loads(content)
            assert "Statement" in policy
        finally:
            os.unlink(outpath)

    @patch("trailpolicy.cli.detect_partition", return_value="aws")
    @patch("trailpolicy.cli.fetch_events", return_value=[])
    def test_generate_no_events_exits(self, mock_fetch, mock_partition):
        runner = CliRunner()
        result = runner.invoke(
            main, ["generate", "--role-arn", ROLE_ARN, "--no-advisor"]
        )
        assert result.exit_code == 1

    def test_generate_missing_role_arn(self):
        runner = CliRunner()
        result = runner.invoke(main, ["generate"])
        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()

    def test_generate_invalid_days(self):
        runner = CliRunner()
        result = runner.invoke(
            main, ["generate", "--role-arn", ROLE_ARN, "--days", "200"]
        )
        assert result.exit_code != 0

    @patch("trailpolicy.cli.detect_partition", return_value="aws")
    @patch("trailpolicy.cli.fetch_events", return_value=SAMPLE_RAW_EVENTS)
    def test_generate_verbose(self, mock_fetch, mock_partition):
        runner = CliRunner()
        result = runner.invoke(
            main, ["generate", "--role-arn", ROLE_ARN, "--no-advisor", "-v"]
        )
        assert result.exit_code == 0

    def test_generate_athena_without_options(self):
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "generate",
                "--role-arn",
                ROLE_ARN,
                "--source",
                "athena",
                "--no-advisor",
            ],
        )
        assert result.exit_code != 0


class TestValidate:
    """Tests for the validate command."""

    def test_validate_valid_policy(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                }
            ],
        }
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(policy, f)
            f.flush()
            fpath = f.name
        try:
            result = runner.invoke(main, ["validate", "--policy-file", fpath])
            assert result.exit_code == 0
            assert "valid" in result.output.lower()
        finally:
            os.unlink(fpath)

    def test_validate_invalid_json(self):
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            f.write("not json{{{")
            f.flush()
            fpath = f.name
        try:
            result = runner.invoke(main, ["validate", "--policy-file", fpath])
            assert result.exit_code == 1
        finally:
            os.unlink(fpath)

    def test_validate_missing_statement(self):
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump({"Version": "2012-10-17"}, f)
            f.flush()
            fpath = f.name
        try:
            result = runner.invoke(main, ["validate", "--policy-file", fpath])
            assert result.exit_code == 1
        finally:
            os.unlink(fpath)

    def test_validate_policy_document_envelope(self):
        """Validates a file wrapped in PolicyDocument envelope."""
        policy = {
            "PolicyName": "MyPolicy",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "*",
                    }
                ],
            },
        }
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(policy, f)
            f.flush()
            fpath = f.name
        try:
            result = runner.invoke(main, ["validate", "--policy-file", fpath])
            assert result.exit_code == 0
        finally:
            os.unlink(fpath)

    def test_validate_bad_action_format(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "NoColonHere",
                    "Resource": "*",
                }
            ],
        }
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(policy, f)
            f.flush()
            fpath = f.name
        try:
            result = runner.invoke(main, ["validate", "--policy-file", fpath])
            assert result.exit_code == 1
            assert "missing ':'" in result.output.lower() or "missing" in result.output.lower()
        finally:
            os.unlink(fpath)

    def test_validate_missing_effect(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "s3:GetObject",
                    "Resource": "*",
                }
            ],
        }
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(policy, f)
            f.flush()
            fpath = f.name
        try:
            result = runner.invoke(main, ["validate", "--policy-file", fpath])
            assert result.exit_code == 1
        finally:
            os.unlink(fpath)


class TestDiff:
    """Tests for the diff command."""

    @patch("trailpolicy.cli.compute_diff")
    @patch("trailpolicy.cli.detect_partition", return_value="aws")
    @patch("trailpolicy.cli.fetch_events", return_value=SAMPLE_RAW_EVENTS)
    def test_diff_happy_path(self, mock_fetch, mock_partition, mock_diff):
        from trailpolicy.output.diff_reporter import DiffResult

        mock_diff.return_value = DiffResult(
            matched=["s3:GetObject"],
            unused=["s3:PutObject"],
            missing=["ec2:DescribeInstances"],
            current_action_count=2,
            observed_action_count=2,
            coverage_pct=50,
        )
        runner = CliRunner()
        result = runner.invoke(
            main, ["diff", "--role-arn", ROLE_ARN]
        )
        assert result.exit_code == 0
        assert "MATCHED" in result.output or "UNUSED" in result.output

    @patch("trailpolicy.cli.detect_partition", return_value="aws")
    @patch("trailpolicy.cli.fetch_events", return_value=[])
    def test_diff_no_events_exits(self, mock_fetch, mock_partition):
        runner = CliRunner()
        result = runner.invoke(
            main, ["diff", "--role-arn", ROLE_ARN]
        )
        assert result.exit_code == 1

    def test_diff_missing_role_arn(self):
        runner = CliRunner()
        result = runner.invoke(main, ["diff"])
        assert result.exit_code != 0


class TestVersionAndHelp:
    """Tests for --version and --help flags."""

    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "generate" in result.output
        assert "diff" in result.output
        assert "validate" in result.output

    def test_generate_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["generate", "--help"])
        assert result.exit_code == 0
        assert "--role-arn" in result.output
        assert "--days" in result.output
