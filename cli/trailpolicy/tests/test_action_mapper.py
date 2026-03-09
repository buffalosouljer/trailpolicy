"""Tests for action_mapper module."""

from trailpolicy.core.action_mapper import ActionMapper


class TestActionMapper:
    def setup_method(self):
        self.mapper = ActionMapper()

    def test_standard_service_prefix(self):
        """Standard services strip .amazonaws.com."""
        assert self.mapper.resolve("ec2.amazonaws.com", "DescribeInstances") == "ec2:DescribeInstances"
        assert self.mapper.resolve("s3.amazonaws.com", "GetObject") == "s3:GetObject"
        assert self.mapper.resolve("iam.amazonaws.com", "CreateRole") == "iam:CreateRole"
        assert self.mapper.resolve("kms.amazonaws.com", "Decrypt") == "kms:Decrypt"

    def test_monitoring_override(self):
        """monitoring.amazonaws.com maps to cloudwatch, not monitoring."""
        result = self.mapper.resolve("monitoring.amazonaws.com", "DescribeAlarms")
        assert result == "cloudwatch:DescribeAlarms"

    def test_logs_override(self):
        """logs.amazonaws.com maps to logs."""
        result = self.mapper.resolve("logs.amazonaws.com", "PutLogEvents")
        assert result == "logs:PutLogEvents"

    def test_events_override(self):
        """events.amazonaws.com maps to events."""
        result = self.mapper.resolve("events.amazonaws.com", "PutRule")
        assert result == "events:PutRule"

    def test_ses_override(self):
        """email.amazonaws.com maps to ses."""
        result = self.mapper.resolve("email.amazonaws.com", "SendEmail")
        assert result == "ses:SendEmail"

    def test_tagging_override(self):
        """tagging.amazonaws.com maps to tag."""
        result = self.mapper.resolve("tagging.amazonaws.com", "GetResources")
        assert result == "tag:GetResources"

    def test_states_override(self):
        """states.amazonaws.com maps to states."""
        result = self.mapper.resolve("states.amazonaws.com", "StartExecution")
        assert result == "states:StartExecution"

    def test_lex_overrides(self):
        """Both lex eventSources map to lex prefix."""
        assert self.mapper.resolve("models.lex.amazonaws.com", "GetBot") == "lex:GetBot"
        assert self.mapper.resolve("runtime.lex.amazonaws.com", "PostText") == "lex:PostText"

    def test_event_source_to_prefix(self):
        """Test prefix extraction independently."""
        assert self.mapper.event_source_to_prefix("ec2.amazonaws.com") == "ec2"
        assert self.mapper.event_source_to_prefix("monitoring.amazonaws.com") == "cloudwatch"
        assert self.mapper.event_source_to_prefix("ce.amazonaws.com") == "ce"

    def test_preserves_event_name_casing(self):
        """Action name casing from CloudTrail should be preserved."""
        result = self.mapper.resolve("s3.amazonaws.com", "GetBucketAcl")
        assert result == "s3:GetBucketAcl"
