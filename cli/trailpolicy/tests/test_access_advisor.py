"""Tests for access_advisor module — result parsing only (no AWS calls)."""

from datetime import datetime
from trailpolicy.core.access_advisor import ServiceAccess


class TestServiceAccessDataclass:
    def test_service_with_last_accessed(self):
        sa = ServiceAccess(
            service_name="Amazon S3",
            service_namespace="s3",
            last_accessed=datetime(2026, 1, 15),
            total_entities=3,
        )
        assert sa.service_namespace == "s3"
        assert sa.last_accessed is not None
        assert sa.total_entities == 3

    def test_service_without_last_accessed(self):
        sa = ServiceAccess(
            service_name="AWS CloudFormation",
            service_namespace="cloudformation",
            last_accessed=None,
        )
        assert sa.last_accessed is None
        assert sa.total_entities == 0

    def test_filter_accessed_services(self):
        """Verify the filtering pattern used in get_last_accessed."""
        services = [
            ServiceAccess("S3", "s3", datetime(2026, 1, 1)),
            ServiceAccess("EC2", "ec2", None),
            ServiceAccess("IAM", "iam", datetime(2026, 2, 1)),
        ]
        accessed = [s for s in services if s.last_accessed is not None]
        assert len(accessed) == 2
        assert {s.service_namespace for s in accessed} == {"s3", "iam"}
