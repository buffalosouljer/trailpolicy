"""Tests for athena module — input validation only (no AWS calls)."""

import pytest

from trailpolicy.core.athena import _validate_athena_inputs


class TestValidateAthenaInputs:
    def test_valid_inputs(self):
        """Valid inputs should not raise."""
        _validate_athena_inputs(
            role_arn="arn:aws:iam::123456789012:role/MyRole",
            database="my_database",
            table="cloudtrail_logs",
            start_date="2026-01-01",
            end_date="2026-03-01",
        )

    def test_invalid_role_arn(self):
        with pytest.raises(ValueError, match="Invalid role ARN"):
            _validate_athena_inputs(
                role_arn="') OR '1'='1",
                database="db",
                table="tbl",
                start_date="2026-01-01",
                end_date="2026-03-01",
            )

    def test_invalid_database_name(self):
        with pytest.raises(ValueError, match="Invalid database name"):
            _validate_athena_inputs(
                role_arn="arn:aws:iam::123456789012:role/MyRole",
                database="db; DROP TABLE",
                table="tbl",
                start_date="2026-01-01",
                end_date="2026-03-01",
            )

    def test_invalid_table_name(self):
        with pytest.raises(ValueError, match="Invalid table name"):
            _validate_athena_inputs(
                role_arn="arn:aws:iam::123456789012:role/MyRole",
                database="db",
                table="tbl' --",
                start_date="2026-01-01",
                end_date="2026-03-01",
            )

    def test_invalid_start_date(self):
        with pytest.raises(ValueError, match="Invalid start_date"):
            _validate_athena_inputs(
                role_arn="arn:aws:iam::123456789012:role/MyRole",
                database="db",
                table="tbl",
                start_date="not-a-date",
                end_date="2026-03-01",
            )

    def test_invalid_end_date(self):
        with pytest.raises(ValueError, match="Invalid end_date"):
            _validate_athena_inputs(
                role_arn="arn:aws:iam::123456789012:role/MyRole",
                database="db",
                table="tbl",
                start_date="2026-01-01",
                end_date="March 1st",
            )

    def test_govcloud_role_arn(self):
        """GovCloud ARNs should be accepted."""
        _validate_athena_inputs(
            role_arn="arn:aws-us-gov:iam::123456789012:role/GovRole",
            database="db",
            table="tbl",
            start_date="2026-01-01",
            end_date="2026-03-01",
        )

    def test_role_arn_with_path(self):
        """Role ARNs with path components should be accepted."""
        _validate_athena_inputs(
            role_arn="arn:aws:iam::123456789012:role/path/to/MyRole",
            database="db",
            table="tbl",
            start_date="2026-01-01",
            end_date="2026-03-01",
        )
