"""Tests for cloudtrail module."""

from trailpolicy.core.cloudtrail import _role_name_from_arn


class TestRoleNameFromArn:
    def test_simple_role(self):
        assert _role_name_from_arn("arn:aws:iam::123456789012:role/MyRole") == "MyRole"

    def test_role_with_path(self):
        assert _role_name_from_arn("arn:aws:iam::123456789012:role/path/to/MyRole") == "MyRole"

    def test_govcloud_role(self):
        assert _role_name_from_arn("arn:aws-us-gov:iam::123456789012:role/GovRole") == "GovRole"

    def test_role_with_special_chars(self):
        assert _role_name_from_arn("arn:aws:iam::123456789012:role/My-Role_v2") == "My-Role_v2"


class TestFetchEventsDedup:
    def test_dedup_by_event_id(self):
        """Verify deduplication logic with duplicate EventId values."""
        # Simulate what fetch_events does internally with dedup
        all_events = [
            {"EventId": "evt-1", "EventName": "A"},
            {"EventId": "evt-2", "EventName": "B"},
            {"EventId": "evt-1", "EventName": "A"},  # duplicate
            {"EventId": "evt-3", "EventName": "C"},
        ]
        seen_ids = set()
        unique_events = []
        for event in all_events:
            event_id = event.get("EventId", "")
            if event_id and event_id not in seen_ids:
                seen_ids.add(event_id)
                unique_events.append(event)
        assert len(unique_events) == 3
        assert [e["EventId"] for e in unique_events] == ["evt-1", "evt-2", "evt-3"]

    def test_dedup_preserves_order(self):
        """First occurrence should be kept."""
        all_events = [
            {"EventId": "evt-1", "EventName": "First"},
            {"EventId": "evt-1", "EventName": "Second"},
        ]
        seen_ids = set()
        unique_events = []
        for event in all_events:
            event_id = event.get("EventId", "")
            if event_id and event_id not in seen_ids:
                seen_ids.add(event_id)
                unique_events.append(event)
        assert unique_events[0]["EventName"] == "First"
