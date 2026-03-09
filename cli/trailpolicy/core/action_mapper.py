"""Map CloudTrail eventSource + eventName to IAM actions."""

from __future__ import annotations

import json
from importlib import resources as pkg_resources
from pathlib import Path


class ActionMapper:
    """Resolves CloudTrail events to IAM action strings."""

    def __init__(self) -> None:
        self._overrides = self._load_overrides()

    @staticmethod
    def _load_overrides() -> dict[str, str]:
        """Load eventSource → IAM service prefix overrides."""
        data_path = Path(__file__).parent.parent / "data" / "ct_iam_overrides.json"
        with open(data_path) as f:
            return json.load(f)

    def event_source_to_prefix(self, event_source: str) -> str:
        """Convert CloudTrail eventSource to IAM service prefix.

        General rule: strip '.amazonaws.com' from eventSource.
        Override map handles known mismatches.
        """
        if event_source in self._overrides:
            return self._overrides[event_source]
        return event_source.replace(".amazonaws.com", "")

    def resolve(self, event_source: str, event_name: str) -> str:
        """Return the full IAM action string (e.g., 's3:GetObject')."""
        prefix = self.event_source_to_prefix(event_source)
        return f"{prefix}:{event_name}"
