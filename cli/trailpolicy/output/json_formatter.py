"""Format IAM policies as JSON output."""

from __future__ import annotations

import json


def format_policy_json(
    policy: dict,
    policy_name: str | None = None,
    pretty: bool = True,
) -> str:
    """Format a policy document as JSON.

    Args:
        policy: IAM policy document dict.
        policy_name: Optional name to wrap in a PolicyName/PolicyDocument envelope.
        pretty: Whether to pretty-print with indentation.

    Returns:
        JSON string.
    """
    if policy_name:
        output = {
            "PolicyName": policy_name,
            "PolicyDocument": policy,
        }
    else:
        output = policy

    indent = 2 if pretty else None
    return json.dumps(output, indent=indent, sort_keys=False)
