"""Compare existing role policies against generated least-privilege policy."""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import unquote

import boto3

from ..config import BOTO_CONFIG

logger = logging.getLogger(__name__)


@dataclass
class DiffResult:
    """Result of comparing current vs generated policy actions."""

    matched: list[str] = field(default_factory=list)
    unused: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    current_action_count: int = 0
    observed_action_count: int = 0
    coverage_pct: int = 0


def compute_diff(
    role_arn: str,
    generated_policy: dict,
    region: str | None = None,
) -> DiffResult:
    """Compare a role's current policies against a generated policy.

    Args:
        role_arn: IAM role ARN to fetch current policies for.
        generated_policy: The generated least-privilege policy document.
        region: AWS region.

    Returns:
        DiffResult with matched, unused, and missing actions.
    """
    role_name = role_arn.split("/")[-1]
    current_actions = _fetch_current_actions(role_name, region)
    generated_actions = _extract_actions(generated_policy)

    current_set = set(current_actions)
    generated_set = set(generated_actions)

    matched = sorted(current_set & generated_set)
    unused = sorted(current_set - generated_set)
    missing = sorted(generated_set - current_set)

    current_count = len(current_set)
    coverage = int((len(matched) / current_count * 100)) if current_count > 0 else 0

    return DiffResult(
        matched=matched,
        unused=unused,
        missing=missing,
        current_action_count=current_count,
        observed_action_count=len(generated_set),
        coverage_pct=coverage,
    )


def format_diff_text(diff: DiffResult) -> str:
    """Format a DiffResult as a text report grouped by service.

    Returns:
        Formatted text string for display or email.
    """
    # Group all actions by service
    services: dict[str, dict[str, list[str]]] = defaultdict(
        lambda: {"matched": [], "unused": [], "missing": []}
    )

    for action in diff.matched:
        svc = action.split(":")[0]
        services[svc]["matched"].append(action)

    for action in diff.unused:
        svc = action.split(":")[0]
        services[svc]["unused"].append(action)

    for action in diff.missing:
        svc = action.split(":")[0]
        services[svc]["missing"].append(action)

    lines = []
    for svc in sorted(services):
        data = services[svc]
        current = len(data["matched"]) + len(data["unused"])
        observed = len(data["matched"]) + len(data["missing"])
        lines.append(f"[{svc}] (Current: {current} actions | Observed: {observed} actions)")

        if data["matched"]:
            lines.append(f"  MATCHED:  {', '.join(sorted(data['matched']))}")
        if data["unused"]:
            lines.append(f"  UNUSED:   {', '.join(sorted(data['unused']))}")
        if data["missing"]:
            lines.append(f"  MISSING:  {', '.join(sorted(data['missing']))}")
        if not any(data.values()):
            lines.append("  (none)")
        lines.append("")

    # IAM PassRole note
    lines.append("[iam] NOTE: iam:PassRole is not tracked by CloudTrail and cannot be detected.")
    lines.append("")

    # Summary
    lines.append("--- SUMMARY ---")
    lines.append(f"  {len(diff.unused)} actions are UNUSED and can potentially be removed")
    lines.append(f"  {len(diff.missing)} actions are MISSING from the policy (granted via other paths)")
    lines.append(f"  {len(diff.matched)} actions MATCHED between policy and observed usage")

    return "\n".join(lines)


def _fetch_current_actions(role_name: str, region: str | None = None) -> list[str]:
    """Fetch all actions from a role's attached and inline policies."""
    client = boto3.client("iam", region_name=region, config=BOTO_CONFIG)
    actions = set()

    # Managed policies
    try:
        paginator = client.get_paginator("list_attached_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy in page.get("AttachedPolicies", []):
                policy_arn = policy["PolicyArn"]
                policy_actions = _get_managed_policy_actions(client, policy_arn)
                actions.update(policy_actions)
    except Exception as e:
        logger.warning("Failed to list managed policies for %s: %s", role_name, e)

    # Inline policies
    try:
        paginator = client.get_paginator("list_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy_name in page.get("PolicyNames", []):
                policy_actions = _get_inline_policy_actions(
                    client, role_name, policy_name
                )
                actions.update(policy_actions)
    except Exception as e:
        logger.warning("Failed to list inline policies for %s: %s", role_name, e)

    return sorted(actions)


def _get_managed_policy_actions(client, policy_arn: str) -> set[str]:
    """Extract actions from a managed policy's default version."""
    actions = set()
    try:
        policy_resp = client.get_policy(PolicyArn=policy_arn)
        version_id = policy_resp["Policy"]["DefaultVersionId"]
        version_resp = client.get_policy_version(
            PolicyArn=policy_arn, VersionId=version_id
        )
        doc = version_resp["PolicyVersion"]["Document"]
        if isinstance(doc, str):
            doc = json.loads(unquote(doc))
        actions.update(_extract_actions(doc))
    except Exception as e:
        logger.warning("Failed to get managed policy %s: %s", policy_arn, e)
    return actions


def _get_inline_policy_actions(
    client, role_name: str, policy_name: str
) -> set[str]:
    """Extract actions from an inline policy."""
    actions = set()
    try:
        resp = client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
        doc = resp["PolicyDocument"]
        if isinstance(doc, str):
            doc = json.loads(unquote(doc))
        actions.update(_extract_actions(doc))
    except Exception as e:
        logger.warning(
            "Failed to get inline policy %s/%s: %s", role_name, policy_name, e
        )
    return actions


def _extract_actions(policy_doc: dict) -> set[str]:
    """Extract all Allow actions from a policy document."""
    actions = set()
    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        stmt_actions = stmt.get("Action", [])
        if isinstance(stmt_actions, str):
            stmt_actions = [stmt_actions]
        actions.update(stmt_actions)
    return actions
