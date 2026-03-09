"""Assemble and optimize IAM policy documents from parsed CloudTrail events."""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field

from ..config import MAX_POLICY_SIZE
from .action_mapper import ActionMapper
from .event_parser import ParsedEvent

logger = logging.getLogger(__name__)


@dataclass
class PolicyMetadata:
    """Metadata about a generated policy."""

    total_actions: int = 0
    total_services: int = 0
    policy_size: int = 0
    warnings: list[str] = field(default_factory=list)
    wildcard_actions: list[str] = field(default_factory=list)
    advisor_only_services: list[str] = field(default_factory=list)


def build_policy(
    events: list[ParsedEvent],
    advisor_services: list[str] | None = None,
) -> tuple[dict, PolicyMetadata]:
    """Build a least-privilege IAM policy from parsed CloudTrail events.

    Args:
        events: Parsed events with iam_action and resources populated.
        advisor_services: Service namespaces from Access Advisor (optional).

    Returns:
        Tuple of (policy_document, metadata).
    """
    metadata = PolicyMetadata()
    mapper = ActionMapper()

    # 1. Resolve IAM actions and collect (action, resources) pairs
    action_resources: dict[str, set[str]] = defaultdict(set)
    for event in events:
        if not event.iam_action:
            event.iam_action = mapper.resolve(event.event_source, event.event_name)
        action_resources[event.iam_action].update(event.resources)

    if not action_resources:
        metadata.warnings.append("No actions found — policy will be empty.")
        return {"Version": "2012-10-17", "Statement": []}, metadata

    # 2. Group actions by their resource set
    resource_set_actions: dict[frozenset[str], list[str]] = defaultdict(list)
    for action, resources in action_resources.items():
        resource_set_actions[frozenset(resources)].append(action)

    # 3. Build statements
    statements = []
    used_sids: set[str] = set()

    for resource_set, actions in resource_set_actions.items():
        actions_sorted = sorted(actions)
        resources_sorted = sorted(resource_set)

        # Track wildcard-only actions
        if resources_sorted == ["*"]:
            metadata.wildcard_actions.extend(actions_sorted)

        # Generate Sid
        sid = _generate_sid(actions_sorted, used_sids)
        used_sids.add(sid)

        statement = {
            "Sid": sid,
            "Effect": "Allow",
            "Action": actions_sorted if len(actions_sorted) > 1 else actions_sorted[0],
            "Resource": resources_sorted if len(resources_sorted) > 1 else resources_sorted[0],
        }
        statements.append(statement)

    # 4. Sort statements by Sid
    statements.sort(key=lambda s: s["Sid"])

    policy = {"Version": "2012-10-17", "Statement": statements}

    # 5. Check size and compress if needed
    policy_json = json.dumps(policy, separators=(",", ":"))
    metadata.policy_size = len(policy_json)

    if metadata.policy_size > MAX_POLICY_SIZE:
        policy, metadata.policy_size = _compress_policy(policy)
        if metadata.policy_size > MAX_POLICY_SIZE:
            metadata.warnings.append(
                f"Policy size ({metadata.policy_size} chars) exceeds "
                f"IAM limit ({MAX_POLICY_SIZE} chars). Consider splitting "
                "into multiple policies."
            )

    # 6. Compute stats
    all_actions = set()
    all_services = set()
    for actions in action_resources:
        all_actions.add(actions)
        all_services.add(actions.split(":")[0])
    metadata.total_actions = len(all_actions)
    metadata.total_services = len(all_services)

    # 7. iam:PassRole warning
    metadata.warnings.append(
        "iam:PassRole is not tracked by CloudTrail and cannot be detected. "
        "Add it manually if required."
    )

    # 8. Access Advisor supplementary services
    if advisor_services:
        ct_services = {a.split(":")[0] for a in action_resources}
        for svc in advisor_services:
            if svc not in ct_services:
                metadata.advisor_only_services.append(svc)
        if metadata.advisor_only_services:
            metadata.warnings.append(
                f"Services in Access Advisor but not in CloudTrail: "
                f"{', '.join(sorted(metadata.advisor_only_services))}. "
                "These may need manual action additions."
            )

    return policy, metadata


def _generate_sid(actions: list[str], used_sids: set[str]) -> str:
    """Generate a descriptive Sid for a statement.

    Format: {Service}{AccessType} e.g., S3ReadWrite, EC2Describe
    """
    # Extract unique service prefixes
    services = sorted({a.split(":")[0] for a in actions})
    service_part = "".join(
        s.capitalize() if not s[0].isupper() else s for s in services[:3]
    )
    if len(services) > 3:
        service_part += "Multi"

    # Determine access type
    action_names = [a.split(":")[1] for a in actions]
    if all(
        name.startswith(("Describe", "List", "Get"))
        for name in action_names
    ):
        access_type = "Read"
    else:
        access_type = "Access"

    sid = f"{service_part}{access_type}"

    # Ensure uniqueness
    if sid in used_sids:
        counter = 2
        while f"{sid}{counter}" in used_sids:
            counter += 1
        sid = f"{sid}{counter}"

    return sid


def _compress_policy(policy: dict) -> tuple[dict, int]:
    """Attempt to reduce policy size by consolidating actions with wildcards.

    Strategy: For services with >5 actions sharing a common prefix pattern,
    consolidate to a wildcard (e.g., s3:Get* instead of listing each).
    """
    new_statements = []
    for stmt in policy["Statement"]:
        actions = stmt["Action"] if isinstance(stmt["Action"], list) else [stmt["Action"]]

        # Group by service
        service_actions: dict[str, list[str]] = defaultdict(list)
        for action in actions:
            svc, name = action.split(":", 1)
            service_actions[svc].append(name)

        compressed_actions = []
        for svc, names in service_actions.items():
            if len(names) > 5:
                # Find common prefixes
                prefixes = _find_common_prefixes(names)
                compressed_actions.extend(f"{svc}:{p}*" for p in prefixes)
            else:
                compressed_actions.extend(f"{svc}:{n}" for n in names)

        stmt = dict(stmt)
        stmt["Action"] = sorted(compressed_actions) if len(compressed_actions) > 1 else compressed_actions[0]
        new_statements.append(stmt)

    policy = {"Version": "2012-10-17", "Statement": new_statements}
    size = len(json.dumps(policy, separators=(",", ":")))
    return policy, size


def _find_common_prefixes(names: list[str]) -> list[str]:
    """Find common prefixes among action names for wildcard consolidation.

    Groups actions like GetObject, GetBucketAcl, GetBucketPolicy -> Get
    """
    prefix_groups: dict[str, list[str]] = defaultdict(list)
    for name in names:
        # Use common verb prefixes: Get, Put, Delete, Create, Describe, List, Update
        for prefix in ("Describe", "List", "Get", "Put", "Delete", "Create", "Update", "Batch"):
            if name.startswith(prefix):
                prefix_groups[prefix].append(name)
                break
        else:
            prefix_groups[name].append(name)

    result = []
    for prefix, group in prefix_groups.items():
        if len(group) >= 3:
            result.append(prefix)
        else:
            result.extend(group)
    return result
