"""Convert IAM policies to Terraform aws_iam_policy_document format."""

from __future__ import annotations


def _hcl_escape(value: str) -> str:
    """Escape a string for safe embedding in HCL double-quoted strings."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("${", "$${")


def format_policy_terraform(policy: dict) -> str:
    """Convert a policy document to a Terraform data source block.

    Args:
        policy: IAM policy document dict.

    Returns:
        HCL string for a data "aws_iam_policy_document" block.
    """
    lines = ['data "aws_iam_policy_document" "generated" {']

    for stmt in policy.get("Statement", []):
        lines.append("")
        lines.append("  statement {")

        if "Sid" in stmt:
            lines.append(f'    sid    = "{_hcl_escape(stmt["Sid"])}"')
        lines.append(f'    effect = "{_hcl_escape(stmt.get("Effect", "Allow"))}"')

        # Actions
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        lines.append("")
        lines.append("    actions = [")
        for action in sorted(actions):
            lines.append(f'      "{_hcl_escape(action)}",')
        lines.append("    ]")

        # Resources
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        lines.append("")
        lines.append("    resources = [")
        for resource in sorted(resources):
            lines.append(f'      "{_hcl_escape(resource)}",')
        lines.append("    ]")

        # Conditions
        if "Condition" in stmt:
            for operator, conditions in stmt["Condition"].items():
                for key, values in conditions.items():
                    if isinstance(values, str):
                        values = [values]
                    lines.append("")
                    lines.append("    condition {")
                    lines.append(f'      test     = "{_hcl_escape(operator)}"')
                    lines.append(f'      variable = "{_hcl_escape(key)}"')
                    lines.append("")
                    lines.append("      values = [")
                    for val in values:
                        lines.append(f'        "{_hcl_escape(val)}",')
                    lines.append("      ]")
                    lines.append("    }")

        lines.append("  }")

    lines.append("}")
    lines.append("")
    return "\n".join(lines)
