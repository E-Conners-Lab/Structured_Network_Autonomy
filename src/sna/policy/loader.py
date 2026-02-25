"""Policy YAML loading, validation, hot reload, and diff logging.

SECURITY: Uses yaml.safe_load() exclusively. Never use yaml.load().
Uses aiofiles for non-blocking file I/O.
"""

from __future__ import annotations

import difflib

import aiofiles
import structlog
import yaml

from sna.policy.models import PolicyConfig

logger = structlog.get_logger()


async def load_policy(file_path: str) -> PolicyConfig:
    """Load and validate a policy YAML file.

    Reads the file asynchronously, parses with yaml.safe_load(),
    and validates with Pydantic. Raises on any error — invalid
    policy fails loudly.

    Args:
        file_path: Path to the policy YAML file.

    Returns:
        A validated PolicyConfig instance.

    Raises:
        FileNotFoundError: If the policy file does not exist.
        yaml.YAMLError: If the YAML is malformed.
        pydantic.ValidationError: If the YAML content fails validation.
    """
    async with aiofiles.open(file_path, mode="r", encoding="utf-8") as f:
        raw_content = await f.read()

    data = yaml.safe_load(raw_content)
    if data is None:
        raise ValueError(f"Policy file is empty: {file_path}")

    policy = PolicyConfig(**data)

    await logger.ainfo(
        "policy_loaded",
        file_path=file_path,
        version=policy.version,
        tier_count=len(policy.action_tiers),
        hard_block_count=len(policy.hard_rules.always_block),
    )

    return policy


async def reload_policy(
    file_path: str,
    current_policy: PolicyConfig | None = None,
) -> tuple[PolicyConfig, str | None]:
    """Reload policy from YAML with optional diff logging.

    Loads the new policy and computes a diff against the current policy
    if one is provided. The diff is logged for audit purposes.

    Args:
        file_path: Path to the policy YAML file.
        current_policy: The currently loaded policy, if any.

    Returns:
        A tuple of (new_policy, diff_text). diff_text is None if there
        was no previous policy to compare against.

    Raises:
        FileNotFoundError: If the policy file does not exist.
        yaml.YAMLError: If the YAML is malformed.
        pydantic.ValidationError: If the YAML content fails validation.
    """
    new_policy = await load_policy(file_path)

    diff_text: str | None = None
    if current_policy is not None:
        diff_text = compute_policy_diff(current_policy, new_policy)
        if diff_text:
            await logger.ainfo(
                "policy_reloaded_with_changes",
                file_path=file_path,
                diff=diff_text,
            )
        else:
            await logger.ainfo(
                "policy_reloaded_no_changes",
                file_path=file_path,
            )

    return new_policy, diff_text


def compute_policy_diff(old: PolicyConfig, new: PolicyConfig) -> str | None:
    """Compute a unified diff between two policy configurations.

    Serializes both policies to sorted JSON-like representation and
    computes a line-by-line diff. Returns None if policies are identical.

    Args:
        old: The previous policy configuration.
        new: The new policy configuration.

    Returns:
        A unified diff string, or None if no changes.
    """
    old_text = old.model_dump_json(indent=2).splitlines(keepends=True)
    new_text = new.model_dump_json(indent=2).splitlines(keepends=True)

    diff_lines = list(difflib.unified_diff(
        old_text,
        new_text,
        fromfile="policy (before)",
        tofile="policy (after)",
    ))

    if not diff_lines:
        return None

    return "".join(diff_lines)
