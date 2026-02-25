"""Semantic config diff analysis for IOS-style network device configurations.

Provides section-aware diffing (groups changes by config section) rather than
flat line-by-line comparison. All diff output is sanitized before storage.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field

from sna.devices.sanitizer import sanitize_output

# Maximum input size for parsing (security: prevents regex DoS on large output)
_MAX_INPUT_BYTES = 65_536


@dataclass
class ConfigSection:
    """A parsed section of IOS-style configuration."""

    name: str
    lines: list[str] = field(default_factory=list)
    children: list[ConfigSection] = field(default_factory=list)


class ChangeType(str, enum.Enum):
    """Type of change in a diff entry."""

    ADDED = "ADDED"
    REMOVED = "REMOVED"
    MODIFIED = "MODIFIED"


@dataclass(frozen=True)
class DiffEntry:
    """A single diff entry representing a change in one config section."""

    section: str
    change_type: ChangeType
    before_lines: tuple[str, ...] = ()
    after_lines: tuple[str, ...] = ()


def parse_config_sections(config_text: str) -> list[ConfigSection]:
    """Parse IOS-style config into hierarchical sections.

    Recognizes section headers like 'interface GigabitEthernet0/1',
    'router ospf 1', 'line vty 0 4', etc. Nested content is grouped
    under the section until the next section or '!' separator.

    Args:
        config_text: Raw configuration text.

    Returns:
        List of ConfigSection objects.
    """
    # Truncate to prevent regex DoS
    text = config_text[:_MAX_INPUT_BYTES]

    # Patterns that start a new section in IOS-style config
    section_pattern = re.compile(
        r"^(interface|router|ip route|ip access-list|line|vlan|"
        r"crypto|snmp-server|ntp|logging|aaa|class-map|"
        r"policy-map|route-map|prefix-list|banner)\s",
        re.IGNORECASE,
    )

    sections: list[ConfigSection] = []
    current_section: ConfigSection | None = None

    for line in text.splitlines():
        stripped = line.rstrip()

        # Skip empty lines and comment separators
        if not stripped or stripped == "!":
            if current_section is not None:
                sections.append(current_section)
                current_section = None
            continue

        # Check if this starts a new section
        if section_pattern.match(stripped) and not stripped.startswith(" "):
            if current_section is not None:
                sections.append(current_section)
            current_section = ConfigSection(name=stripped)
        elif current_section is not None:
            # Indented line belongs to current section
            current_section.lines.append(stripped)
        else:
            # Top-level line outside a section
            sections.append(ConfigSection(name=stripped))

    if current_section is not None:
        sections.append(current_section)

    return sections


def compute_semantic_diff(before: str, after: str) -> list[DiffEntry]:
    """Compute a section-aware diff between two configurations.

    Groups changes by config section rather than producing a flat line diff.
    All output is sanitized to strip credentials.

    Args:
        before: Pre-change configuration text.
        after: Post-change configuration text.

    Returns:
        List of DiffEntry objects describing changes by section.
    """
    before_sections = parse_config_sections(before)
    after_sections = parse_config_sections(after)

    # Index sections by name
    before_map: dict[str, ConfigSection] = {s.name: s for s in before_sections}
    after_map: dict[str, ConfigSection] = {s.name: s for s in after_sections}

    entries: list[DiffEntry] = []

    # Find removed sections
    for name, section in before_map.items():
        if name not in after_map:
            entries.append(DiffEntry(
                section=sanitize_output(name),
                change_type=ChangeType.REMOVED,
                before_lines=tuple(sanitize_output(l) for l in section.lines),
            ))

    # Find added and modified sections
    for name, section in after_map.items():
        if name not in before_map:
            entries.append(DiffEntry(
                section=sanitize_output(name),
                change_type=ChangeType.ADDED,
                after_lines=tuple(sanitize_output(l) for l in section.lines),
            ))
        else:
            before_section = before_map[name]
            if section.lines != before_section.lines:
                entries.append(DiffEntry(
                    section=sanitize_output(name),
                    change_type=ChangeType.MODIFIED,
                    before_lines=tuple(sanitize_output(l) for l in before_section.lines),
                    after_lines=tuple(sanitize_output(l) for l in section.lines),
                ))

    return entries


def summarize_diff(entries: list[DiffEntry]) -> str:
    """Generate a human-readable summary of diff entries.

    Args:
        entries: List of DiffEntry objects.

    Returns:
        Multi-line summary string.
    """
    if not entries:
        return "No configuration changes detected."

    lines: list[str] = [f"{len(entries)} section(s) changed:"]
    for entry in entries:
        lines.append(f"  [{entry.change_type.value}] {entry.section}")
        if entry.change_type == ChangeType.ADDED:
            for line in entry.after_lines[:5]:
                lines.append(f"    + {line}")
        elif entry.change_type == ChangeType.REMOVED:
            for line in entry.before_lines[:5]:
                lines.append(f"    - {line}")
        elif entry.change_type == ChangeType.MODIFIED:
            for line in entry.before_lines[:3]:
                lines.append(f"    - {line}")
            for line in entry.after_lines[:3]:
                lines.append(f"    + {line}")

    return "\n".join(lines)
