"""Output sanitization — strips known password patterns from device output.

SECURITY: All device output is passed through sanitize_output() before
storage to prevent credential leakage in audit logs and API responses.
"""

from __future__ import annotations

import re

# Patterns that match known credential formats in device output
_PASSWORD_PATTERNS: list[re.Pattern[str]] = [
    # Cisco Type 7 passwords (e.g., "password 7 094F471A1A0A")
    re.compile(r"(?i)(password\s+7\s+)\S+"),
    # Cisco Type 5 passwords (e.g., "secret 5 $1$xxxx$xxxxx")
    re.compile(r"(?i)(secret\s+5\s+)\S+"),
    # Cisco Type 8/9 passwords
    re.compile(r"(?i)(secret\s+[89]\s+)\S+"),
    # SNMP community strings (e.g., "snmp-server community PUBLIC")
    re.compile(r"(?i)(snmp-server\s+community\s+)\S+"),
    # Pre-shared keys
    re.compile(r"(?i)(pre-shared-key\s+)\S+"),
    # Crypto key strings
    re.compile(r"(?i)(key-string\s+)\S+"),
    # TACACS/RADIUS shared secrets
    re.compile(r"(?i)(server-private\s+\S+\s+key\s+)\S+"),
    re.compile(r"(?i)(key\s+7\s+)\S+"),
    # NTP authentication key
    re.compile(r"(?i)(ntp\s+authentication-key\s+\d+\s+md5\s+)\S+"),
    # Generic password lines
    re.compile(r"(?i)(password\s+)\S+(?=\s*$)", re.MULTILINE),
    # Enable secret
    re.compile(r"(?i)(enable\s+secret\s+\d+\s+)\S+"),
    # Username password
    re.compile(r"(?i)(username\s+\S+\s+(?:password|secret)\s+\d+\s+)\S+"),
]

_REDACTED = "***REDACTED***"


def sanitize_output(output: str) -> str:
    """Strip known password and credential patterns from device output.

    Args:
        output: Raw device command output.

    Returns:
        Sanitized output with credentials replaced by ***REDACTED***.
    """
    result = output
    for pattern in _PASSWORD_PATTERNS:
        result = pattern.sub(rf"\g<1>{_REDACTED}", result)
    return result
