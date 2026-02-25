"""Tests for output sanitization — password stripping."""

from __future__ import annotations

from sna.devices.sanitizer import sanitize_output


class TestSanitizeOutput:
    """Verify passwords and credentials are stripped from device output."""

    def test_type7_password(self) -> None:
        output = "line con 0\n password 7 094F471A1A0A\n login"
        result = sanitize_output(output)
        assert "094F471A1A0A" not in result
        assert "***REDACTED***" in result

    def test_type5_secret(self) -> None:
        output = "enable secret 5 $1$mERr$9cTjUIEqN"
        result = sanitize_output(output)
        assert "$1$mERr$9cTjUIEqN" not in result
        assert "***REDACTED***" in result

    def test_snmp_community(self) -> None:
        output = "snmp-server community PUBLIC RO"
        result = sanitize_output(output)
        assert "PUBLIC" not in result
        assert "***REDACTED***" in result

    def test_preshared_key(self) -> None:
        output = "pre-shared-key abc123secret"
        result = sanitize_output(output)
        assert "abc123secret" not in result
        assert "***REDACTED***" in result

    def test_username_password(self) -> None:
        output = "username admin password 7 070C285F4D06"
        result = sanitize_output(output)
        assert "070C285F4D06" not in result
        assert "***REDACTED***" in result

    def test_key7(self) -> None:
        output = "key 7 15170A1715"
        result = sanitize_output(output)
        assert "15170A1715" not in result

    def test_no_passwords_unchanged(self) -> None:
        output = "interface GigabitEthernet0/1\n description Uplink\n ip address 10.0.0.1 255.255.255.0"
        result = sanitize_output(output)
        assert result == output

    def test_multiple_passwords_in_output(self) -> None:
        output = (
            "snmp-server community SECRET1 RO\n"
            "snmp-server community SECRET2 RW\n"
            "enable secret 5 $1$xxx$yyy\n"
        )
        result = sanitize_output(output)
        assert "SECRET1" not in result
        assert "SECRET2" not in result
        assert "$1$xxx$yyy" not in result

    def test_empty_output(self) -> None:
        assert sanitize_output("") == ""

    def test_ntp_auth_key(self) -> None:
        output = "ntp authentication-key 1 md5 NTPSECRET"
        result = sanitize_output(output)
        assert "NTPSECRET" not in result
