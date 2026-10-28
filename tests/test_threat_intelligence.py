
import pytest

from agents.threat_intelligence import lookup_indicator


def test_known_malicious_demo_domain():
    result = lookup_indicator(
        "malware-example.test",
        "domain",
    )

    assert result["matched"] is True
    assert result["status"] == "known_malicious"


def test_suspicious_demo_ip():
    result = lookup_indicator(
        "203.0.113.10",
        "ip",
    )

    assert result["matched"] is True
    assert result["status"] == "suspicious"


def test_unknown_domain():
    result = lookup_indicator(
        "unknown-example.test",
        "domain",
    )

    assert result["matched"] is False
    assert result["status"] == "unknown"


def test_indicator_lookup_is_case_insensitive():
    result = lookup_indicator(
        "MALWARE-EXAMPLE.TEST",
        "domain",
    )

    assert result["matched"] is True


def test_reject_unsupported_indicator_type():
    with pytest.raises(ValueError, match="Unsupported"):
        lookup_indicator("example.test", "email")
