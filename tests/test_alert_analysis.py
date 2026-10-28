
import pytest

from agents.alert_analysis import analyze_alert


def test_extract_ip_and_domain():
    result = analyze_alert(
        "Connection from 203.0.113.10 to malware-example.test"
    )

    assert "203.0.113.10" in result["potential_ips"]
    assert "malware-example.test" in result["potential_domains"]


def test_empty_alert():
    result = analyze_alert("")

    assert result["potential_ips"] == []
    assert result["potential_domains"] == []


def test_duplicate_indicators_are_removed():
    result = analyze_alert(
        "203.0.113.10 connected to 203.0.113.10"
    )

    assert result["potential_ips"] == ["203.0.113.10"]


def test_reject_non_string_alert():
    with pytest.raises(TypeError):
        analyze_alert(None)


def test_reject_oversized_alert():
    with pytest.raises(ValueError, match="20,000"):
        analyze_alert("A" * 20_001)

