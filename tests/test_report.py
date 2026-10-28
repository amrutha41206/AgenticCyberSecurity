
from core.graph import report_node


def test_report_preserves_individual_indicator_statuses():
    state = {
        "mode": "alert",
        "threat_matches": [
            {
                "indicator": "203.0.113.10",
                "type": "ip",
                "status": "suspicious",
                "matched": True,
                "source": "Synthetic training dataset",
            },
            {
                "indicator": "malware-example.test",
                "type": "domain",
                "status": "known_malicious",
                "matched": True,
                "source": "Synthetic training dataset",
            },
        ],
        "errors": [],
    }

    result = report_node(state)
    report = result["report"]

    assert result["risk_level"] == "High"
    assert report["risk_level"] == "High"

    evidence = {
        item["indicator"]: item
        for item in report["evidence_summary"]
    }

    assert evidence["203.0.113.10"]["status"] == "suspicious"
    assert evidence["malware-example.test"]["status"] == "known_malicious"

    assert evidence["203.0.113.10"]["matched"] is True
    assert evidence["malware-example.test"]["matched"] is True
