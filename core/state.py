
from typing import TypedDict, Any


class InvestigationState(TypedDict, total=False):
    # Input
    mode: str
    filename: str
    file_bytes: bytes
    alert_text: str

    # Analysis results
    file_analysis: dict[str, Any]
    alert_analysis: dict[str, Any]
    threat_matches: list[dict[str, Any]]

    # Final output
    risk_level: str
    report: dict[str, Any]
    errors: list[str]
