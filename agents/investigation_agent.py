
from typing import Any


def investigate_evidence(
    threat_matches: list[dict[str, Any]],
    errors: list[str] | None = None,
) -> dict[str, Any]:
    """
    Examine investigation evidence and identify follow-up checks.

    This agent uses deterministic Python rules. It does not execute
    files, change system settings, or perform network actions.
    """
    errors = errors or []

    matched_indicators = [
        item
        for item in threat_matches
        if item.get("matched") is True
    ]

    unmatched_indicators = [
        item
        for item in threat_matches
        if item.get("matched") is not True
    ]

    known_malicious = [
        item
        for item in matched_indicators
        if item.get("status") == "known_malicious"
    ]

    suspicious = [
        item
        for item in matched_indicators
        if item.get("status") == "suspicious"
    ]

    findings = []
    follow_up_checks = []

    if known_malicious:
        findings.append(
            "One or more indicators matched entries labelled "
            "known_malicious in the local demonstration dataset."
        )
        follow_up_checks.append(
            "Validate the matched indicators against trusted "
            "threat-intelligence sources."
        )

    if suspicious:
        findings.append(
            "One or more indicators matched entries labelled "
            "suspicious in the local demonstration dataset."
        )
        follow_up_checks.append(
            "Review the surrounding security logs to understand "
            "the context of the suspicious indicators."
        )

    if unmatched_indicators:
        findings.append(
            "Some indicators did not match an entry in the local dataset."
        )
        follow_up_checks.append(
            "Investigate unmatched indicators using approved "
            "security tools and trusted sources."
        )

    if not threat_matches:
        findings.append(
            "No indicators were available for comparison."
        )
        follow_up_checks.append(
            "Review the extracted evidence and confirm whether "
            "additional indicators can be collected."
        )

    if errors:
        findings.append(
            "One or more analysis or lookup operations reported errors."
        )
        follow_up_checks.append(
            "Review processing errors before relying on the assessment."
        )

    if not findings:
        findings.append(
            "No matched suspicious indicators or processing errors "
            "were identified in the supplied evidence."
        )
        follow_up_checks.append(
            "Review the available evidence and remember that no match "
            "does not establish that a system is safe."
        )

    follow_up_checks.append(
        "Treat these findings as preliminary because the local dataset "
        "contains synthetic demonstration indicators."
    )

    # Remove duplicate follow-up checks while preserving order.
    follow_up_checks = list(dict.fromkeys(follow_up_checks))

    return {
        "findings": findings,
        "follow_up_checks": follow_up_checks,
        "matched_indicator_count": len(matched_indicators),
        "unmatched_indicator_count": len(unmatched_indicators),
        "processing_error_count": len(errors),
    }
