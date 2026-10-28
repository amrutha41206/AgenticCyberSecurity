
from typing import Any

from langgraph.graph import StateGraph, START, END

from core.state import InvestigationState
from agents.static_analysis import analyze_file
from agents.alert_analysis import analyze_alert
from agents.threat_intelligence import lookup_indicator
from agents.local_llm import generate_explanation
from agents.investigation_agent import investigate_evidence


def route_input(state: InvestigationState) -> str:
    """Choose the analysis path based on the input mode."""
    mode = state.get("mode")

    if mode == "file":
        return "file_analysis"

    if mode == "alert":
        return "alert_analysis"

    raise ValueError("Mode must be 'file' or 'alert'.")


def file_analysis_node(
    state: InvestigationState,
) -> dict[str, Any]:
    """Analyze file bytes without executing the file."""
    filename = state.get("filename", "uploaded_file")
    file_bytes = state.get("file_bytes")

    if not isinstance(file_bytes, bytes):
        return {"errors": ["File analysis requires file bytes."]}

    try:
        result = analyze_file(filename, file_bytes)
        return {"file_analysis": result}
    except (ValueError, TypeError) as exc:
        return {"errors": [f"File analysis failed: {exc}"]}


def alert_analysis_node(
    state: InvestigationState,
) -> dict[str, Any]:
    """Extract candidate indicators from a security alert."""
    alert_text = state.get("alert_text")

    if not isinstance(alert_text, str):
        return {"errors": ["Alert analysis requires text."]}

    try:
        result = analyze_alert(alert_text)
        return {"alert_analysis": result}
    except (ValueError, TypeError) as exc:
        return {"errors": [f"Alert analysis failed: {exc}"]}


def threat_lookup_node(
    state: InvestigationState,
) -> dict[str, Any]:
    """Check extracted indicators against the local demo dataset."""
    matches = []
    errors = list(state.get("errors", []))
    seen = set()

    file_analysis = state.get("file_analysis") or {}
    alert_analysis = state.get("alert_analysis") or {}

    candidates = []

    file_hash = file_analysis.get("sha256")
    if file_hash:
        candidates.append(("hash", file_hash))

    file_indicators = file_analysis.get("potential_indicators", {})

    for value in file_indicators.get("potential_ips", []):
        candidates.append(("ip", value))

    for value in file_indicators.get("potential_domains", []):
        candidates.append(("domain", value))

    for value in file_indicators.get("potential_urls", []):
        candidates.append(("url", value))

    for value in alert_analysis.get("potential_ips", []):
        candidates.append(("ip", value))

    for value in alert_analysis.get("potential_domains", []):
        candidates.append(("domain", value))

    for indicator_type, value in candidates:
        key = (indicator_type, value.strip().lower())

        if key in seen:
            continue

        seen.add(key)

        try:
            result = lookup_indicator(value, indicator_type)
            matches.append(result)
        except (ValueError, OSError, KeyError) as exc:
            errors.append(
                f"Threat lookup failed for {value}: {exc}"
            )

    return {
        "threat_matches": matches,
        "errors": errors,
    }


def get_recommended_actions(
    risk_level: str,
    threat_matches: list[dict],
    errors: list[str],
) -> list[str]:
    """Return defensive recommendations using deterministic rules."""
    actions = []

    if risk_level == "High":
        actions.extend([
            "Preserve the investigation report and relevant security logs.",
            "Validate matched indicators using trusted threat-intelligence sources.",
            "If a real system may be affected, follow the approved incident-response "
            "procedure and notify the responsible security team.",
        ])

    elif risk_level == "Medium":
        actions.extend([
            "Review suspicious indicators using trusted threat-intelligence sources.",
            "Correlate the alert with relevant system and network logs.",
            "Escalate the finding if additional evidence supports suspicious activity.",
        ])

    else:
        actions.extend([
            "Do not treat the absence of a known indicator match as proof of safety.",
            "Gather additional context and review relevant security logs if needed.",
            "Use trusted, approved security tools for further analysis.",
        ])

    if not threat_matches:
        actions.append(
            "No indicators were available for comparison; review extracted evidence."
        )

    if errors:
        actions.append(
            "Review processing or lookup errors before relying on the assessment."
        )

    actions.append(
        "These recommendations are advisory. No files or system settings "
        "were automatically changed."
    )

    return actions


def report_node(
    state: InvestigationState,
) -> dict[str, Any]:
    """Create the rule-based report and investigation findings."""
    matches = state.get("threat_matches", [])
    errors = state.get("errors", [])

    statuses = {
        match.get("status")
        for match in matches
        if match.get("matched")
    }

    # The rule-based system assigns risk; the AI cannot change it.
    if "known_malicious" in statuses:
        risk_level = "High"
        explanation = (
            "At least one indicator matched an entry labelled "
            "known_malicious in the local indicator list."
        )
    elif "suspicious" in statuses:
        risk_level = "Medium"
        explanation = (
            "At least one indicator matched an entry labelled "
            "suspicious in the local indicator list."
        )
    else:
        risk_level = "Unconfirmed"
        explanation = (
            "No known_malicious or suspicious indicator was matched. "
            "This does not prove the file or alert is safe."
        )

    limitations = [
        "The local indicator list is synthetic demonstration data.",
        "Static analysis alone cannot prove whether a file is malicious.",
        "Extracted indicators are candidates, not proof of malicious activity.",
        "Unknown indicators may still be harmful.",
        "This prototype is not a production malware detector.",
    ]

    evidence_summary = [
        {
            "indicator": match.get("indicator"),
            "type": match.get("type"),
            "status": match.get("status"),
            "matched": match.get("matched"),
            "source": match.get("source"),
        }
        for match in matches
    ]

    # Deterministic recommendations.
    recommended_actions = get_recommended_actions(
        risk_level,
        matches,
        errors,
    )

    # New investigation agent examines evidence and suggests follow-up checks.
    investigation_result = investigate_evidence(
        matches,
        errors,
    )

    prompt = (
        "Explain this cybersecurity investigation in at most "
        "3 short sentences. Use only the supplied evidence. "
        "Do not claim that an infection is confirmed. "
        "Mention that the indicator dataset is synthetic "
        "demonstration data. Do not change the assigned risk level.\n\n"
        f"Assigned risk level: {risk_level}\n"
        f"Rule-based explanation: {explanation}\n"
        f"Indicator evidence: {evidence_summary}\n"
        f"Investigation mode: {state.get('mode', 'unknown')}\n"
        f"Limitations: {limitations}"
    )

    try:
        ai_explanation = generate_explanation(prompt)

        if (
            not isinstance(ai_explanation, str)
            or not ai_explanation.strip()
        ):
            ai_explanation = (
                "AI explanation was unavailable. "
                "Refer to the rule-based explanation and evidence."
            )
    except Exception:
        ai_explanation = (
            "AI explanation was unavailable. "
            "Refer to the rule-based explanation and evidence."
        )

    investigation_metrics = {
        "matched_indicator_count": investigation_result[
            "matched_indicator_count"
        ],
        "unmatched_indicator_count": investigation_result[
            "unmatched_indicator_count"
        ],
        "processing_error_count": investigation_result[
            "processing_error_count"
        ],
    }

    report = {
        "risk_level": risk_level,
        "explanation": explanation,
        "ai_explanation": ai_explanation,
        "recommended_actions": recommended_actions,
        "investigation_findings": investigation_result["findings"],
        "follow_up_checks": investigation_result["follow_up_checks"],
        "investigation_metrics": investigation_metrics,
        "file_analysis": state.get("file_analysis"),
        "alert_analysis": state.get("alert_analysis"),
        "threat_matches": matches,
        "evidence_summary": evidence_summary,
        "errors": errors,
        "limitations": limitations,
    }

    return {
        "risk_level": risk_level,
        "report": report,
    }


def build_graph():
    """Build the conditional investigation workflow."""
    builder = StateGraph(InvestigationState)

    builder.add_node("file_analysis", file_analysis_node)
    builder.add_node("alert_analysis", alert_analysis_node)
    builder.add_node("threat_lookup", threat_lookup_node)
    builder.add_node("report", report_node)

    builder.add_conditional_edges(
        START,
        route_input,
        {
            "file_analysis": "file_analysis",
            "alert_analysis": "alert_analysis",
        },
    )

    builder.add_edge("file_analysis", "threat_lookup")
    builder.add_edge("alert_analysis", "threat_lookup")
    builder.add_edge("threat_lookup", "report")
    builder.add_edge("report", END)

    return builder.compile()


graph = build_graph()


def run_investigation(
    inputs: dict[str, Any],
) -> dict[str, Any]:
    """Validate input and run the investigation graph."""
    if not isinstance(inputs, dict):
        raise TypeError("Inputs must be provided as a dictionary.")

    mode = inputs.get("mode")

    if mode not in {"file", "alert"}:
        raise ValueError("Mode must be 'file' or 'alert'.")

    if mode == "file":
        if not isinstance(inputs.get("file_bytes"), bytes):
            raise ValueError(
                "File mode requires file_bytes as bytes."
            )

    if mode == "alert":
        if not isinstance(inputs.get("alert_text"), str):
            raise ValueError(
                "Alert mode requires alert_text as text."
            )

    return graph.invoke(inputs)

