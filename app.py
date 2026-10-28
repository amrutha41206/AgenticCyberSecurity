
import streamlit as st
import pandas as pd

from core.graph import run_investigation

MAX_FILE_SIZE = 25 * 1024 * 1024

st.set_page_config(
    page_title="Agentic AI Cybersecurity Platform",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Agentic AI Cybersecurity Platform")
st.caption(
    "Static file analysis and security-alert investigation "
    "using a conditional LangGraph workflow."
)

st.info(
    "Safety: Uploaded files are inspected without execution. "
    "The local threat indicators are synthetic demonstration data."
)


def display_investigation_summary(report: dict) -> None:
    """Display the main risk assessment and AI explanation."""
    st.subheader("Investigation Summary")

    risk_level = str(report.get("risk_level", "Unconfirmed"))

    risk_icons = {
        "High": "🔴",
        "Medium": "🟠",
        "Low": "🟢",
        "Unconfirmed": "⚪",
    }

    icon = risk_icons.get(risk_level, "⚪")

    st.markdown(f"### {icon} Risk Level: {risk_level}")

    st.write(
        report.get(
            "explanation",
            "No rule-based explanation is available.",
        )
    )

    # Display the AI-generated explanation separately.
    ai_explanation = report.get("ai_explanation")

    if ai_explanation:
        with st.container(border=True):
            st.markdown("#### 🤖 AI-Generated Explanation")
            st.write(ai_explanation)

            st.caption(
                "AI-generated analysis is supplementary and may be "
                "inaccurate. Verify conclusions against the evidence "
                "and rule-based results."
            )

    # Display recommendations if the backend provides them.
    actions = report.get("recommended_actions", [])

    if isinstance(actions, list) and actions:
        with st.container(border=True):
            st.markdown("#### 🛡️ Recommended Defensive Actions")

            for action in actions:
                st.markdown(f"- {action}")

    elif isinstance(actions, str) and actions.strip():
        with st.container(border=True):
            st.markdown("#### 🛡️ Recommended Defensive Actions")
            st.write(actions)

    else:
        st.info(
            "Recommended actions are not included in this report yet. "
            "We can add them to the report-generation logic next."
        )



def display_investigation_details(report: dict) -> None:
    """Display findings, follow-up checks, and investigation metrics."""
    findings = report.get("investigation_findings", [])
    follow_up_checks = report.get("follow_up_checks", [])
    metrics = report.get("investigation_metrics", {})

    if findings or follow_up_checks or metrics:
        st.subheader("Investigation Agent Results")

        if findings:
            with st.container(border=True):
                st.markdown("#### 🔎 Investigation Findings")
                for finding in findings:
                    st.markdown(f"- {finding}")
        else:
            st.info("No investigation findings were included in this report.")

        if follow_up_checks:
            with st.container(border=True):
                st.markdown("#### 🧭 Recommended Follow-up Checks")
                for check in follow_up_checks:
                    st.markdown(f"- {check}")

        if isinstance(metrics, dict) and metrics:
            st.markdown("#### 📊 Investigation Metrics")
            col1, col2, col3 = st.columns(3)
            col1.metric(
                "Matched Indicators",
                metrics.get("matched_indicator_count", 0),
            )
            col2.metric(
                "Unmatched Indicators",
                metrics.get("unmatched_indicator_count", 0),
            )
            col3.metric(
                "Processing Errors",
                metrics.get("processing_error_count", 0),
            )


def display_threat_matches(matches: list[dict]) -> None:
    """Display local indicator lookup results."""
    st.subheader("Threat Intelligence Results")

    if not matches:
        st.warning("No indicators were available for lookup.")
        return

    rows = []

    for match in matches:
        rows.append({
            "Indicator": match.get("indicator", "Unknown"),
            "Type": match.get("type", "Unknown"),
            "Status": match.get("status", "Unknown"),
            "Matched": "Yes" if match.get("matched") else "No",
            "Source": match.get("source", "Unknown"),
        })

    st.dataframe(
        pd.DataFrame(rows),
        use_container_width=True,
        hide_index=True,
    )

    st.caption(
        "A dataset match is not independent proof of malicious activity. "
        "An unknown result does not mean an indicator is safe."
    )


def display_potential_indicators(indicators: dict) -> None:
    """Display candidate URLs, IPs, and domains."""
    st.subheader("Potential Indicators")

    categories = [
        ("potential_urls", "URLs"),
        ("potential_ips", "IP addresses"),
        ("potential_domains", "Domains"),
    ]

    columns = st.columns(3)

    for column, (key, label) in zip(columns, categories):
        values = indicators.get(key, [])
        column.metric(label, len(values))

        with column:
            if values:
                st.write(values)
            else:
                st.write("None detected")


def display_errors_and_limitations(report: dict) -> None:
    """Show processing errors and interpretation limitations."""
    errors = report.get("errors", [])

    if errors:
        st.subheader("Processing Warnings")

        for error in errors:
            st.warning(error)

    limitations = report.get("limitations", [])

    if limitations:
        with st.expander("Limitations and safety notes"):
            for limitation in limitations:
                st.write(f"- {limitation}")


# Investigation mode selection
mode = st.radio(
    "Choose investigation type",
    ["File Analysis", "Security Alert Analysis"],
    horizontal=True,
)


# --------------------------------------------------
# FILE ANALYSIS
# --------------------------------------------------
if mode == "File Analysis":
    st.subheader("Static File Analysis")

    uploaded_file = st.file_uploader(
        "Upload a file for analysis",
        type=None,
    )

    if uploaded_file is not None:
        st.write(f"**Filename:** {uploaded_file.name}")
        st.write(f"**Size:** {uploaded_file.size:,} bytes")
        st.caption("Maximum supported size: 25 MB.")

        if st.button("Analyze File", type="primary"):
            if uploaded_file.size > MAX_FILE_SIZE:
                st.error("File exceeds the 25 MB limit.")

            else:
                try:
                    with st.spinner("Running static analysis..."):
                        result = run_investigation({
                            "mode": "file",
                            "filename": uploaded_file.name,
                            "file_bytes": uploaded_file.getvalue(),
                        })

                    report = result["report"]

                    # New professional summary
                    display_investigation_summary(report)
                    display_investigation_details(report)

                    st.warning(
                        "This is a preliminary assessment based on "
                        "static indicators and a local synthetic dataset. "
                        "It is not a definitive malware verdict."
                    )

                    file_result = report.get("file_analysis")

                    if file_result:
                        st.subheader("File Properties")

                        col1, col2, col3 = st.columns(3)

                        col1.metric(
                            "File Size",
                            f"{file_result.get('size_bytes', 0):,} bytes",
                        )

                        col2.metric(
                            "Entropy",
                            file_result.get("entropy", "N/A"),
                        )

                        col3.metric(
                            "File Type",
                            file_result.get("file_type", "Unknown"),
                        )

                        sha256 = file_result.get("sha256")

                        if sha256:
                            st.write("**SHA-256 hash**")
                            st.code(sha256)

                        pe_metadata = file_result.get("pe_metadata")

                        if pe_metadata:
                            st.write("**PE Metadata**")
                            st.json(pe_metadata)

                        display_potential_indicators(
                            file_result.get("potential_indicators", {})
                        )

                        with st.expander("Readable strings extracted"):
                            strings = file_result.get(
                                "readable_strings", []
                            )

                            if strings:
                                for extracted_text in strings:
                                    st.code(extracted_text)
                            else:
                                st.write(
                                    "No readable strings detected."
                                )

                    display_threat_matches(
                        report.get("threat_matches", [])
                    )

                    display_errors_and_limitations(report)

                    with st.expander(
                        "Full Investigation Report (JSON)"
                    ):
                        st.json(report)

                except Exception as exc:
                    st.error(f"Analysis failed: {exc}")


# --------------------------------------------------
# SECURITY ALERT ANALYSIS
# --------------------------------------------------
elif mode == "Security Alert Analysis":
    st.subheader("Security Alert Investigation")

    alert_text = st.text_area(
        "Paste security alert or log text",
        height=180,
        max_chars=20000,
        placeholder=(
            "Example: Suspicious connection to "
            "malware-example.test from 203.0.113.10"
        ),
    )

    if st.button("Analyze Alert", type="primary"):
        if not alert_text.strip():
            st.warning("Please enter security alert text.")

        else:
            try:
                with st.spinner("Investigating alert indicators..."):
                    result = run_investigation({
                        "mode": "alert",
                        "alert_text": alert_text,
                    })

                report = result["report"]

                # New professional summary
                display_investigation_summary(report)
                display_investigation_details(report)

                st.warning(
                    "Extracted indicators are candidates for investigation, "
                    "not proof that a connection or host is malicious."
                )

                alert_result = report.get("alert_analysis")

                if alert_result:
                    col1, col2 = st.columns(2)

                    col1.metric(
                        "Potential IP addresses",
                        len(alert_result.get("potential_ips", [])),
                    )

                    col2.metric(
                        "Potential domains",
                        len(alert_result.get("potential_domains", [])),
                    )

                    st.write("**Extracted IP addresses**")

                    st.write(
                        alert_result.get("potential_ips", [])
                        or "None found"
                    )

                    st.write("**Extracted domains**")

                    st.write(
                        alert_result.get("potential_domains", [])
                        or "None found"
                    )

                display_threat_matches(
                    report.get("threat_matches", [])
                )

                display_errors_and_limitations(report)

                with st.expander(
                    "Full Investigation Report (JSON)"
                ):
                    st.json(report)

            except Exception as exc:
                st.error(f"Analysis failed: {exc}")


# --------------------------------------------------
# FOOTER
# --------------------------------------------------
st.divider()

st.caption(
    "Academic prototype only. Unknown indicators do not mean safe. "
    "The local threat list is synthetic, not live threat intelligence. "
    "Do not upload confidential or sensitive files."
)
