
import re


IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,63}\b"
)


def analyze_alert(alert_text: str) -> dict:
    """Extract potential indicators from security-alert text."""

    if not isinstance(alert_text, str):
        raise TypeError("Alert text must be a string.")

    if len(alert_text) > 20_000:
        raise ValueError("Alert text exceeds the 20,000-character limit.")

    ips = sorted(set(IP_PATTERN.findall(alert_text)))
    domains = sorted(set(DOMAIN_PATTERN.findall(alert_text)))

    return {
        "alert_length": len(alert_text),
        "potential_ips": ips,
        "potential_domains": domains,
        "limitations": [
            "Extracted indicators are not verified as malicious.",
            "IP pattern matching does not validate IP address ranges.",
            "Domain extraction is pattern-based and may produce false positives."
        ]
    }
