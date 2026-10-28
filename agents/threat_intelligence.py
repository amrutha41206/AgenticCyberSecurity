
import json
from pathlib import Path

DATASET_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "threat_indicators.json"
)


def load_indicators() -> list[dict]:
    """Load indicators from the local JSON file."""
    with DATASET_PATH.open("r", encoding="utf-8") as file:
        dataset = json.load(file)

    return dataset["indicators"]


def lookup_indicator(value: str, indicator_type: str) -> dict:
    """Look for an exact indicator match."""
    normalized_value = value.strip().lower()
    normalized_type = indicator_type.strip().lower()

    allowed_types = {"domain", "ip", "hash", "url"}

    if normalized_type not in allowed_types:
        raise ValueError("Unsupported indicator type.")

    indicators = load_indicators()

    for indicator in indicators:
        if (
            indicator["type"].lower() == normalized_type
            and indicator["value"].strip().lower()
            == normalized_value
        ):
            return {
                "indicator": normalized_value,
                "type": normalized_type,
                "status": indicator["status"],
                "source": indicator["source"],
                "matched": True,
            }

    return {
        "indicator": normalized_value,
        "type": normalized_type,
        "status": "unknown",
        "source": "No match in local demonstration dataset",
        "matched": False,
    }
