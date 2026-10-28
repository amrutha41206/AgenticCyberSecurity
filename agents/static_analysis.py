
import hashlib
import math
import re
from typing import Any


MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB
MAX_EXTRACTED_STRINGS = 200
MIN_STRING_LENGTH = 5
MAX_STRING_LENGTH = 500

URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>]+",
    re.IGNORECASE,
)

IP_PATTERN = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
)

DOMAIN_PATTERN = re.compile(
    r"(?<![\w.-])(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,63}(?![\w.-])"
)


def detect_file_type(data: bytes) -> str:
    """Identify a few common file formats from their signatures."""
    if data.startswith(b"MZ"):
        return "Windows PE candidate (MZ signature)"
    if data.startswith(b"\x7fELF"):
        return "ELF executable"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP archive"
    if data.startswith(b"%PDF"):
        return "PDF document"
    if not data:
        return "Empty file"

    return "Unknown or unrecognized format"


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy, from 0 to 8 bits per byte."""
    if not data:
        return 0.0

    counts = [0] * 256

    for byte in data:
        counts[byte] += 1

    entropy = 0.0

    for count in counts:
        if count:
            probability = count / len(data)
            entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def extract_readable_strings(data: bytes) -> list[str]:
    """Extract printable ASCII strings without executing the file."""
    extracted = []
    current = bytearray()

    for byte in data:
        if byte in (9, 10, 13) or 32 <= byte <= 126:
            current.append(byte)
        else:
            if len(current) >= MIN_STRING_LENGTH:
                text = current.decode(
                    "ascii", errors="ignore"
                ).strip()

                if text:
                    extracted.append(text[:MAX_STRING_LENGTH])

            current.clear()

        if len(extracted) >= MAX_EXTRACTED_STRINGS:
            break

    # Include the final string if the file ends with printable bytes.
    if (
        len(extracted) < MAX_EXTRACTED_STRINGS
        and len(current) >= MIN_STRING_LENGTH
    ):
        text = current.decode(
            "ascii", errors="ignore"
        ).strip()

        if text:
            extracted.append(text[:MAX_STRING_LENGTH])

    return extracted[:MAX_EXTRACTED_STRINGS]


def extract_potential_indicators(
    strings: list[str],
) -> dict[str, list[str]]:
    """Find candidate URLs, IP addresses and domains."""
    combined_text = "\n".join(strings)

    urls = sorted(set(URL_PATTERN.findall(combined_text)))
    ips = sorted(set(IP_PATTERN.findall(combined_text)))
    domains = sorted(set(DOMAIN_PATTERN.findall(combined_text)))

    return {
        "potential_urls": urls[:100],
        "potential_ips": ips[:100],
        "potential_domains": domains[:100],
    }


def analyze_file(filename: str, data: bytes) -> dict[str, Any]:
    """Analyze file bytes without executing the file."""
    if not isinstance(data, bytes):
        raise TypeError("File data must be provided as bytes.")

    if len(data) > MAX_FILE_SIZE:
        raise ValueError("File exceeds the 25 MB analysis limit.")

    readable_strings = extract_readable_strings(data)
    potential_indicators = extract_potential_indicators(
        readable_strings
    )

    findings = {
        "filename": filename,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "file_type": detect_file_type(data),
        "entropy": calculate_entropy(data),
        "pe_metadata": None,
        "readable_strings": readable_strings,
        "potential_indicators": potential_indicators,
        "limitations": [
            "Static indicators alone cannot prove that a file is malicious.",
            "High entropy can occur in compressed or encrypted files.",
            "String extraction currently focuses on printable ASCII.",
            "Extracted IPs, domains and URLs are candidates, not verified threats.",
            "The file was not executed.",
        ],
    }

    # Inspect PE metadata only when the file looks like a PE candidate.
    if data.startswith(b"MZ"):
        try:
            import pefile

            pe = pefile.PE(data=data, fast_load=True)

            try:
                findings["pe_metadata"] = {
                    "machine": hex(pe.FILE_HEADER.Machine),
                    "number_of_sections": (
                        pe.FILE_HEADER.NumberOfSections
                    ),
                    "entry_point": hex(
                        pe.OPTIONAL_HEADER.AddressOfEntryPoint
                    ),
                }
            finally:
                pe.close()

        except Exception:
            findings["pe_metadata"] = {
                "error": "PE metadata could not be parsed."
            }

    return findings

