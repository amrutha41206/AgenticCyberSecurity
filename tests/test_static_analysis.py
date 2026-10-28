
import hashlib
import pytest

from agents.static_analysis import (
    analyze_file,
    calculate_entropy,
    detect_file_type,
    extract_readable_strings,
    extract_potential_indicators,
    MAX_FILE_SIZE,
)


def test_detect_empty_file():
    assert detect_file_type(b"") == "Empty file"


def test_detect_pdf_signature():
    assert detect_file_type(b"%PDF-1.7 sample") == "PDF document"


def test_calculate_entropy_for_empty_data():
    assert calculate_entropy(b"") == 0.0


def test_calculate_entropy_for_repeated_bytes():
    assert calculate_entropy(b"A" * 100) == 0.0


def test_extract_readable_strings():
    result = extract_readable_strings(
        b"\x00Hello security test\x00"
    )
    assert "Hello security test" in result


def test_extract_potential_indicators():
    strings = [
        "Visit https://example.com/test",
        "Contact malware-example.test",
        "Address 203.0.113.10",
    ]

    result = extract_potential_indicators(strings)

    assert "https://example.com/test" in result["potential_urls"]
    assert "malware-example.test" in result["potential_domains"]
    assert "203.0.113.10" in result["potential_ips"]


def test_analyze_file_returns_sha256():
    data = b"Safe demonstration content"

    result = analyze_file("demo.txt", data)

    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert result["size_bytes"] == len(data)
    assert result["file_type"] == "Unknown or unrecognized format"


def test_analyze_file_rejects_oversized_data():
    with pytest.raises(ValueError, match="25 MB"):
        analyze_file("large.bin", b"A" * (MAX_FILE_SIZE + 1))
