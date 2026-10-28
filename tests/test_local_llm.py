
import pytest

from agents.local_llm import generate_explanation


def test_reject_non_string_prompt():
    with pytest.raises(TypeError, match="string"):
        generate_explanation(None)


def test_reject_empty_prompt():
    with pytest.raises(ValueError, match="empty"):
        generate_explanation("   ")


def test_reject_oversized_prompt():
    with pytest.raises(ValueError, match="10,000"):
        generate_explanation("A" * 10_001)

