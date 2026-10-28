
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen2.5:1.5b"


def generate_explanation(prompt: str) -> str:
    """Generate an explanation using the local Ollama model."""

    if not isinstance(prompt, str):
        raise TypeError("Prompt must be a string.")

    if not prompt.strip():
        raise ValueError("Prompt cannot be empty.")

    if len(prompt) > 10_000:
        raise ValueError("Prompt exceeds the 10,000-character limit.")

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "options": {
    
        "temperature": 0,
        }
    }

    response = requests.post(
        OLLAMA_URL,
        json=payload,
        timeout=120,
    )
    response.raise_for_status()

    result = response.json()
    explanation = result.get("response", "").strip()

    if not explanation:
        raise RuntimeError("Ollama returned an empty response.")

    return explanation
