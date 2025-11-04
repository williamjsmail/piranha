import os
import requests
from backend.utils import resource_path

API_KEY_FILE = resource_path("backend\\files\\API\\openai_api.key")

def load_api_key_from_file():
    # ENV var takes precedence if set
    env_key = os.getenv("OPENAI_API_KEY")
    if env_key:
        return env_key.strip()

    if not os.path.exists(API_KEY_FILE):
        print(f" OpenAI API key file not found: {API_KEY_FILE}")
        return None

    try:
        with open(API_KEY_FILE, "r") as f:
            return f.read().strip()
    except Exception as e:
        print(f" Error reading OpenAI API key file: {e}")
        return None


def enrich_data_with_ai(query: str) -> str:
    api_url = "https://api.openai.com/v1/chat/completions"
    bearer_token = load_api_key_from_file()

    if not bearer_token:
        return " OpenAI API Error: Missing API key. Set OPENAI_API_KEY or create backend/files/API/openai_api.key"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {bearer_token}"
    }

    data = {
        "model": "gpt-5",
        "messages": [
            {
                "role": "system",
                "content": "You are Piranha's enrichment assistant. Provide concise, actionable analysis. Include in-text URL citations."
            },
            {
                "role": "user",
                "content": query
            }
        ],
        "max_tokens": 1500,
        "temperature": 0.2
    }

    try:
        response = requests.post(api_url, headers=headers, json=data, timeout=120)
        response.raise_for_status()
        result = response.json()
        return result["choices"][0]["message"]["content"].strip()

    except requests.exceptions.RequestException as e:
        return f" OpenAI API Error: {e}"
    except Exception as e:
        return f" Unexpected error: {e}"
