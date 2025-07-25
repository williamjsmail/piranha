import os
import requests
from backend.utils import resource_path

#  Define the API key file path
API_KEY_FILE = resource_path("backend\\files\\API\\niprgpt_api.key")

def load_api_key_from_file():
    if not os.path.exists(API_KEY_FILE):
        print(f" API key file not found: {API_KEY_FILE}")
        return None

    try:
        with open(API_KEY_FILE, "r") as f:
            key = f.read().strip()
            return key
    except Exception as e:
        print(f" Error reading API key file: {e}")
        return None


def enrich_data_with_ai(query):
    """Use NIPRGPT API to enrich data based on the provided query."""
    
    api_url = "https://api.niprgpt.mil/v1/chat/completions"
    bearer_token = load_api_key_from_file()

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {bearer_token}"
    }

    data = {
        "model": "Gemini 1.5 Pro",
        "messages": [
            {
                "role": "user",
                "content": query
            }
        ],
        "max_tokens": 1500
    }

    try:
        response = requests.post(api_url, headers=headers, json=data)
        response.raise_for_status()  # Raise an error for bad status codes
        result = response.json()
        return result['choices'][0]['message']['content'].strip()

    except requests.exceptions.RequestException as e:
        return f" NIPRGPT API Error: {e}"

