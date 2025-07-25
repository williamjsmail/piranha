import os
from PyQt6.QtCore import QThread, pyqtSignal
from openai import OpenAI


#  Define the API key file path
API_KEY_FILE = os.path.join(os.path.dirname(__file__), "files", "API", "openai_api.key")


def load_api_key_from_file():
    """Load the OpenAI API key from 'files/API/openai_api.key'."""
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
    """Use OpenAI API to enrich data based on the provided query."""
    api_key = load_api_key_from_file()  #  Load the API key from the file


    if not api_key:
        return f" OpenAI API key is missing. Ensure the file '{API_KEY_FILE}' exists and contains a valid key."


    client = OpenAI(api_key=api_key)


    try:
        completion = client.chat.completions.create(
            model="gpt-4o-search-preview",
            max_tokens=1000,
            messages=[{"role": "user", "content": query}]
        )
        return completion.choices[0].message.content.strip()


    except Exception as e:
        return f" OpenAI API Error: {e}"


class AIEnrichmentThread(QThread):
    """Runs OpenAI API queries in a separate thread and sends results back to the UI."""
    result_ready = pyqtSignal(str, str)  #  Send (APT name, AI response) to the main thread


    def __init__(self, apt_name, tactic_name, technique):
        super().__init__()
        self.apt_name = apt_name
        self.tactic_name = tactic_name
        self.technique = technique


    def run(self):
        """Run the OpenAI API query in a separate thread and send results back."""
        query = (f"Generate a comprehensive report on how {self.apt_name} uses the {self.tactic_name} technique {self.technique}, including attack methods, indicators of compromise, and detection strategies.")
        print(f" AI Query: {query}")  #  Debugging


        enrichment_result = enrich_data_with_ai(query)  #  Call AI enrichment function


        self.result_ready.emit(self.apt_name, enrichment_result)  #  Send data to the main thread
