import requests
import json
from datetime import datetime
from tqdm import tqdm
from re import match
import os
import time

API_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
#API_KEY = os.environ.get("NVD_API_KEY")
API_KEY = "75753a25-3a92-494a-a47f-f97196a04b49"
UPDATE_FILE = "lastUpdate.txt"
CVE_FILE = "results/new_cves.jsonl"


def fetch_data_with_retries(session, url, retries=3, delay=6):
    for attempt in range(1, retries + 1):
        response = session.get(url)
        if response.status_code == 200:
            return response
        elif 500 <= response.status_code < 600:
            print(f"[-] Failed to download CVE data (attempt {attempt}/{retries}) - Error:{response.status_code}. Retrying in {delay*attempt}s...")
            time.sleep(delay*attempt)
        else:
            raise Exception(f"Failed to download CVE data after {retries} attempts (status code: {response.status_code})")
    raise Exception(f"Failed to download CVE data after {retries} attempts (status code: {response.status_code})")


# Parse CVE data from the API
def parse_cves(url_base: str):
    cve_data = {}
    session = requests.Session()
    session.headers.update({"apiKey": API_KEY})
    response = fetch_data_with_retries(session, url_base)

    if response.status_code != 200:
        raise Exception("Failed to download CVE data")

    # Get the total number of results and the number of results per page    
    cves = response.json()
    results_per_page = cves.get("resultsPerPage", 0)
    total_results = cves.get("totalResults", 0)

    if results_per_page == 0 or total_results == 0:
        print("[-]No new vulnerabilities found")
        return cve_data
    nb_pages = (total_results + results_per_page - 1) // results_per_page
    
    # Process each page of the API response
    for page in tqdm(range(nb_pages), desc="Fetching pages", unit="Page"):
        url = f"{url_base}&resultsPerPage=2000&startIndex={page * 2000}"
        response = fetch_data_with_retries(session, url)
        if response.status_code != 200:
            raise Exception("Failed to download CVE data")
        cves = response.json()
        for cve in tqdm(cves.get("vulnerabilities", []), desc="Processing CVEs", unit="CVE"):
            has_primary_cwe = False
            cve_id = cve.get("cve", {}).get("id", "")
            cwe_list = []
            infos = cve.get("cve", {}).get("weaknesses", [])
            if infos:
                for cwe in infos:
                    if cwe.get("type", "") == "Primary":  # Get only primary CWE
                            cwe_code = cwe.get("description", [])[0].get("value", "")
                            if match(r"CWE-\d{1,4}", cwe_code):
                                cwe_list.append(cwe_code.split("-")[1])
                                has_primary_cwe = True
                if not has_primary_cwe:
                        for cwe in infos:
                            if cwe.get("type", "") == "Secondary":  # Get only secondary CWE
                                cwe_code = cwe.get("description", [])[0].get("value", "")
                                if match(r"CWE-\d{1,4}", cwe_code):
                                    cwe_list.append(cwe_code.split("-")[1])
                cve_data[cve_id] = {"CWE": cwe_list}
            else:
                cve_data[cve_id] = {"CWE": []}
    return cve_data

# Save CVE data to JSONL file
def save_jsonl(cve_data, today):
    with open(CVE_FILE, 'w') as f:
        for cve, data in cve_data.items():
            f.write(json.dumps({cve: data}) + "\n")
    
    # Update the last update date
    with open(UPDATE_FILE, 'w') as f:
        f.write(today)
    

if __name__ == "__main__":
    # Get the last update date
    today = datetime.now().replace(microsecond=0).isoformat() + "Z"
    last_update = ""
    with open(UPDATE_FILE, 'r') as f:
        last_update = f.read()
    url = f"{API_CVES}?lastModStartDate={last_update}&lastModEndDate={today}"
    print(url)
    cves_data = parse_cves(url)
    save_jsonl(cves_data, today)
