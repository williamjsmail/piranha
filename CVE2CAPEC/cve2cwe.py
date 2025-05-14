import json
import sys
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

session = requests.Session()
CWE_FILE = "resources/cwe_db.json"
CVE_FILE = "results/new_cves.jsonl"
RETRY_LIMIT = 3  # Retry limit for HTTP requests
MAX_THREADS = 10  # Maximum number of threads for concurrent processing

def get_parent_cwe(cwe: str, cwe_db: dict):
    cwe_list = set()
    try:
        result = cwe_db.get(cwe, {})
        if result.get("ChildOf", []):
            for related_cwe in result["ChildOf"]:
                cwe_list.add(related_cwe)
            return cwe_list
        else:
            return None
    except Exception as e:
        print(f"Exception occurred for CWE-{cwe}: {e}")
    return None

# Process each CVE to extract the related CWE entries
def process_cve_to_cwe(cve_cwe_data, cve_year, cwe_db):
    cwe_list = {}

    def process_single_cve(cve, cwe_db):
        cwe_set = set()  # Use a set to avoid duplicates
        for cwe in cve_cwe_data[cve]['CWE']:
            cwe_set.add(cwe)
            child_cwe = get_parent_cwe(cwe, cwe_db)
            
            # Use queue to process all parent CWEs
            queue = list(child_cwe) if child_cwe else []

            while queue:
                current_cwe = queue.pop(0)
                if current_cwe not in cwe_set: 
                    cwe_set.add(current_cwe)
                    new_children = get_parent_cwe(current_cwe, cwe_db)
                    if new_children:
                        # Add new children to the queue
                        queue.extend(new_children)

        return {cve: {"CWE": list(sorted(cwe_set))}}

    # Process each CVE concurrently
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(process_single_cve, cve, cwe_db): cve for cve in cve_cwe_data}
        for future in tqdm(as_completed(futures), total=len(futures), desc=f"Processing CVEs for CVE-{cve_year}", unit="CVE"):
            cve = futures[future]
            try:
                result = future.result()
                cwe_list.update(result)
            except Exception as exc:
                print(f"CVE {cve} generated an exception: {exc}")

    save_jsonl(cwe_list)


def load_db():
    with open(CWE_FILE, 'r') as f:
        cwe_db = json.load(f)
    return cwe_db


# Save the results to a JSONL file
def save_jsonl(cve_cwe_data):
    with open(CVE_FILE, 'w') as f:
        for cve, data in cve_cwe_data.items():
            f.write(json.dumps({cve: data}) + "\n")


if __name__ == "__main__":
    if len(sys.argv) == 2:
        file = sys.argv[1]
    else:
        file = CVE_FILE

    # Load the JSONL file
    with open(file, 'r') as f:
        cve_cwe_data = {}
        for line in f:
            cve = json.loads(line.strip())
            cve_cwe_data.update(cve)

    if cve_cwe_data:
        cwe_db = load_db()
        
        cve_year = list(cve_cwe_data.keys())[0].split('-')[1]

        process_cve_to_cwe(cve_cwe_data, cve_year, cwe_db)
    else:
        print("[-]No new vulnerabilities found")
