import os
import json
from functools import lru_cache
from backend.logging_config import logger
from backend.utils import resource_path

FILES_DIR = resource_path(os.path.join("backend", "files"))
KEYWORD_IOC_FILE = resource_path(os.path.join("backend", "files", "KEYWORD_IOC_MAPPING.json"))
APT_JSON_DIR = resource_path(os.path.join("backend", "files", "APT"))
CVE_TO_TCODE_DIR = resource_path(os.path.join("CVE2CAPEC", "database"))
DATA_COMPONENTS_FILE = resource_path(os.path.join("backend", "files", "DATA_COMPONENTS_MAPPING.json"))

def load_component_json():
    if os.path.exists(DATA_COMPONENTS_FILE):
        try:
            with open(DATA_COMPONENTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"JSON Error in {DATA_COMPONENTS_FILE}: {e}")


    logger.warning(f"No JSON file found for {DATA_COMPONENTS_FILE}. Returning empty list.")
    return {}

def load_apt_json(apt_name, selected_datasets):
    apt_variants = [apt_name]  # Default: Enterprise dataset

    # Append dataset-specific variants (e.g., APT28-ICS, APT28-MOBILE)
    if selected_datasets.get("mobile"):
        apt_variants.append(f"{apt_name}-MOBILE")

    if selected_datasets.get("ics"):
        apt_variants.append(f"{apt_name}-ICS")


    for apt_variant in apt_variants:
        apt_json_file = os.path.join(APT_JSON_DIR, f"{apt_variant}.json")

        if os.path.exists(apt_json_file):
            try:
                with open(apt_json_file, "r", encoding="utf-8") as f:
                    logger.info(f"Loaded APT JSON: {apt_variant}.json")
                    return json.load(f)
            except json.JSONDecodeError as e:
                logger.error(f"JSON Error in {apt_json_file}: {e}")

    logger.warning(f"No JSON file found for {apt_name} across selected datasets. Using global IOC mapping.")
    return {}


def load_keyword_ioc_mapping():
    if os.path.exists(KEYWORD_IOC_FILE):
        try:
            with open(KEYWORD_IOC_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)

                # Ensure all "ioc" values are stored as lists
                for key, value in data.items():
                    if isinstance(value["ioc"], str):
                        data[key]["ioc"] = [value["ioc"]]  # Convert to list if it's a string
                    if isinstance(value["tools"], list):
                        data[key]["tools"] = set(value["tools"])  # Convert tools to a set
                return data
        except json.JSONDecodeError as e:
            logger.error(f"JSON Error in {KEYWORD_IOC_FILE}: {e}")
    logger.warning("No valid keyword-to-IOC mapping found. Using empty dictionary.")
    return {}

@lru_cache(maxsize=None)
def load_mitre_data_cached(enterprise=True, mobile=False, ics=False):
    selected_datasets = {
        "enterprise": enterprise,
        "mobile": mobile,
        "ics": ics
    }
    return load_mitre_data(selected_datasets)

def load_mitre_data(selected_datasets):
    dataset_files = {
        "enterprise": "enterprise-attack.json",
        "mobile": "mobile-attack.json",
        "ics": "ics-attack.json"
    }

    combined_data = {"objects": []}
    dataset_mapping = {}

    for dataset, selected in selected_datasets.items():
        if selected:
            json_path = resource_path(os.path.join("backend", "files", dataset_files[dataset]))
            if os.path.exists(json_path):
                logger.info(f"Loading {dataset_files[dataset]}")
                with open(json_path, "r", encoding="utf-8") as file:
                    data = json.load(file)
                    for obj in data["objects"]:
                        combined_data["objects"].append(obj)
                        if obj["type"] == "attack-pattern" and "external_references" in obj:
                            t_code = obj["external_references"][0]["external_id"]
                            dataset_mapping[t_code] = dataset
            else:
                logger.error(f"{json_path} not found!")

    return combined_data if combined_data["objects"] else None, dataset_mapping


loaded_cve_data = {}


def extract_year_from_cve(cve):
    """Extract the year from a CVE ID (e.g., CVE-2023-1234 -> 2023)."""
    try:
        return cve.split("-")[1]
    except IndexError:
        return None

def load_cve_mappings(year):
    """Load CVE-to-TCode mappings from a given year's JSONL file."""
    file_path = os.path.join(CVE_TO_TCODE_DIR, f"CVE-{year}.jsonl")
    if not os.path.exists(file_path):
        logger.warning(f"CVE data file {file_path} not found.")
        return {}


    cve_data = {}
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                cve_id = list(entry.keys())[0]
                cve_data[cve_id] = entry[cve_id]  # Store mapping
            except json.JSONDecodeError:
                logger.error(f"Failed to parse line in {file_path}")


    logger.info(f"Loaded {len(cve_data)} CVEs from {file_path}")
    return cve_data


def load_tcodes_for_cve(cve):
    """Load T-Codes for a given CVE by checking cached JSONL data."""
    year = extract_year_from_cve(cve)
    if not year:
        logger.warning(f"Could not extract year from {cve}")
        return []


    if year not in loaded_cve_data:
        loaded_cve_data[year] = load_cve_mappings(year)


    cve_entry = loaded_cve_data[year].get(cve, {})


    t_codes = cve_entry.get("TECHNIQUES", [])


    # Normalize Data: Ensure it's always a list of strings
    if isinstance(t_codes, str):
        t_codes = [t_codes]  # Convert single string to list
    elif not isinstance(t_codes, list):
        t_codes = []


    t_codes = [str(t).strip() for t in t_codes]  # Ensure consistent formatting
    return t_codes
