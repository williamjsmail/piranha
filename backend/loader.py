import os
import json
from backend.logging_config import logger

FILES_DIR = os.path.join(os.path.dirname(__file__), "files")
KEYWORD_IOC_FILE = os.path.join(os.path.dirname(__file__), "files", "KEYWORD_IOC_MAPPING.json")
APT_JSON_DIR = os.path.join(os.path.dirname(__file__), "files", "APT")

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

def load_mitre_data(selected_datasets):
    dataset_files = {
    "enterprise": os.path.join(FILES_DIR, "enterprise-attack.json"),
    "mobile": os.path.join(FILES_DIR, "mobile-attack.json"),
    "ics": os.path.join(FILES_DIR, "ics-attack.json")
    }

    combined_data = {"objects": []}
    dataset_mapping = {}

    for dataset, selected in selected_datasets.items():
        if selected:
            json_path = os.path.join(os.path.dirname(__file__), dataset_files[dataset])
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
                logger.error(f"{dataset_files[dataset]} not found!")

    return combined_data if combined_data["objects"] else None, dataset_mapping