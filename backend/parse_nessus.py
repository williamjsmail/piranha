import json
import xml.etree.ElementTree as ET
from backend.logging_config import logger

def parse_nessus_xml(xml_file):
    """Extract CVEs and CVSS scores from a Nessus scan."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        cve_data = {}
        for report_item in root.findall(".//ReportItem"):
            cve_tag = report_item.find("cvss_score_source")
            score_tag = report_item.find("cvss3_base_score")

            if cve_tag is not None and score_tag is not None:
                cve = cve_tag.text.strip()
                cvss_score = float(score_tag.text.strip())

                cve_data[cve] = cvss_score

        return cve_data

    except Exception as e:
        logger.error(f"XML Parsing failed - {e}")
        return {}
    
def map_cve_to_tcodes(cve_data, jsonl_file="backend/files/cve-2023.jsonl"):
    """Map CVEs to MITRE ATT&CK techniques using stored mappings."""
    cve_tcode_map = {}

    with open(jsonl_file, "r") as f:
        for line in f:
            data = json.loads(line.strip())
            for cve, mappings in data.items():
                if cve in cve_data:
                    cve_tcode_map[cve] = {
                        "cvss_score": cve_data[cve],
                        "techniques": mappings.get("TECHNIQUES", [])
                    }

    return cve_tcode_map

def filter_relevant_tcodes(cve_tcode_map, selected_apts, selected_tactics):
    """Filter extracted T-Codes based on selected APTs and tactics in Piranha."""
    print("DEBUG DEBUG DEBUG")
    filtered_data = []
    additional_data = []

    for cve, data in cve_tcode_map.items():
        for tcode in data["techniques"]:
            if tcode in selected_tactics:
                filtered_data.append({
                    "technique": tcode,
                    "cvss_score": data["cvss_score"],
                    "associated_cve": cve,
                    "used_by_apts": list(selected_apts)
                })
            else:
                additional_data.append({
                    "technique": tcode,
                    "associated_cve": cve
                })
    print(f"Additional CVEs: {additional_data}")
    return filtered_data
