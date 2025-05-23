import os
import re
from backend.logging_config import logger
from backend.loader import *

KEYWORD_IOC_FILE = load_keyword_ioc_mapping()

def get_apt_groups(mitre_data):
    apt_id_map = {}
    alias_map = {}

    for obj in mitre_data["objects"]:
        if obj["type"] == "intrusion-set":
            name = obj.get("name", "")
            apt_id = obj.get("id", "")
            apt_id_map[name] = apt_id

            # Store all aliases pointing to the primary name
            aliases = obj.get("aliases", [])
            for alias in aliases:
                alias_map[alias.lower()] = name.lower()  # case-insensitive mapping
            alias_map[name.lower()] = name.lower()  # include canonical name as its own alias

    return apt_id_map, alias_map

def get_apt_techniques(mitre_data, apt_id):
    return [obj["target_ref"] for obj in mitre_data["objects"] if obj["type"] == "relationship" and obj["relationship_type"] == "uses" and obj["source_ref"] == apt_id]

def get_tactics_for_apt(mitre_data, apt_techniques, selected_tactics):
    techniques = {tactic: [] for tactic in selected_tactics}
    tcode_descriptions = {}

    for obj in mitre_data["objects"]:
        if obj["type"] == "attack-pattern" and obj["id"] in apt_techniques:
            t_code = obj["external_references"][0]["external_id"]
            description = obj.get("description", "No description available.")

            if "kill_chain_phases" in obj:
                for phase in obj["kill_chain_phases"]:
                    if phase["phase_name"] in selected_tactics:
                        techniques[phase["phase_name"]].append(t_code)
                        tcode_descriptions[t_code] = description

    return techniques, tcode_descriptions

def get_apt_groups_for_graph(mitre_data):
    apt_groups = {}

    for obj in mitre_data["objects"]:
        if obj["type"] == "intrusion-set":
            apt_name = obj["name"]
            apt_id = obj["id"]  # Store APT ID for mapping
            apt_groups[apt_name] = {"id": apt_id, "techniques": {}}  # Technique dictionary

    # Link techniques to APTs
    for obj in mitre_data["objects"]:
        if obj["type"] == "relationship" and obj["relationship_type"] == "uses":
            source_ref = obj["source_ref"]
            target_ref = obj["target_ref"]

            # Find the APT name that corresponds to source_ref
            for apt_name, apt_data in apt_groups.items():
                if apt_data["id"] == source_ref:
                    for technique_obj in mitre_data["objects"]:
                        if technique_obj["id"] == target_ref and technique_obj["type"] == "attack-pattern":
                            tcode = None
                            for ref in technique_obj.get("external_references", []):
                                if ref.get("source_name") == "mitre-attack" and "external_id" in ref:
                                    tcode = ref["external_id"]  # Extract T-Code

                            if not tcode:
                                continue

                            tactic = technique_obj["kill_chain_phases"][0]["phase_name"] if "kill_chain_phases" in technique_obj else "Unknown"
                            iom = technique_obj["description"].split("\n")[0] if "description" in technique_obj else "No IoM"

                            apt_groups[apt_name]["techniques"][tcode] = {"tactic": tactic, "iom": iom}

    return {apt: data["techniques"] for apt, data in apt_groups.items()}

def get_apt_report(selected_apts, selected_tactics, include_desc, selected_datasets, include_mitre_detections=False):
    mitre_data, dataset_mapping = load_mitre_data(selected_datasets)
    if not mitre_data:
        return None

    apt_groups, _ = get_apt_groups(mitre_data)
    output_data = []
    data_components = {}

    logger.info(f"Searching for APTs: {selected_apts}")
    logger.info(f"Filtering by tactics: {selected_tactics}")
    logger.info(f"Include T-Code Descriptions: {include_desc}")

    for apt in selected_apts:
        apt_data = load_apt_json(apt, selected_datasets)
        if not apt_data:
            logger.warning(f"No JSON file found for {apt}, skipping.")
            continue

        apt_id = apt_groups.get(apt)
        apt_techniques = get_apt_techniques(mitre_data, apt_id) if apt_id else []
        techniques, tcode_descriptions = get_tactics_for_apt(mitre_data, apt_techniques, selected_tactics)

        if not any(techniques.values()):
            output_data.append([apt, "No Mapped Techniques", "", "Unknown Dataset", "", "", ""])
            continue

        for category, t_codes in techniques.items():
            for t_code in t_codes:
                dataset_source = dataset_mapping.get(t_code, "Unknown Dataset")

                tcode_description = next(
                    (t["comment"] for t in apt_data.get("techniques", []) if t["techniqueID"] == t_code),
                    None
                ) if include_desc else ""

                if not tcode_description:
                    tcode_description = tcode_descriptions.get(t_code, "No description available.")

                # Match IOCs Based on Keywords in Description
                matched_iocs = []
                matched_tools = []
                ioc_entries = []
                KEYWORD_IOC_FILE = load_keyword_ioc_mapping()
                for keyword, ioc_data in KEYWORD_IOC_FILE.items():
                    if re.search(rf"\b{keyword}\b(?!://)", tcode_description, re.IGNORECASE):
                        for ioc in ioc_data["ioc"]:
                            ioc_entries.append(f"({keyword}) {ioc}")
                        if isinstance(ioc_data["ioc"], list):
                            matched_iocs.extend(ioc_data["ioc"])
                        else:
                            matched_iocs.append(ioc_data["ioc"])

                        matched_tools.extend(ioc_data["tools"])
                
                #Extract data components for radar graph
                for obj in mitre_data["objects"]:
                    if obj["type"] == "attack-pattern" and "external_references" in obj:
                        for ref in obj["external_references"]:
                            if ref.get("external_id") == t_code:  # Match the correct technique
                                comp = obj.get("x_mitre_data_sources", [])
                                data_components[t_code] = comp


                if include_mitre_detections:
                    mitre_detection_entries = []
                    if include_mitre_detections:
                        for obj in mitre_data["objects"]:
                            if obj["type"] == "attack-pattern" and "external_references" in obj:
                                for ref in obj["external_references"]:
                                    if ref.get("external_id") == t_code:  # Match the correct technique
                                        detection_description = obj.get("x_mitre_detection", "No detection description available.")

                                        mitre_detection_set = set()

                                        detection_description = obj.get("x_mitre_detection", "No detection description available.")

                                        if detection_description and detection_description != "No detection description available.":
                                            mitre_detection_set.add(detection_description)

                                        mitre_detection_entries = list(mitre_detection_set)
                                        break

                ioc_string = ", ".join(ioc_entries) if ioc_entries else "No IOCs Found"
                tool_string = ", ".join(set(matched_tools)) if matched_tools else "Unknown Tool"

                row = [
                    apt,
                    category,
                    t_code,
                    dataset_source,
                    tcode_description,
                    ioc_string,
                    tool_string,
                    ", ".join(mitre_detection_entries) if include_mitre_detections and mitre_detection_entries else "No MITRE Detections"
                ]

                output_data.append(row)

    return output_data, data_components

def get_limited_apt_report(selected_apts, selected_tactics, selected_datasets):
    mitre_data, dataset_mapping = load_mitre_data_cached(True, False, False)
    if not mitre_data:
        return None

    apt_groups, _ = get_apt_groups(mitre_data)
    output_data = []
    data_components = {}

    logger.info(f"Searching for APTs: {selected_apts}")
    logger.info(f"Filtering by tactics: {selected_tactics}")

    for apt in selected_apts:
        apt_data = load_apt_json(apt, selected_datasets)
        if not apt_data:
            logger.warning(f"No JSON file found for {apt}, skipping.")
            continue

        apt_id = apt_groups.get(apt)
        apt_techniques = get_apt_techniques(mitre_data, apt_id) if apt_id else []
        techniques, _ = get_tactics_for_apt(mitre_data, apt_techniques, selected_tactics)

        if not any(techniques.values()):
            output_data.append([apt, "No Mapped Techniques", "", "Unknown Dataset", "", "", ""])
            continue

        for category, t_codes in techniques.items():
            for t_code in t_codes:
                
                #Extract data components for radar graph
                for obj in mitre_data["objects"]:
                    if obj["type"] == "attack-pattern" and "external_references" in obj:
                        for ref in obj["external_references"]:
                            if ref.get("external_id") == t_code:  # Match the correct technique
                                comp = obj.get("x_mitre_data_sources", [])
                                data_components[t_code] = comp

                row = [
                    apt,
                    category,
                    t_code]
                
                output_data.append(row)

    return output_data, data_components
