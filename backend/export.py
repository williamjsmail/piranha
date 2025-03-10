import pandas as pd
from backend.logging_config import logger

def save_to_excel(output_data, file_path, include_desc, include_mitre_detections):
    if not output_data:
        logger.warning("No data to save!")
        return

    columns = ["APT", "Category", "T-Code", "Dataset Source", "IOC", "Detection Tool"]
    if include_desc:
        columns.insert(4, "T-Code Description")

    if include_mitre_detections:
        columns.append("MITRE Detection")

    expected_columns = len(columns)

   
    corrected_data = []
    for row in output_data:
        if len(row) < expected_columns:
            row.extend([""] * (expected_columns - len(row))) 
        elif len(row) > expected_columns:
            row = row[:expected_columns] 
        corrected_data.append(row)

    try:
        df = pd.DataFrame(corrected_data, columns=columns)
        df.to_excel(file_path, index=False, engine='openpyxl')
        logger.info(f"Report successfully saved to {file_path}")
    except Exception as e:
        logger.error(f"Error saving report: {e}")
