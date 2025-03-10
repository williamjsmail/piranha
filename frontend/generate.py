import matplotlib.pyplot as plt
from PyQt6.QtWidgets import QMessageBox, QFileDialog, QTableWidgetItem
from collections import defaultdict
from backend.processor import get_apt_report
from backend.export import save_to_excel
from backend.logging_config import logger

def generate_mitre_heatmap(output_data):
    if not output_data:
        QMessageBox.critical(None, "Error", "No report data available.")
        return

    tcode_counts = defaultdict(int)
    for row in output_data:
        t_code = row[2]
        tcode_counts[t_code] += 1

    sorted_tcodes = sorted(tcode_counts.items(), key=lambda x: x[1], reverse=True)

    labels, values = zip(*sorted_tcodes)
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.barh(labels, values, color="grey")
    ax.set_xlabel("Usage Count")
    ax.set_title("MITRE ATT&CK Heatmap (Most Used Techniques)")
    plt.show()

def generate_report(apt_listbox, tactic_listbox, TACTIC_MAPPING, include_description, use_enterprise, use_mobile, use_ics, include_detections, tree):
    selected_apts = [apt_listbox.item(i).text() for i in range(apt_listbox.count()) if apt_listbox.item(i).isSelected()]
    selected_display_tactics = [tactic_listbox.item(i).text() for i in range(tactic_listbox.count()) if tactic_listbox.item(i).isSelected()]
    selected_tactics = [TACTIC_MAPPING[tactic] for tactic in selected_display_tactics]
    include_desc = include_description.isChecked()

    selected_datasets = {
        "enterprise": use_enterprise.isChecked(),
        "mobile": use_mobile.isChecked(),
        "ics": use_ics.isChecked()
    }

    logger.info(f"Selected APTs: {selected_apts}")
    logger.info(f"Selected Tactics (Human-readable): {selected_display_tactics}")
    logger.info(f"Converted Tactics (JSON names): {selected_tactics}")
    logger.info(f"Include T-Code Descriptions: {include_desc}")
    logger.info(f"Selected Datasets: {selected_datasets}")

    if not selected_apts:
        QMessageBox.critical(None, "Error", "Please select at least one APT.")
        return
    if not selected_tactics:
        QMessageBox.critical(None, "Error", "Please select at least one tactic.")
        return
    if not any(selected_datasets.values()):
        QMessageBox.critical(None, "Error", "Please select at least one dataset.")
        return

    include_mitre_detections = include_detections.isChecked()
    
    global output_data
    output_data = get_apt_report(
        selected_apts, selected_tactics, include_desc, selected_datasets, include_mitre_detections
    )

    if not output_data:
        logger.error("No data retrieved from backend.")
        QMessageBox.critical(None, "Error", "No data retrieved. Check the JSON file or tactic mappings.")
        return

    tree.setRowCount(0)
    for data in output_data:
        row_position = tree.rowCount()
        tree.insertRow(row_position)
        for col, value in enumerate(data):
            tree.setItem(row_position, col, QTableWidgetItem(str(value)))

def export_to_excel(output_data, include_description, include_detections):
    if not output_data:
        QMessageBox.critical(None, "Error", "No data to export. Generate a report first.")
        return

    file_path, _ = QFileDialog.getSaveFileName(None, "Save Report", "", "Excel Files (*.xlsx);;All Files (*)")

    if file_path:
        include_desc = include_description.isChecked()
        save_to_excel(output_data, file_path, include_desc, include_detections.isChecked())
        QMessageBox.information(None, "Success", f"Data saved to {file_path}")
