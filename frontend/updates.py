from PyQt6.QtWidgets import QListWidget, QMessageBox, QTableWidgetItem
from backend.loader import load_mitre_data, load_keyword_ioc_mapping
from backend.processor import get_apt_groups, get_apt_report

def update_listbox(use_enterprise, use_mobile, use_ics, apt_listbox, search_var):
    global apt_groups
    selected_datasets = {
        "enterprise": use_enterprise.isChecked(),
        "mobile": use_mobile.isChecked(),
        "ics": use_ics.isChecked()
    }

    mitre_data, _ = load_mitre_data(selected_datasets)
    apt_groups = get_apt_groups(mitre_data) if mitre_data else {}

    apt_listbox.clear()
    search_term = search_var.text().lower()
    
    for apt in sorted(apt_groups.keys()):
        if search_term in apt.lower():
            apt_listbox.addItem(apt)

def refresh_data(apt_listbox, tactic_listbox, TACTIC_MAPPING, include_description, include_detections, use_enterprise, use_mobile, use_ics, tree):
    global KEYWORD_IOC_MAPPING
    
    KEYWORD_IOC_MAPPING = load_keyword_ioc_mapping()
    
    selected_apts = [apt_listbox.item(i).text() for i in range(apt_listbox.count()) if apt_listbox.item(i).isSelected()]
    selected_display_tactics = [tactic_listbox.item(i).text() for i in range(tactic_listbox.count()) if tactic_listbox.item(i).isSelected()]
    
    if not selected_apts or not selected_display_tactics:
        QMessageBox.critical(None, "Error", "Please select at least one APT and one tactic before refreshing.")
        return

    selected_tactics = [TACTIC_MAPPING[tactic] for tactic in selected_display_tactics]
    include_desc = include_description.isChecked()
    include_mitre_detections = include_detections.isChecked()

    selected_datasets = {
        "enterprise": use_enterprise.isChecked(),
        "mobile": use_mobile.isChecked(),
        "ics": use_ics.isChecked()
    }

    if not any(selected_datasets.values()):
        QMessageBox.critical(None, "Error", "Please select at least one dataset before refreshing.")
        return

    output_data = get_apt_report(
        selected_apts,
        selected_tactics,
        include_desc,
        selected_datasets,
        include_mitre_detections
    )

    if not output_data:
        QMessageBox.critical(None, "Error", "No data retrieved. Check the JSON file or tactic mappings.")
        return
    
    tree.setRowCount(0)
    for data in output_data:
        row_position = tree.rowCount()
        tree.insertRow(row_position)
        for col, value in enumerate(data):
            tree.setItem(row_position, col, QTableWidgetItem(str(value)))
    
    QMessageBox.information(None, "Success", "Mappings refreshed! The report has been updated.")