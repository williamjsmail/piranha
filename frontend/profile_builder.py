from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QListWidget, QListWidgetItem,
    QLineEdit, QTextEdit, QPushButton, QSpinBox, QFileDialog, QFormLayout, QSizePolicy,
    QMessageBox, QGroupBox
)
from PyQt6.QtCore import Qt
import json
import uuid
import os
from backend.loader import load_mitre_data, load_tcodes_for_cve
from backend.processor import get_apt_groups, get_limited_apt_report
from backend.logging_config import logger

TACTIC_MAPPING = {
    "Reconnaissance": "reconnaissance",
    "Resource Development": "resource-development",
    "Initial Access": "initial-access",
    "Execution": "execution",
    "Persistence": "persistence",
    "Privilege Escalation": "privilege-escalation",
    "Defense Evasion": "defense-evasion",
    "Credential Access": "credential-access",
    "Discovery": "discovery",
    "Lateral Movement": "lateral-movement",
    "Collection": "collection",
    "Command and Control": "command-and-control",
    "Exfiltration": "exfiltration",
    "Impact": "impact"
}

class ThreatProfileBuilder(QWidget):
    def __init__(self, tactic_list):
        super().__init__()
        self.tactics = tactic_list
        self.init_ui()

    def load_apts(self):
        selected_datasets = {"enterprise": True}
        self.mitre_data, _ = load_mitre_data(selected_datasets)
        if self.mitre_data is None:
            logger.error("MITRE data is empty. Check dataset paths and JSON format.")
            return
        self.apt_groups, alias_map = get_apt_groups(self.mitre_data)
        self.apt_alias_map = {}
        for alias, canonical in alias_map.items():
            self.apt_alias_map.setdefault(canonical, []).append(alias)
        self.apt_list_widget.clear()
        for apt in sorted(self.apt_groups.keys()):
            self.apt_list_widget.addItem(apt)
    
    def load_tactics(self):
        tactics = [
            "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
            "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
            "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"
        ]
        self.tactic_listbox.clear()
        for tactic in tactics:
            self.tactic_listbox.addItem(tactic)

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(20, 20, 20, 20)

        # Top controls (Profile Details)
        top_bar = QFormLayout()
        self.profile_name_input = QLineEdit()
        top_bar.addRow("Profile Name:", self.profile_name_input)
        self.author_name_input = QLineEdit()
        top_bar.addRow("Author Name:", self.author_name_input)
        self.description_input = QLineEdit()
        top_bar.addRow("Profile Description:", self.description_input)

        # Main layout
        main_layout = QHBoxLayout()

        # Left: APT and tactic selection
        left_layout = QVBoxLayout()
        self.apt_list_widget = QListWidget()
        self.apt_list_widget.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        self.apt_list_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.load_apts()
        self.tactic_listbox = QListWidget()
        self.tactic_listbox.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        self.tactic_listbox.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.load_tactics()
        left_layout.addWidget(QLabel("APT Groups"))
        left_layout.addWidget(self.apt_list_widget)
        left_layout.addWidget(QLabel("Tactics"))
        left_layout.addWidget(self.tactic_listbox)
        apt_tactics_group = QGroupBox("APT and Tactics")
        apt_tactics_group.setLayout(left_layout)

        # Right: CVEs, techniques
        right_layout = QVBoxLayout()
        cve_label = QLabel("CVEs Related to Profile")
        self.custom_cve_textbox = QTextEdit()
        self.custom_cve_textbox.setPlaceholderText("Example:\nCVE-2025-12345\nCVE-2023-54321")
        self.custom_cve_textbox.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        add_tech_label = QLabel("Specific Techniques Related to Profile")
        self.add_tech_textbox = QTextEdit()
        self.add_tech_textbox.setPlaceholderText("Example:\nT1133\nT1114.002")
        self.add_tech_textbox.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        import_btn = QPushButton("Import Barracuda JSON")
        import_btn.clicked.connect(self.import_json_tcodes)
        right_layout.addWidget(cve_label)
        right_layout.addWidget(self.custom_cve_textbox)
        right_layout.addWidget(add_tech_label)
        right_layout.addWidget(self.add_tech_textbox)
        right_layout.addWidget(import_btn)
        cve_tech_group = QGroupBox("CVEs and Techniques")
        cve_tech_group.setLayout(right_layout)

        # Add group boxes to main layout
        main_layout.addWidget(apt_tactics_group)
        main_layout.addWidget(cve_tech_group)

        # Bottom: Action buttons
        bottom_layout = QHBoxLayout()
        save_profile_btn = QPushButton("Save Profile")
        save_profile_btn.setObjectName("save_profile_btn")
        save_profile_btn.clicked.connect(self.save_profile)
        load_profile_btn = QPushButton("Edit Existing Profile")
        load_profile_btn.clicked.connect(self.load_profile_for_editing)
        clear_btn = QPushButton("Clear Profile")
        clear_btn.clicked.connect(self.clear_form)
        bottom_layout.addWidget(save_profile_btn)
        bottom_layout.addWidget(load_profile_btn)
        bottom_layout.addWidget(clear_btn)

        # Assemble panels
        layout.addLayout(top_bar)
        layout.addLayout(main_layout)
        layout.addLayout(bottom_layout)
        self.setLayout(layout)

    def save_profile(self):
        profile_name = self.profile_name_input.text().strip()
        author = self.author_name_input.text().strip()
        description = self.description_input.text().strip()
        if hasattr(self, "original_version"):
            try:
                major, minor = map(int, self.original_version.split("."))
                new_version = f"{major}.{minor + 1}"
            except:
                new_version = "1.1"
        else:
            new_version = "1.0"
        if not profile_name or not author:
            QMessageBox.warning(self, "Missing Info", "Profile name and author are required.")
            return
        apts = [item.text() for item in self.apt_list_widget.selectedItems()]
        tactics = [item.text() for item in self.tactic_listbox.selectedItems()]
        raw_cves = self.custom_cve_textbox.toPlainText().splitlines()
        cves = [line.split(',')[0].strip() for line in raw_cves if line.strip().startswith("CVE")]
        raw_techniques = self.add_tech_textbox.toPlainText().splitlines()
        additional_techniques = [line.strip() for line in raw_techniques if line.strip()]
        all_techniques_set = set()
        for cve in cves:
            tcodes = load_tcodes_for_cve(cve)
            for t in tcodes:
                tcode = f"T{t.strip()}" if not t.strip().startswith("T") else t.strip()
                all_techniques_set.add(tcode)
        for t in additional_techniques:
            all_techniques_set.add(t.strip())
        try:
            internal_tactics = [TACTIC_MAPPING[t] for t in tactics if t in TACTIC_MAPPING]
            report_data, _ = get_limited_apt_report(apts, internal_tactics, {"enterprise": True})
            if report_data:
                for row in report_data:
                    if len(row) >= 3:
                        tcode = row[2].strip()
                        if tcode:
                            all_techniques_set.add(tcode)
        except Exception as e:
            logger.error(f"Error generating techniques from APT/tactics: {e}")
        all_techniques = sorted(all_techniques_set)
        profile_data = {
            "profile_name": profile_name,
            "guid": getattr(self, "current_guid", str(uuid.uuid4())),
            "description": description,
            "created_by": author,
            "version": new_version,
            "apts": apts,
            "tactics": tactics,
            "cves": cves,
            "additional_techniques": additional_techniques,
            "all_techniques": all_techniques
        }
        save_path, _ = QFileDialog.getSaveFileName(self, "Save Profile", f"{profile_name}.pir", "Piranha Profile (*.pir)")
        if save_path:
            try:
                with open(save_path, "w") as f:
                    json.dump(profile_data, f, indent=2)
                QMessageBox.information(self, "Success", f"Profile saved to {os.path.basename(save_path)}.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save file:\n{e}")
    
    def load_profile_for_editing(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Profile to Edit", "", "Piranha Profile (*.pir)")
        if not file_path:
            return
        try:
            with open(file_path, "r") as f:
                profile = json.load(f)
            self.current_profile_path = file_path
            self.profile_name_input.setText(profile.get("profile_name", ""))
            self.author_name_input.setText(profile.get("created_by", ""))
            self.description_input.setText(profile.get("description", ""))
            apts = set(profile.get("apts", []))
            for i in range(self.apt_list_widget.count()):
                item = self.apt_list_widget.item(i)
                item.setSelected(item.text() in apts)
            tactics = set(profile.get("tactics", []))
            for i in range(self.tactic_listbox.count()):
                item = self.tactic_listbox.item(i)
                item.setSelected(item.text() in tactics)
            cves = profile.get("cves", [])
            self.custom_cve_textbox.setPlainText("\n".join(cves))
            techniques = profile.get("additional_techniques", [])
            self.add_tech_textbox.setPlainText("\n".join(techniques))
            self.original_version = profile.get("version", "1.0")
            self.current_guid = profile.get("guid", str(uuid.uuid4()))
            QMessageBox.information(self, "Profile Loaded", f"Loaded profile: {profile.get('profile_name', 'Unnamed')}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load profile: {e}")

    def clear_form(self):
        confirm = QMessageBox.question(
            self,
            "Confirm Clear",
            "Are you sure you want to clear this profile?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            self.profile_name_input.clear()
            self.author_name_input.clear()
            self.description_input.clear()
            for i in range(self.apt_list_widget.count()):
                self.apt_list_widget.item(i).setSelected(False)
            for i in range(self.tactic_listbox.count()):
                self.tactic_listbox.item(i).setSelected(False)
            self.custom_cve_textbox.clear()
            self.add_tech_textbox.clear()
    
    def import_json_tcodes(self):
        file_paths, _ = QFileDialog.getOpenFileNames(self, "Import Barracuda JSON File(s)", "", "JSON Files (*.json)")
        if not file_paths:
            return
        imported_tcodes = set()
        for path in file_paths:
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                    if "tcode_to_sentences" in data:
                        imported_tcodes.update(data["tcode_to_sentences"].keys())
                    else:
                        QMessageBox.warning(self, "Format Issue", f"File {os.path.basename(path)} does not contain 'tcode_to_sentences'.")
            except Exception as e:
                QMessageBox.critical(self, "Import Failed", f"Error importing {os.path.basename(path)}:\n{str(e)}")
        if imported_tcodes:
            existing_text = self.add_tech_textbox.toPlainText().strip()
            existing_set = set(existing_text.splitlines())
            combined = sorted(existing_set.union(imported_tcodes))
            self.add_tech_textbox.setPlainText("\n".join(combined))
            QMessageBox.information(self, "Import Successful", f"Imported {len(imported_tcodes)} T-Codes from {len(file_paths)} file(s).")