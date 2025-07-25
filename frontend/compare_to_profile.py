from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QListWidget, QListWidgetItem, QFileDialog, QTextEdit, QMessageBox, QCheckBox, QGroupBox
)
import os
import json
from backend.loader import load_tcodes_for_cve

class CompareToProfileTab(QWidget):
    def __init__(self, get_current_cves_func):
        super().__init__()
        self.get_current_cves_func = get_current_cves_func
        self.last_loaded_profile = None
        self.init_ui()

    def init_ui(self):
        # Main layout with spacing and margins for better breathing room
        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(20, 20, 20, 20)

        # Instructions with slightly larger font for prominence
        instructions = QLabel("Compare imported Nessus scan to one or more threat profiles:")
        instructions.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(instructions)

        # Horizontal split for profile list and preview
        main_split = QHBoxLayout()
        main_split.setSpacing(20)

        # === LEFT: Profile list in a group box ===
        profile_group = QGroupBox("Loaded Profiles")
        profile_layout = QVBoxLayout()
        self.profile_list = QListWidget()
        self.profile_list.setMinimumWidth(250)
        self.profile_list.setMinimumHeight(300)
        self.profile_list.itemClicked.connect(self.preview_profile)
        profile_layout.addWidget(self.profile_list)
        profile_group.setLayout(profile_layout)
        main_split.addWidget(profile_group)

        # === RIGHT: Profile preview + toggle in a group box ===
        right_layout = QVBoxLayout()
        toggle_layout = QHBoxLayout()
        toggle_label = QLabel("View Mode:")
        self.view_toggle = QCheckBox("Pretty View")
        self.view_toggle.setChecked(True)
        self.view_toggle.stateChanged.connect(self.toggle_profile_view)
        toggle_layout.addWidget(toggle_label)
        toggle_layout.addWidget(self.view_toggle)
        toggle_layout.addStretch()
        right_layout.addLayout(toggle_layout)
        self.profile_preview_box = QTextEdit()
        self.profile_preview_box.setReadOnly(True)
        self.profile_preview_box.setMinimumHeight(300)
        right_layout.addWidget(self.profile_preview_box)
        preview_group = QGroupBox("Profile Preview")
        preview_group.setLayout(right_layout)
        main_split.addWidget(preview_group)

        layout.addLayout(main_split)

        # Buttons with some spacing
        load_btn = QPushButton("Load .pir Profiles")
        load_btn.clicked.connect(self.load_profiles)
        layout.addWidget(load_btn)

        compare_btn = QPushButton("Compare to Nessus Scan")
        compare_btn.clicked.connect(self.run_comparison)
        layout.addWidget(compare_btn)

        # Results box
        self.results_box = QTextEdit()
        self.results_box.setReadOnly(True)
        self.results_box.setMinimumHeight(200)
        layout.addWidget(self.results_box)

        self.setLayout(layout)

        # Set a reasonable minimum size for the widget
        self.setMinimumSize(1000, 800)

    def load_profiles(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select .pir Profiles", "", "Threat Profiles (*.pir)")
        if files:
            self.profile_list.clear()
            for path in files:
                item = QListWidgetItem(os.path.basename(path))
                item.setData(1000, path)
                self.profile_list.addItem(item)

    def run_comparison(self):
        scan_cves = set(self.get_current_cves_func())
        if not scan_cves:
            QMessageBox.warning(self, "No CVEs", "You must load a Nessus scan first.")
            return

        # Build technique set from scan CVEs
        scan_techniques = set()
        for cve in scan_cves:
            try:
                tcodes = load_tcodes_for_cve(cve)
                for t in tcodes:
                    if t.strip():
                        norm_t = f"T{t.strip()}" if not t.strip().startswith("T") else t.strip()
                        scan_techniques.add(norm_t)
            except Exception as e:
                print(f"Error loading techniques for {cve}: {e}")
        if not scan_techniques:
            self.results_box.setText("No techniques mapped from current scan CVEs.")
            return

        results = []
        for i in range(self.profile_list.count()):
            item = self.profile_list.item(i)
            profile_path = item.data(1000)
            try:
                with open(profile_path, "r") as f:
                    profile = json.load(f)
            except Exception as e:
                results.append(f"{item.text()}: Error reading profile - {e}\n\n")
                continue

            profile_name = profile.get("profile_name", item.text())
            profile_techs = set(profile.get("all_techniques", []))
            profile_techs = {t.strip() for t in profile_techs if t.strip().startswith("T")}
            profile_cves = set(profile.get("cves", []))

            if not profile_techs:
                results.append(f"{profile_name}: No techniques in profile.\n")
                continue

            matches = scan_techniques.intersection(profile_techs)
            cve_matches = scan_cves.intersection(profile_cves)

            precision = len(matches) / len(scan_techniques) if scan_techniques else 0
            recall = len(matches) / len(profile_techs) if profile_techs else 0
            f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0

            results.append(
                f"{profile_name}\n"
                f"F1: {f1_score:.3f}\n"
                f"Precision: {precision * 100:.1f}%\n"
                f"Recall: {recall * 100:.1f}%\n"
            )
            results.append(f"\u2192 Matched CVEs: {', '.join(sorted(cve_matches))}\n")
            results.append(f"\u2192 Matched T-Codes: {', '.join(sorted(matches))}\n\n")

        self.results_box.setText("".join(results))

    def preview_profile(self, item):
        path = item.data(1000)
        try:
            with open(path, "r") as f:
                profile_data = json.load(f)
            self.last_loaded_profile = profile_data
            self.toggle_profile_view()
        except Exception as e:
            self.profile_preview_box.setText(f"Error loading profile: {e}")

    def toggle_profile_view(self):
        if not self.last_loaded_profile:
            return

        if self.view_toggle.isChecked():
            self.display_pretty_profile(self.last_loaded_profile)
        else:
            self.display_raw_profile(self.last_loaded_profile)

    def display_pretty_profile(self, profile):
        lines = []
        lines.append(f"<b style='font-size:20px'> {profile.get('profile_name', 'Unnamed')}</b>")
        lines.append(f"📝<b>Author: {profile.get('created_by', '-')}</b>")
        lines.append(f"{profile.get('description', '')}<br><br>")
        lines.append("🎯<b>APTs:</b><br>" + "<br>".join(f"• {apt}" for apt in profile.get('apts', [])))
        lines.append("<br>📊<b>Tactics:</b><br>" + "<br>".join(f"• {t}" for t in profile.get('tactics', [])))
        lines.append("<br>📎<b>CVEs:</b><br>" + "<br>".join(f"• {cve}" for cve in profile.get('cves', [])))
        lines.append("<br>🛠️<b>Additional Techniques:</b><br>" + "<br>".join(f"• {t}" for t in profile.get('additional_techniques', [])))
        self.profile_preview_box.setHtml("<br>".join(lines))

    def display_raw_profile(self, profile):
        formatted = json.dumps(profile, indent=2)
        self.profile_preview_box.setPlainText(formatted)