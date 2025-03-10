import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QCheckBox, QLineEdit, QListWidget, QTableWidget, QHeaderView, 
    QSizePolicy, QMenu
)
from PyQt6.QtGui import QAction
from PyQt6.QtCore import Qt

# Import your modules
from frontend.generate import generate_mitre_heatmap, generate_report, export_to_excel
from frontend.keywords import *
from frontend.selection import *
from frontend.updates import *
from backend.loader import load_mitre_data
from backend.processor import get_apt_groups

class PiranhaApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Piranha v3.0.0")
        self.setGeometry(100, 100, 950, 750)

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)

        # Header
        header_label = QLabel("Piranha T-Code Mapper")
        header_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        main_layout.addWidget(header_label, alignment=Qt.AlignmentFlag.AlignCenter)

        sub_label = QLabel("v3.0.0, Dev/POC: Sgt Smail, William J")
        sub_label.setStyleSheet("font-size: 10px;")
        main_layout.addWidget(sub_label, alignment=Qt.AlignmentFlag.AlignCenter)

        # Selection frame
        selection_layout = QHBoxLayout()
        main_layout.addLayout(selection_layout)

        # APT Frame
        apt_layout = QVBoxLayout()
        selection_layout.addLayout(apt_layout)
        
        apt_label = QLabel("Select APT(s):")
        apt_layout.addWidget(apt_label)

        self.apt_listbox = QListWidget()
        self.apt_listbox.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        apt_layout.addWidget(self.apt_listbox)

        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText("Search...")
        apt_layout.addWidget(self.search_entry)
        
        # Dataset selection checkboxes
        dataset_layout = QHBoxLayout()
        main_layout.addLayout(dataset_layout)

        self.use_enterprise = QCheckBox("Enterprise ATT&CK")
        self.use_mobile = QCheckBox("Mobile ATT&CK")
        self.use_ics = QCheckBox("ICS ATT&CK")
        self.include_descriptions = QCheckBox("APT Specific Descriptions")
        self.include_detections = QCheckBox("Include MITRE ATT&CK Detections")
        dataset_layout.addWidget(self.use_enterprise)
        dataset_layout.addWidget(self.use_mobile)
        dataset_layout.addWidget(self.use_ics)
        dataset_layout.addWidget(self.include_descriptions)
        dataset_layout.addWidget(self.include_detections)

        # Enable Enterprise by default
        self.use_enterprise.setChecked(True)
        self.include_descriptions.setChecked(True)

        # Tactic Selection
        tactic_layout = QVBoxLayout()
        selection_layout.addLayout(tactic_layout)
        tactic_label = QLabel("Select Tactic(s):")
        tactic_layout.addWidget(tactic_label)
        self.tactic_listbox = QListWidget()
        self.tactic_listbox.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        tactic_layout.addWidget(self.tactic_listbox)

        # Table
        self.table = QTableWidget()
        columns = ["APT", "Category", "T-Code", "Dataset Source", "Description", "IOC", "Detection Tool", "MITRE Detection"]
        self.table.setColumnCount(len(columns))
        self.table.setHorizontalHeaderLabels(columns)
        self.table.cellDoubleClicked.connect(lambda row, col: self.view_full_row())
        self.table.setRowCount(0)
        header = self.table.horizontalHeader()
        header.setStyleSheet("font-weight: bold;")
        self.table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        # Allow columns to stretch by default but remain resizable
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)  # Allows manual resizing
        header.setStretchLastSection(True)  # Ensures last column stretches to fit if needed
        main_layout.addWidget(self.table)

        #Enable edits to cells
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)

        # Buttons
        button_layout = QHBoxLayout()
        main_layout.addLayout(button_layout)

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

        generate_btn = QPushButton("Generate Report")
        generate_btn.clicked.connect(lambda: generate_report(
            self.apt_listbox, 
            self.tactic_listbox, 
            TACTIC_MAPPING, 
            self.include_descriptions,
            self.use_enterprise, 
            self.use_mobile, 
            self.use_ics,
            self.include_detections,
            self.table
        ))
        button_layout.addWidget(generate_btn)

        refresh_btn = QPushButton("Refresh Data")
        refresh_btn.clicked.connect(lambda: refresh_data(
            self.apt_listbox, 
            self.tactic_listbox, 
            TACTIC_MAPPING, 
            self.include_descriptions,
            self.include_detections,
            self.use_enterprise, 
            self.use_mobile, 
            self.use_ics,
            self.table
        ))
        button_layout.addWidget(refresh_btn)

        heatmap_btn = QPushButton("Generate Heatmap")
        heatmap_btn.clicked.connect(lambda: generate_mitre_heatmap(self.table))
        button_layout.addWidget(heatmap_btn)

        export_btn = QPushButton("Export to Excel")
        export_btn.clicked.connect(lambda: export_to_excel(
            self.include_detections, self.use_enterprise
        ))
        button_layout.addWidget(export_btn)

        # Load APTs and Tactics on Startup
        self.load_apts()
        self.load_tactics()

    def load_apts(self):
        selected_datasets = {
            "enterprise": True,  # Always load Enterprise by default
            "mobile": self.use_mobile.isChecked(),
            "ics": self.use_ics.isChecked()
        }

        mitre_data, _ = load_mitre_data(selected_datasets)
        if mitre_data is None:
            print("Error: MITRE data is empty. Check dataset paths and JSON format.")
            return

        apt_groups = get_apt_groups(mitre_data)
        self.apt_listbox.clear()
        for apt in sorted(apt_groups.keys()):
            self.apt_listbox.addItem(apt)

    def load_tactics(self):
        tactics = [
            "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
            "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
            "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"
        ]

        self.tactic_listbox.clear()
        for tactic in tactics:
            self.tactic_listbox.addItem(tactic)
    
    def view_full_row(self):
        selected_items = self.table.selectedItems()
        if not selected_items:
            QMessageBox.critical(self, "Error", "No row selected.")
            return

        row = selected_items[0].row()
        row_data = [self.table.item(row, col).text() if self.table.item(row, col) else "" for col in range(self.table.columnCount())]

        popup = QDialog(self)
        popup.setWindowTitle("Row Details")
        popup.resize(600, 400)

        layout = QVBoxLayout()
        popup.setLayout(layout)
        
        title_label = QLabel("Full Row Details")
        title_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title_label)

        text_area = QTextEdit()
        text_area.setReadOnly(True)
        layout.addWidget(text_area)

        column_headers = ["APT", "Category", "T-Code", "Dataset Source", "Description", "IOC", "Detection Tool", "MITRE Detection"]
        formatted_text = "".join(f"<b>{header}:</b> {value}<br><br>" for header, value in zip(column_headers, row_data))

        text_area.setText(formatted_text)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(popup.accept)
        layout.addWidget(close_btn)

        popup.exec()
    
    def show_context_menu(self, pos):
        item = self.table.itemAt(pos)
        if item is None:
            return

        menu = QMenu(self)

        edit_action = QAction("Edit", self)
        edit_action.triggered.connect(lambda: self.enable_editing(item))
        menu.addAction(edit_action)

        menu.exec(self.table.viewport().mapToGlobal(pos))
    
    def enable_editing(self, item):
        self.table.setEditTriggers(QTableWidget.EditTrigger.AllEditTriggers)
        self.table.editItem(item)
        self.table.itemChanged.connect(self.disable_editing)
        
    def disable_editing(self, item):
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.itemChanged.disconnect(self.disable_editing)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PiranhaApp()
    window.show()
    sys.exit(app.exec())