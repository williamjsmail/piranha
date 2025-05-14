import sys
import pyqtgraph as pg
from pyqtgraph import QtGui
import networkx as nx
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QCheckBox, QLineEdit, QListWidget, QTableWidget, QHeaderView, QAbstractItemDelegate,
    QSizePolicy, QMenu, QListWidgetItem, QGraphicsView, QTabWidget, QFileDialog, QProgressBar,
    QSlider, QScrollArea
)
from PyQt6.QtGui import QAction, QWheelEvent, QMouseEvent, QPainter, QIntValidator
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import qdarktheme
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from frontend.generate import generate_mitre_freq_table, generate_report, generate_heatmap, plot_3d_bar_chart, TacticOptimizationThread, InteractiveGraph
from frontend.keywords import *
from frontend.updates import *
from frontend.profile_builder import ThreatProfileBuilder
from frontend.compare_to_profile import CompareToProfileTab
from backend.logging_config import logger
from backend.enrich import enrich_data_with_ai
from backend.loader import load_mitre_data, load_component_json
from backend.processor import get_apt_groups
from backend.export import save_to_excel
from backend.parse_nessus import parse_nessus_xml


class PiranhaApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Piranha v3.4.0")
        self.adjustSize()
        self.setMinimumSize(1080, 800)

        try:
            qdarktheme.setup_theme("dark")
        except:
            qdarktheme.load_stylesheet("dark")

        self.TACTIC_MAPPING = {
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

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.analysis_tab = QWidget()
        self.tabs.addTab(self.analysis_tab, "Main Analysis")
        self.init_analysis_tab()
        self.radar_tab = QWidget()
        self.tabs.addTab(self.radar_tab, "Radar Chart")
        self.init_radar_tab()
        self.heatmap_tab = QWidget()
        self.tabs.addTab(self.heatmap_tab, "Heatmap")
        self.init_heatmap_tab()
        self.compare_tab = CompareToProfileTab(get_current_cves_func=self.get_parsed_cve_list)
        self.tabs.addTab(self.compare_tab, "Compare to Profile")
        self.profile_tab = ThreatProfileBuilder(list(self.TACTIC_MAPPING.keys()))
        self.tabs.addTab(self.profile_tab, "Profile Builder")

        menubar = self.menuBar()
        import_file = menubar.addMenu("File")

        import_nessus = QAction("Import Nessus Scan", self)
        import_nessus.triggered.connect(self.load_nessus_scan)
        import_file.addAction(import_nessus)
        load_profile = QAction("Load Piranha Profile", self)
        load_profile.triggered.connect(self.load_profile_and_generate_report)
        import_file.addAction(load_profile)

        help_menu = menubar.addMenu("Help")
        
        report_help_action = QAction("Main Analysis Report Help", self)
        report_help_action.triggered.connect(self.show_report_help)
        help_menu.addAction(report_help_action)
        freqtable_help_action = QAction("Frequency Table Help", self)
        freqtable_help_action.triggered.connect(self.show_freqtable_help)
        help_menu.addAction(freqtable_help_action)
        radar_help_action = QAction("Radar Chart Help", self)
        radar_help_action.triggered.connect(self.show_radar_help)
        help_menu.addAction(radar_help_action)
        heatmap_help_action = QAction("Heatmap Help", self)
        heatmap_help_action.triggered.connect(self.show_heatmap_help)
        help_menu.addAction(heatmap_help_action)
        profile_help_action = QAction("Profile Help", self)
        profile_help_action.triggered.connect(self.show_profile_help)
        help_menu.addAction(profile_help_action)
        contact_dev_action = QAction("Contact Developer", self)
        contact_dev_action.triggered.connect(self.show_contact_info)
        help_menu.addAction(contact_dev_action)

        # Load APTs and Tactics on Startup
        self.load_apts()
        self.load_tactics()

    def init_analysis_tab(self):
        # Main UI
        layout = QVBoxLayout()
        self.analysis_tab.setLayout(layout)

        # Header
        header_label = QLabel("Piranha T-Code Mapper")
        header_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(header_label, alignment=Qt.AlignmentFlag.AlignCenter)

        # Upper Section (APT Selection, Tactics, Graph)
        upper_layout = QHBoxLayout()
        layout.addLayout(upper_layout, 1)

        # Left Panel (APT Selection)
        left_panel = QVBoxLayout()
        upper_layout.addLayout(left_panel, 1)

        apt_label = QLabel("Select APT(s):")
        left_panel.addWidget(apt_label)
        self.apt_listbox = QListWidget()
        self.apt_listbox.setFixedWidth(275)
        self.apt_listbox.setFixedHeight(400)
        self.apt_listbox.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.apt_listbox.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        left_panel.addWidget(self.apt_listbox)
        self.search_entry = QLineEdit()

        self.search_entry.setPlaceholderText("Search APT name or alias...")
        self.search_entry.setFixedWidth(275)
        left_panel.addWidget(self.search_entry)
        self.search_entry.textChanged.connect(lambda: self.update_apt_list(self.search_entry.text()))
        self.selected_apts = set()

        # Center Panel (Tactic Selection)
        tactic_panel = QVBoxLayout()
        upper_layout.addLayout(tactic_panel, 1)

        tactic_label = QLabel("Select Tactic(s):")
        tactic_panel.addWidget(tactic_label)
        self.tactic_listbox = QListWidget()
        self.tactic_listbox.setFixedWidth(275)
        self.tactic_listbox.setFixedHeight(525)
        self.tactic_listbox.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.tactic_listbox.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        tactic_panel.addWidget(self.tactic_listbox)

        
        
        # Right Panel (Graph View)
        self.graph_scene = InteractiveGraph([])
        self.graph_view = InteractiveGraphicsView(self.graph_scene)
        self.graph_view.setMinimumSize(800, 600)
        self.graph_view.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        graph_panel = QVBoxLayout()
        upper_layout.addLayout(graph_panel, 2)
        graph_panel.addWidget(QLabel("APT T-Code Node Analysis"))
        fullscreen_btn = QPushButton("Fullscreen Mode")
        graph_panel.addWidget(fullscreen_btn)
        fullscreen_btn.clicked.connect(self.fullscreen_graph)
        graph_panel.addWidget(self.graph_view)

        # Lower Section (Dataset Selection + Table)
        lower_layout = QVBoxLayout()
        layout.addLayout(lower_layout, 2)
        dataset_layout = QHBoxLayout()
        lower_layout.addLayout(dataset_layout)
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search table...")
        self.search_bar.setFixedWidth(560)
        self.search_bar.textChanged.connect(self.filter_table)
        dataset_layout.addWidget(self.search_bar)

        self.use_enterprise = QCheckBox("Enterprise ATTACK")
        self.use_enterprise.setChecked(True)
        self.use_mobile = QCheckBox("Mobile ATTACK")
        self.use_ics = QCheckBox("ICS ATTACK")
        self.include_descriptions = QCheckBox("APT Specific Descriptions")
        self.include_descriptions.setChecked(True)
        self.include_detections = QCheckBox("MITRE ATTACK Detections")

        dataset_layout.addWidget(self.use_enterprise)
        dataset_layout.addWidget(self.use_mobile)
        dataset_layout.addWidget(self.use_ics)
        dataset_layout.addWidget(self.include_descriptions)
        dataset_layout.addWidget(self.include_detections)

        #  Table & Buttons
        self.table = EditableTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels(["APT", "Category", "T-Code", "Dataset Source", "Description", "IOM", "Detection Tool", "MITRE Detection"])
        self.table.setSortingEnabled(True)
        self.table.setMinimumHeight(400)
        self.table.cellDoubleClicked.connect(lambda row, col: self.view_full_row())
        self.table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)

        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        lower_layout.addWidget(self.table)
        button_layout = QHBoxLayout()
        layout.addLayout(button_layout)

        generate_btn = QPushButton("Generate Report")
        generate_btn.clicked.connect(lambda: generate_report(
            self.apt_listbox,
            self.tactic_listbox,
            self.TACTIC_MAPPING,
            self.include_descriptions,
            self.use_enterprise,
            self.use_mobile,
            self.use_ics,
            self.include_detections,
            self.table,
            self.graph_view,
            self.radar_fig,           
            self.radar_canvas,        
            self.radar_summary,       
            self.radar_tables         
        ))
        button_layout.addWidget(generate_btn)
        
        manage_keywords_btn = QPushButton("Manage Keywords")
        manage_keywords_btn.clicked.connect(lambda: manage_keywords_popup(self))
        button_layout.addWidget(manage_keywords_btn)

        refresh_btn = QPushButton("Refresh Data")
        refresh_btn.clicked.connect(lambda: refresh_data(
            self.apt_listbox, 
            self.tactic_listbox, 
            self.TACTIC_MAPPING, 
            self.include_descriptions,
            self.include_detections,
            self.use_enterprise, 
            self.use_mobile, 
            self.use_ics,
            self.table
        ))
        button_layout.addWidget(refresh_btn)

        heatmap_btn = QPushButton("Generate Frequency Table")
        heatmap_btn.clicked.connect(lambda: generate_mitre_freq_table(self.get_table_data()))
        button_layout.addWidget(heatmap_btn)

        export_btn = QPushButton("Export to Excel")
        export_btn.clicked.connect(lambda: save_to_excel(self.table))
        button_layout.addWidget(export_btn)
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("font-size: 12px; color: #AAAAAA; padding: 5px;")
        button_layout.addWidget(self.status_label)

    def load_nessus_scan(self):
        # Load and parse Nessus XML
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Nessus Scan File", "", "Nessus Scan Files (*.xml *.nessus)")
        
        if not file_path:
            return

        self.heatmap_label.setText("Loading Nessus scan...")
        try:
            parsed_data = parse_nessus_xml(file_path)
            if not parsed_data:
                QMessageBox.critical(self, "Error", " No CVEs found in the scan.")
                self.heatmap_label.setText(" No data found.")
                return
            
            self.parsed_cve_data = parsed_data
            self.heatmap_label.setText(f"Loaded: {file_path}")
            self.refresh_cve_table()
            QMessageBox.information(self, "Success", "Nessus scan parsed successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Nessus parsing failed: {e}")
            self.heatmap_label.setText("Failed to load Nessus scan.")
            logger.error(f"Failed to load Nessus scan: {e}")
    
    def init_radar_tab(self):
        main_layout = QVBoxLayout()
        self.radar_tab.setLayout(main_layout)

        # === TOP LAYOUT: Radar Chart + Summary Text ===
        top_layout = QHBoxLayout()

        # Radar Chart Canvas on the left side
        self.radar_fig = Figure(figsize=(5, 4))
        self.radar_canvas = FigureCanvas(self.radar_fig)
        self.radar_canvas.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        top_layout.addWidget(self.radar_canvas, stretch=3)

        # Summary box on the right
        self.radar_summary = QTextEdit()
        self.radar_summary.setReadOnly(True)
        self.radar_summary.setPlaceholderText("Summary will appear here...")
        self.radar_summary.setFixedWidth(250)
        top_layout.addWidget(self.radar_summary, stretch=1)
        main_layout.addLayout(top_layout)

        main_layout.addLayout(top_layout)

        # === OPTIMIZATION CONTROLS UNDER SUMMARY BOX ===
        summary_container = QVBoxLayout()
        summary_container.addWidget(self.radar_summary)

        # Row for the optimize button and progress bar
        optimize_layout = QVBoxLayout()

        self.optimize_tactics_btn = QPushButton("Optimize Tactic Selection")
        self.optimize_tactics_btn.clicked.connect(self.start_tactic_optimization_popup)
        self.optimize_tactics_btn.setFixedWidth(250)
        optimize_layout.addWidget(self.optimize_tactics_btn)

        self.optimization_progress = QProgressBar()
        self.optimization_progress.setRange(0, 0)
        self.optimization_progress.setVisible(False)
        self.optimization_progress.setFixedWidth(250)
        optimize_layout.addWidget(self.optimization_progress)

        summary_container.addLayout(optimize_layout)
        top_layout.addLayout(summary_container, stretch=1)

        # === BOTTOM LAYOUT: Four Category Tables ===
        bottom_layout = QHBoxLayout()
        

        # === BOTTOM LAYOUT: Four Category Tables ===
        bottom_layout = QHBoxLayout()

        categories = ["Host Collection", "Network Collection", "Host Interrogation", "Host Memory Analysis"]
        self.radar_tables = {}

        for cat in categories:
            cat_table = QTableWidget()
            cat_table.setColumnCount(1)
            cat_table.setHorizontalHeaderLabels(["T-Code"])
            # Center-align header text
            header = cat_table.horizontalHeader()
            header.setDefaultAlignment(Qt.AlignmentFlag.AlignHCenter)
            # Stretch column to fit table width
            header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            cat_table.setSortingEnabled(True)
            cat_table.setMinimumHeight(300)
            cat_table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

            self.radar_tables[cat] = cat_table

            # Label + Table layout
            table_layout = QVBoxLayout()
            label = QLabel(cat)
            table_layout.addWidget(label)
            table_layout.addWidget(cat_table)

            bottom_layout.addLayout(table_layout)

        main_layout.addLayout(bottom_layout)

    def init_heatmap_tab(self):
        # Heatmap UI
        main_layout = QHBoxLayout()
        self.heatmap_tab.setLayout(main_layout)

        # === LEFT COLUMN ===
        left_column = QVBoxLayout()
        left_column.setSpacing(6)
        left_column.setContentsMargins(6, 6, 6, 6)

        # ---- TOP BOX (CVE Table) ----
        self.top_info_label = QLabel("CVEs from Imported Nessus Scan")
        self.top_info_label.setStyleSheet("margin-bottom: 2px;")
        left_column.addWidget(self.top_info_label)

        self.clear_cve_table_btn = QPushButton("Clear CVE Table")
        self.clear_cve_table_btn.setFixedWidth(300)
        self.clear_cve_table_btn.setStyleSheet("padding: 4px; margin-bottom: 10px;")
        self.clear_cve_table_btn.clicked.connect(self.clear_cve_table)
        left_column.addWidget(self.clear_cve_table_btn)

        self.top_info_table = QTableWidget()
        self.top_info_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.top_info_table.customContextMenuRequested.connect(self.show_cve_context_menu)
        self.top_info_table.setColumnCount(2)
        self.top_info_table.setHorizontalHeaderLabels(["CVE", "CVSS Score"])
        self.top_info_table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.top_info_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.top_info_table.setFixedHeight(400)
        self.top_info_table.setFixedWidth(300)
        header = self.top_info_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setStretchLastSection(True)
        left_column.addWidget(self.top_info_table)

        # Populate CVE table from parsed data
        if hasattr(self, 'parsed_cve_data'):
            self.top_info_table.setRowCount(len(self.parsed_cve_data))
            for row_idx, (cve, score) in enumerate(self.parsed_cve_data.items()):
                self.top_info_table.setItem(row_idx, 0, QTableWidgetItem(cve))
                self.top_info_table.setItem(row_idx, 1, QTableWidgetItem(str(score)))
        else:
            self.top_info_table.setRowCount(1)
            self.top_info_table.setItem(0, 0, QTableWidgetItem("No Data"))
            self.top_info_table.setItem(0, 1, QTableWidgetItem("-"))

        # ---- BOTTOM BOX (Bulk CVE Input) ----
        self.bottom_input_label = QLabel("Add Custom CVE's for Heatmap Analysis")
        self.bottom_input_label.setStyleSheet("margin-bottom: 2px;")
        left_column.addWidget(self.bottom_input_label)

        # Widget container for input area
        bottom_input_widget = QWidget()
        bottom_input_layout = QVBoxLayout()
        bottom_input_layout.setSpacing(4)
        bottom_input_layout.setContentsMargins(0, 0, 0, 0)
        bottom_input_widget.setLayout(bottom_input_layout)

        # Text input box
        self.custom_cve_textbox = QTextEdit()
        self.custom_cve_textbox.setPlaceholderText("Example:\nCVE-2025-12345, 9.8\nCVE-2023-54321, 7.5")
        self.custom_cve_textbox.setFixedHeight(375)
        self.custom_cve_textbox.setFixedWidth(300)
        self.custom_cve_textbox.setStyleSheet("padding: 4px; margin-top: 0px;")
        bottom_input_layout.addWidget(self.custom_cve_textbox)

        # Submit button
        self.add_bulk_cve_btn = QPushButton("Submit Custom CVEs")
        self.add_bulk_cve_btn.setFixedWidth(300)
        self.add_bulk_cve_btn.setStyleSheet("padding: 4px; margin-top: 4px;")
        self.add_bulk_cve_btn.clicked.connect(self.handle_custom_cves)
        bottom_input_layout.addWidget(self.add_bulk_cve_btn)

        # Add to column
        left_column.addWidget(bottom_input_widget)

        # === RIGHT COLUMN ===
        right_column = QVBoxLayout()

        self.heatmap_label = QLabel("No heatmap generated yet.")
        right_column.addWidget(self.heatmap_label)

        self.tooltip_table = EditableTableWidget()
        self.tooltip_table.setColumnCount(6)
        self.tooltip_table.setHorizontalHeaderLabels(
            ["T-Code", "APT Count", "CVE Count", "Mean CVSS", "Max CVSS", "Piranha Weight"]
        )
        self.tooltip_table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        header = self.tooltip_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        right_column.addWidget(self.tooltip_table)

        self.heatmap_btn = QPushButton("Generate Heatmap")
        self.heatmap_btn.clicked.connect(self.generate_heatmap_call)
        right_column.addWidget(self.heatmap_btn)

        # Wrap left and right in widgets
        left_widget = QWidget()
        left_widget.setLayout(left_column)
        main_layout.addWidget(left_widget, stretch=1)

        right_widget = QWidget()
        right_widget.setLayout(right_column)
        main_layout.addWidget(right_widget, stretch=3)

    def handle_custom_cves(self):
        # Handle custom CVE entries
        input_text = self.custom_cve_textbox.toPlainText().strip()
        if not input_text:
            QMessageBox.warning(self, "Input Error", "Custom CVE input cannot be empty.")
            return

        lines = input_text.splitlines()
        added_count = 0

        for line in lines:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) != 2:
                continue

            cve_id, score = parts
            if not cve_id.startswith("CVE-") or not cve_id[4:].replace("-", "").isdigit():
                continue

            try:
                score_float = float(score)
            except ValueError:
                continue

            # Initialize dictionary if it doesn't exist yet
            if not hasattr(self, 'parsed_cve_data') or self.parsed_cve_data is None:
                self.parsed_cve_data = {}

            self.parsed_cve_data[cve_id] = score_float
            added_count += 1

        if added_count == 0:
            QMessageBox.information(self, "No Valid Entries", "No valid CVE entries were found.")
            return

        # Refresh the table with updated data
        self.refresh_cve_table()
        self.custom_cve_textbox.clear()

    def refresh_cve_table(self):
        # Update CVE table
        if not hasattr(self, 'parsed_cve_data'):
            return

        self.top_info_table.setRowCount(len(self.parsed_cve_data))
        for row_idx, (cve, score) in enumerate(self.parsed_cve_data.items()):
            self.top_info_table.setItem(row_idx, 0, QTableWidgetItem(cve))
            self.top_info_table.setItem(row_idx, 1, QTableWidgetItem(str(score)))
    
    def delete_cve_entry(self, row):
        if not hasattr(self, 'parsed_cve_data'):
            return

        cve_item = self.top_info_table.item(row, 0)
        if cve_item:
            cve_id = cve_item.text()
            if cve_id in self.parsed_cve_data:
                del self.parsed_cve_data[cve_id]

        self.refresh_cve_table()
    
    def clear_cve_table(self):
        self.top_info_table.setRowCount(0)
        self.parsed_cve_data = {}
        self.top_info_table.setRowCount(1)
        self.top_info_table.setItem(0, 0, QTableWidgetItem("No Data"))
        self.top_info_table.setItem(0, 1, QTableWidgetItem("-"))

    def show_cve_context_menu(self, position):
        index = self.top_info_table.indexAt(position)
        if not index.isValid():
            return

        menu = QMenu()
        delete_action = QAction("Delete Entry", self)
        delete_action.triggered.connect(lambda: self.delete_cve_entry(index.row()))
        menu.addAction(delete_action)
        menu.exec(self.top_info_table.viewport().mapToGlobal(position))
    
    def get_parsed_cve_list(self):
        if hasattr(self, "parsed_cve_data"):
            return list(self.parsed_cve_data.keys())
        return []
        
    
    def generate_heatmap_call(self):
        # Generate 3d map
        if not hasattr(self, "parsed_cve_data") or not self.parsed_cve_data:
            QMessageBox.critical(self, "Error", "Load a Nessus scan first.")
            return

        table_tcodes = set()
        for row in range(self.table.rowCount()):
            tcode = self.table.item(row, 2).text().strip()
            if tcode:
                table_tcodes.add(tcode)
        if not table_tcodes:
            QMessageBox.critical(self, "Error", "No T-Codes found in the report data.")
            return

        self.heatmap_label.setText("Generating 3D bar heatmap...")
        # Extract APT-to-T-Code mapping from output_data
        apt_tcode_map = {}
        if hasattr(self, "output_data") and self.output_data:
            for row in self.output_data:
                apt_name, _, t_code, *_ = row  # Extract APT name and T-Code
                if t_code:
                    if t_code not in apt_tcode_map:
                        apt_tcode_map[t_code] = set()
                    apt_tcode_map[t_code].add(apt_name)
        apt_tcode_map = {t_code: list(apts) for t_code, apts in apt_tcode_map.items()}
        heatmap_data = generate_heatmap(self.parsed_cve_data, table_tcodes, apt_tcode_map)
        if heatmap_data:
            plot_3d_bar_chart(heatmap_data)
            self.populate_tooltip_table(heatmap_data)
        else:
            QMessageBox.warning(self, "Warning", "No relevant T-Codes found for heatmap.")
    
    def populate_tooltip_table(self, heatmap_data):
        # Hover text
        if not heatmap_data:
            self.tooltip_table.setRowCount(0)
            return

        num_rows = len(heatmap_data["x"])
        self.tooltip_table.setRowCount(num_rows)
        for row_idx in range(num_rows):
            row_data = [
                heatmap_data["labels"][row_idx],           # T-Code
                str(heatmap_data["z"][row_idx]),           # APT Count
                str(heatmap_data["x"][row_idx]),           # CVE Count
                f"{heatmap_data['y_mean'][row_idx]:.2f}",  # Mean CVSS
                f"{heatmap_data['y_max'][row_idx]:.2f}",   # Max CVSS
                f"{heatmap_data['weights'][row_idx]:.2f}"  # Piranha Weight
            ]
            for col_idx, value in enumerate(row_data):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.tooltip_table.setItem(row_idx, col_idx, item)

    def load_apts(self):
        selected_datasets = {
            "enterprise": True,
            "mobile": self.use_mobile.isChecked(),
            "ics": self.use_ics.isChecked()
        }
        self.mitre_data, _ = load_mitre_data(selected_datasets)
        if self.mitre_data is None:
            logger.error("MITRE data is empty. Check dataset paths and JSON format.")
            return

        self.apt_groups, alias_map = get_apt_groups(self.mitre_data)

        self.apt_alias_map = {}
        for alias, canonical in alias_map.items():
            self.apt_alias_map.setdefault(canonical, []).append(alias)

        self.apt_listbox.clear()
        for apt in sorted(self.apt_groups.keys()):
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

    def fullscreen_graph(self):
        self.fullscreen_window = FullScreenGraph(self.graph_view.scene())
        self.fullscreen_window.showFullScreen()
    
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
        popup.show()

    def filter_table(self):
        # Search input filter
        search_text = self.search_bar.text().lower()
        for row in range(self.table.rowCount()):
            row_visible = False

            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item and search_text in item.text().lower():
                    row_visible = True
                    break

            self.table.setRowHidden(row, not row_visible)

    def start_tactic_optimization(self, num_tactics, ideal_fit, excluded_tactics):
        self.categorized_data = load_component_json()

        # Show progress bar when optimization starts
        self.optimization_progress.setVisible(True)
        self.mitre_data = load_mitre_data({"enterprise": True})
        self.categorized_data = load_component_json()

        self.optimization_thread = TacticOptimizationThread(
            self.apt_listbox,
            self.TACTIC_MAPPING,
            self.tactic_listbox,
            num_tactics,
            ideal_fit,
            excluded_tactics,
            self.mitre_data,
            self.categorized_data
        )
        self.optimization_thread.finished.connect(self.display_optimized_result)
        self.optimization_thread.finished.connect(lambda: self.optimization_progress.setVisible(False))
        self.optimization_thread.start()
    
    def display_optimized_result(self, best_combo, score, dist):
        msg = f"✅ Best Tactic Combination: {', '.join(best_combo)}\n\nScore: {score:.4f}\nDistribution:\n"
        for k, v in dist.items():
            msg += f"- {k}: {(v * 100):.2f}%\n"

        box = QMessageBox(self)
        box.setWindowTitle("Optimized Tactics")
        box.setText(msg)
        box.setIcon(QMessageBox.Icon.Information)
        box.setStandardButtons(QMessageBox.StandardButton.Ok)
        box.setModal(False)
        box.show()

    def start_tactic_optimization_popup(self):
        popup = QDialog(self)
        popup.setWindowTitle("Tactic Optimization")
        popup.resize(600, 500)
        layout = QVBoxLayout()
        popup.setLayout(layout)

        # === Number of Tactics Selection ===
        layout.addWidget(QLabel("How many tactics would you like to include?"))
        tactic_count_input = QLineEdit()
        tactic_count_input.setPlaceholderText("Enter a number (e.g., 3)")
        tactic_count_input.setValidator(QIntValidator(1, 15))  # Only allow integer input
        layout.addWidget(tactic_count_input)

        # === Exclude Tactics ===
        layout.addWidget(QLabel("Exclude tactics from optimization:"))
        exclude_list = QListWidget()
        exclude_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        for tactic in sorted(self.TACTIC_MAPPING.keys()):
            exclude_list.addItem(tactic)
        layout.addWidget(exclude_list)

        category_defaults = {
            "Host Collection": 40,
            "Network Collection": 20,
            "Host Interrogation": 30,
            "Host Memory Analysis": 10
        }

        # === Sliders with Live Display ===
        layout.addWidget(QLabel("Adjust your ideal detection distribution (must total 100%)"))
        slider_layout = QVBoxLayout()
        sliders = {}
        slider_labels = {}
        categories = list(category_defaults.keys())

        total_label = QLabel("Total: 100%")  # Initial value will be fixed below
        layout.addWidget(total_label)

        def update_total_label():
            total = sum(s.value() for s in sliders.values())
            total_label.setText(f"Total: {total}%")
            if total != 100:
                total_label.setStyleSheet("color: red; font-weight: bold;")
            else:
                total_label.setStyleSheet("color: green; font-weight: normal;")

        for category in categories:
            hbox = QHBoxLayout()
            slider = QSlider(Qt.Orientation.Horizontal)
            slider.setRange(0, 100)
            default_val = category_defaults[category]
            slider.setValue(default_val)
            sliders[category] = slider

            label = QLabel(f"{category}: {default_val}%")
            slider_labels[category] = label

            def make_handler(cat=category):
                def handler():
                    value = sliders[cat].value()
                    slider_labels[cat].setText(f"{cat}: {value}%")
                    update_total_label()
                return handler

            slider.valueChanged.connect(make_handler())

            hbox.addWidget(label)
            hbox.addWidget(slider)
            slider_layout.addLayout(hbox)

        layout.addLayout(slider_layout)

        # Update the total once initially
        update_total_label()

        # === Button to Begin Optimization ===
        start_btn = QPushButton("Start Optimization")
        layout.addWidget(start_btn)

        def validate_and_run():
            try:
                num_tactics = int(tactic_count_input.text())
            except ValueError:
                QMessageBox.warning(popup, "Input Error", "Please enter a valid number of tactics.")
                return

            total = sum(slider.value() for slider in sliders.values())
            if total != 100:
                QMessageBox.warning(popup, "Slider Error", f"Your ideal distribution must total 100%. Currently: {total}%")
                return

            # Prepare the ideal fit dictionary
            ideal_fit = {cat: sliders[cat].value() / 100.0 for cat in categories}
            excluded_tactics = [item.text() for item in exclude_list.selectedItems()]

            # Start optimization with these values
            popup.accept()  # Close popup
            self.start_tactic_optimization(num_tactics, ideal_fit, excluded_tactics)

        start_btn.clicked.connect(validate_and_run)
        popup.show()
    
    def enrich_with_ai(self, item):
        selected_items = self.table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Enrichment Error", " No item selected for enrichment.")
            return

        row = selected_items[0].row()
        apt_name = self.table.item(row, 0).text()
        tactic_name = self.table.item(row, 1).text()
        technique = self.table.item(row, 2).text()
        self.status_label.setText(f"Enriching {apt_name} data...")
        self.status_label.repaint()
        #  Start background AI enrichment
        self.enrichment_thread = AIEnrichmentThread(apt_name, tactic_name, technique)
        self.enrichment_thread.result_ready.connect(self.show_enrichment_popup)
        self.enrichment_thread.start()
    
    def show_enrichment_popup(self, apt_name, enrichment_text):
        self.status_label.setText(f"{apt_name} enrichment complete...")
        self.status_label.repaint()
        popup = QDialog(self)
        popup.setWindowTitle(f"AI Enrichment - {apt_name}")
        popup.setFixedSize(600, 400)

        layout = QVBoxLayout()
        popup.setLayout(layout)
        title_label = QLabel(f"AI Enrichment - {apt_name}")
        title_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title_label)
        # Scrollable text
        text_edit = QTextEdit()
        text_edit.setPlainText(enrichment_text)
        text_edit.setReadOnly(True)
        text_edit.setStyleSheet("font-size: 12px; background-color: #333; color: white;")
        layout.addWidget(text_edit)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(popup.accept)
        layout.addWidget(close_btn)
        popup.show()
        #self.status_label.setText("Ready")
    
    def show_context_menu(self, pos):
        item = self.table.itemAt(pos)
        if item is None:
            return
        menu = QMenu(self)
        edit_action = QAction("Edit", self)
        enrich_data = QAction("Enrich Data with AI", self)
        edit_action.triggered.connect(lambda: self.enable_editing(item))
        enrich_data.triggered.connect(lambda: self.enrich_with_ai(item))
        menu.addAction(edit_action)
        menu.addAction(enrich_data)
        menu.exec(self.table.viewport().mapToGlobal(pos))
    
    def enable_editing(self, item):
        self.table.setEditTriggers(QTableWidget.EditTrigger.AllEditTriggers)
        self.table.editItem(item)

    def get_table_data(self):
        data = []
        for row in range(self.table.rowCount()):
            row_data = []
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                row_data.append(item.text() if item else "")
            data.append(row_data)
        return data
    
    def update_apt_list(self, search_term):
        self.selected_apts.update({
            self.apt_listbox.item(i).text()
            for i in range(self.apt_listbox.count())
            if self.apt_listbox.item(i).isSelected()
        })

        self.apt_listbox.clear()
        if not self.apt_groups:
            return

        search_term = search_term.strip().lower()

        for apt_name in sorted(self.apt_groups.keys()):
            aliases = self.apt_alias_map.get(apt_name.lower(), [])
            all_searchable = [apt_name.lower()] + [alias.lower() for alias in aliases]

            if any(search_term in alias for alias in all_searchable):
                item = QListWidgetItem(apt_name)
                self.apt_listbox.addItem(item)
                if apt_name in self.selected_apts:
                    item.setSelected(True)
                    
    def load_profile_and_generate_report(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Profile", "", "Piranha Profiles (*.pir)")
        if not file_path:
            return

        try:
            with open(file_path, "r") as f:
                profile = json.load(f)

            selected_apts = profile.get("apts", [])
            selected_tactics = profile.get("tactics", [])  
            cves = profile.get("cves", [])  

            # Push report data into main analysis tab
            self.apt_listbox.clearSelection()
            for i in range(self.apt_listbox.count()):
                if self.apt_listbox.item(i).text() in selected_apts:
                    self.apt_listbox.item(i).setSelected(True)

            self.tactic_listbox.clearSelection()
            for i in range(self.tactic_listbox.count()):
                if self.tactic_listbox.item(i).text() in selected_tactics:
                    self.tactic_listbox.item(i).setSelected(True)
            
            if hasattr(self, "custom_cve_textbox"):
                cve_text = "\n".join(cves)
                self.custom_cve_textbox.setPlainText(cve_text)

            QMessageBox.information(self, "Profile Loaded", f"Loaded profile: {profile.get('profile_name', 'Unnamed')}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load profile: {e}")

    def show_report_help(self):
        report_help_text = (
"<b>Understanding the Main Analysis Data</b><br><br>"
"<b>Summary:</b> The main analysis tab is the starting point for analysis. Here, you will select APT's relevant to your mission or information requirement and tactics you would like to pull from. You will then click <b>Generate Report</b> to create a report table containing relevant information pertaining to your knowledge requirements.<br><br>"
"<b>Report Table:</b> The report table contains information about the <b>APT</b> (threat actor), <b>Category</b> (information requirement), <b>T-Code</b> (specific information requirement), <b>Dataset source</b> (enterprise, ICS, mobile), <b>Description</b>, <b>IOM</b> (Indicator of Methodology, essential element of information), <b>Detection Tool</b>, and <b>MITRE Detection</B>.<br><br>"
"<b>Data Enrichment:</b> Right clicking on a column and selecting <b>Enrich Data with AI</b> will allow you to enrich your data via querying OpenAI's API endpoint. Included in the enriched data should be methodology indicators, detection methods, and reporting with citations for enhanced analysis.<br><br>"
"<b>Export to Excel:</b> After you have completed modifying, enriching, editing, or deleting information from your generated report, Piranha provides the ability to export your report to a .xlsx file.<br><br>"
"<b>APT T-Code Node Analysis:</b> This view shows relationships between APT's and their associated techniques as shared with other APT's. Right click context menu will allow you to remove all techniques that aren't shared between multiple APT's.<br>"
        )
        help = HelpMenu("Main Analysis Report Help", report_help_text)
        help.exec()

    def show_freqtable_help(self):
        freqtable_help_text = (
"<b>Understanding the Frequency Table</b><br><br>"
"<b>Summary:</b> The frequency table can be generated via the <b>Generate Frequency Table</b> button after you have selected a list of APT's and tactics.<br>"
"The table represents the frequency of all techniques in your report across all selected APT's and tactics. This feature speeds up prioritization by giving a clean prioritized view of the data.<br><br>"
"<b>X-Axis (Frequency):</b> Number of times a technique is seen across all selected APT's and tactics.<br><br>"
"<b>Y-Axis (Technique):</b> Identifies the technique from the report being counted.<br><br>"
"<b>Example Usage:</b> A user selects APT28 and APT29, and selects Execution, Persistence, and Privilege Escalation. They then generate a frequency table and see that T15447.001 is used 4 times. After searching their table for T15447.001, they find that it is used by both APT's they selected and is used as techniques of both Persistence and Privilege Escalation. This information allows the analyst to now know that this technique is a high priority technique to focus on in their hunt plan based on the fact that both selected APT's use it and the fact it is used in multiple tactics."
        )
        help = HelpMenu("Frequency Table Help", freqtable_help_text)
        help.exec()

    def show_radar_help(self):
        radar_help_text = (
"<b>Understanding the Radar Chart</b><br><br>"
"<b>Summary:</b> The radar chart can be used for multiple functions. A few functions that can be extremely helpful to both intelligence and cyber analysts are data validation, hunt plan development, and hunt plan tuning. As an intelligence analyst in a cyber work role, the techniques you give to cyber analysts matter. However, many intelligence shops are not trained on how to actually hunt on the techniques they provide. If you were to give cyber analysts a report generated based solely on the data found in a report, i.e. APT28 and APT29 seen conducting Execution and Persistence techniques, the techniques present in that report would provide plenty of room to hunt on data collected at the host level. However, there would not be much movement into hunting at the network level, or ways to dive deeper into host interrogation or memory analysis. In a perfect world, cyber analysts would want a blend of tactics to hunt on so that the data they are hunting on is well balanced between host and network collection, host interrogation, and memory analysis. Here is how Piranha helps.<br><br>"
"<b>Data Validation:</b> Once a report is generated, the intelligence analyst can check the radar graph to see how well the data fits within the ideal fit. This will paint a picture of what the techniques are lacking from a collection and hunting point of view if the data were to be used on a mission.<br><br>"
"<b>Hunt Plan Development:</b> Using the <b>Optimize Tactic Selection</b> button, we can specify how many tactics we want to include, the tactics we would want to exclude from a hunt plan, and also adjust the best fit for our team or mission. Piranha will run through every possible combination of the number of tactics you selected, compare them against each other, find the lowest standard deviation from your ideal fit, and then return this information to you.<br><br>"
"<b>Hunt Plan Tuning:</b> Although the 'ideal' fit may work for most missions, there are times where we want to focus more on memory analysis techniques, or do not necessarily care about network collection. This is where we can tune the ideal fit to fit our needs. Using the sliders, we can adjust the values based on our collection needs. Piranha will then run through the same process as before to find the new best fit.<br><br>"
"<b>Summary Text Box:</b> On the right hand side, we see the summary text box. When a report is generated, this summary is generated with information about the data category, the number of times this category is referenced by the data sources associated with the techniques, and the percentage of data sources in the report that are associated with this category.<br><br>"
"<b>Data Category Tables:</b> The bottom pane will show all 4 categories and the techniques that fall within them. <b>Note:</b> Some techniques fall within multiple categories. This is because there are multiple ways we can detect many techniques."
        )
        help = HelpMenu("Radar Help", radar_help_text)
        help.exec()

    def show_heatmap_help(self):
        heatmap_help_text = (
"<b>Understanding the 3-Dimensional Frequency Heatmap</b><br><br>"
"<b>X-Axis (T-Code Frequency):</b> Number of times a technique from the main analysis table data is associated with Nessus CVE results.<br><br>"
"<b>Y-Axis (Mean CVSS Score):</b> The average CVSS score of all CVEs associated with the technique.<br><br>"
"<b>Z-Axis (Number of APT Groups Using the T-Code):</b> The number of APT groups in the main analysis table data that are known to use the technique.<br><br>"
"<b>Color Gradient:</b> Indicates Piranha Weight (blue = low, red = high).<br><br>"
"<b> How is Piranha Weight calculated?</b> weight<sub>t</sub> = #<sub>t</sub> × (max CVSS<sub>t</sub> / 10) × (number of APTs<sub>t</sub> <sup>0.5</sup>)<br><br>"
"<b>What does this all mean?</b> Each bar in the graph represents a technique that appears in your report AND appears as a mapped technique of CVE's in your Nessus scan. Higher Piranha Weight means higher priority based  on your reported data.<br><br>"
"<b>Note:</b> Before a heatmap and it's associated table can be generated, a Nessus scan must be imported in XML format and must contain CVE's."
        )
        help = HelpMenu("Heatmap Help", heatmap_help_text)
        help.exec()
    
    def show_profile_help(self):
        profile_help_text = (
"<b>Understanding Piranha Profiles</b><br><br>"
"<b>What is a Piranha Profile?:</b> A profile in Piranha is a structured snapshot of how adversaries operate, combining APT groups, tactics, techniques, and CVEs into a reusable, mission-driven format. Each profile is designed to reflect real-world behaviors—such as Russian lateral movement or Chinese initial access—enabling analysts to compare their current vulnerability exposure against known TTPs using precise F1 scoring (see \"What is an F1 Score?\" below). Profiles allow for deeper prioritization and hunt planning tailored to the threats that matter most to the mission.<br><br>"
"<b>Profile Builder Tab:</b> The Profile Builder tab lets analysts create custom threat profiles by selecting APTs*, tactics*, submit CVEs, and specific techniques. Piranha auto-generates a full technique list to represent the threat’s behavioral footprint. These profiles can be saved and reused to compare against scans, guide hunts, or represent the attack patterns of the threat an analyst cares about. Piranha will then output a <b>\".pir\"</b> file, denoting it as a Piranha Profile.<br>"
"* = required<br><br>"
"<b>Compare to Profile Tab:</b> The Compare to Profile tab allows analysts to match vulnerability scan data against one or more threat profiles to identify which adversary behaviors align with their environment. Piranha maps scan-derived techniques to each profile’s techniques and calculates an F1 score to show how closely they match. Analysts can view match percentages (precision and recall), see exactly which techniques and CVE's overlap, and preview the full contents of each loaded profile—all in one place.<br><br>"
"<b>What is Precision?:</b> The percentage of techniques from the scan that are also found in the profile. It tells you how focused the scan match is.<br>"
"<b>P</b> = techniques<sub>scan</sub> / techniques<sub>profile</sub><br><br>"
"<b>What is Recall?:</b> The percentage of techniques from the profile that are found in the scan. It shows how much of the profile is covered by the scan.<br>"
"<b>R</b> = techniques<sub>profile</sub> / techniques<sub>scan</sub><br><br>"
"<b>What is an F1 Score?:</b> The balance between precision and recall, giving a single number to represent how well the scan and profile align overall. A higher F1 score means a stronger match.<br>"
"<b>F1</b> = (2 x P x R) / (P + R)<br><br>"
"<b>What does this all mean?</b><br>"
"High precision, low recall: The scan is very specific and only overlaps with a small part of the profile<br>"
"Low precision, high recall: The scan hits lots of the profile but also has lots of techniques not relevant to the profile<br>"
"Low F1 score: Weak overlap — either the scan or profile has too much or too little in common comparitively<br>"
"High F1 score: The scan and profile strongly align — they match broadly and tightly<br>"
">0.9: Near Perfect<br>"
"0.8 - 0.9: Extremely Good<br>"
"0.7 - 0.8: Very Good<br>"
"0.6 - 0.7: Good<br>"
"0.4 - 0.6: OK<br>"
"<0.4: Not Good<br><br>"
"<b>Loading a Piranha Profile:</b> If you find a Piranha Profile that you would like to load into your instance of Piranha, simply click File > Load Piranha Profile. Once loaded, Piranha will automatically select the APTs and tactics present in the profile, as well as preload the CVEs in the Submit Custom CVEs portion of the Heatmap tab. You can generate a report from there in the Main Analysis tab!"
        )
        help = HelpMenu("Profile Help", profile_help_text)
        help.exec()

    def show_contact_info(self):
        contact_text = (
"<b>Contact Information</b><br><br>"
"<b>Developer:</b> William J. Smail<br><br>"
"<b>Phone:</b> (813) 826-2429. Please call between 0800 to 1530 Monday through Thursday. If there is no answer, please call later or contact by email.<br><br>"
"<b>Email:</b> william.j.smail.mil@socom.mil<br><br>"
"<b>Note:</b> For any changes you would like made to Piranha, please be as specific as possible. Please also include the reasons you would like the changes to be made."
        )
        help = HelpMenu("Contact Developer", contact_text)
        help.exec()
    
class FullScreenGraph(QDialog):
    def __init__(self, scene):
        super().__init__()
        self.setWindowTitle("Full-Screen Node Analysis")
        self.setGeometry(100, 100, 1600, 900)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)

        layout = QVBoxLayout()
        self.setLayout(layout)
        self.fullscreen_graph_view = InteractiveGraphView()
        self.fullscreen_graph_view.setScene(scene)
        self.fullscreen_graph_view.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout.addWidget(self.fullscreen_graph_view)
        self.exit_button = QPushButton("Exit Full Screen")
        self.exit_button.setFixedSize(150, 40)
        self.exit_button.setStyleSheet("background-color: red; color: white; font-size: 14px; border-radius: 5px;")
        self.exit_button.clicked.connect(self.close)
        layout.addWidget(self.exit_button, alignment=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)

class InteractiveGraphView(QGraphicsView):
    def __init__(self):
        super().__init__()
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.NoDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.scale_factor = 1.2
        self.is_panning = False
        self.last_mouse_position = None
        self.setSceneRect(-99999, -99999, 199999, 199999)
        
    def wheelEvent(self, event: QWheelEvent):
        zoom_in_factor = self.scale_factor
        zoom_out_factor = 1 / self.scale_factor

        if event.angleDelta().y() > 0:
            self.scale(zoom_in_factor, zoom_in_factor)
        else:
            self.scale(zoom_out_factor, zoom_out_factor)
    def mousePressEvent(self, event: QMouseEvent):
        if event.button() == Qt.MouseButton.MiddleButton:
            self.is_panning = True
            self.last_mouse_position = event.position()
            self.setCursor(Qt.CursorShape.ClosedHandCursor)
        else:
            super().mousePressEvent(event)
    def mouseMoveEvent(self, event: QMouseEvent):
        if self.is_panning and self.last_mouse_position:
            delta = event.position() - self.last_mouse_position
            self.last_mouse_position = event.position()
            self.horizontalScrollBar().setValue(self.horizontalScrollBar().value() - delta.x())
            self.verticalScrollBar().setValue(self.verticalScrollBar().value() - delta.y())
        else:
            super().mouseMoveEvent(event)
    def mouseReleaseEvent(self, event: QMouseEvent):
        if event.button() == Qt.MouseButton.MiddleButton:
            self.is_panning = False
            self.setCursor(Qt.CursorShape.ArrowCursor)
        else:
            super().mouseReleaseEvent(event)

class EditableTableWidget(QTableWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            index = self.currentIndex()
            if index.isValid():
                self.closeEditor(self.indexWidget(index), QAbstractItemDelegate.EndEditHint.NoHint)
                self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
                self.clearFocus()
                self.setCurrentItem(None)
        else:
            super().keyPressEvent(event)

class InteractiveGraphicsView(QGraphicsView):
    def __init__(self, scene):
        super().__init__(scene)
        self.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.scale_factor = 1.15
        self.setSceneRect(-99999, -99999, 199999, 199999)

    def wheelEvent(self, event):
        factor = self.scale_factor if event.angleDelta().y() > 0 else 1 / self.scale_factor
        self.scale(factor, factor)

class AIEnrichmentThread(QThread):
    result_ready = pyqtSignal(str, str)

    def __init__(self, apt_name, tactic_name, technique):
        super().__init__()
        self.apt_name = apt_name
        self.tactic_name = tactic_name
        self.technique = technique

    def run(self):
        query = f"Generate a comprehensive report on how {self.apt_name} uses the {self.tactic_name} technique {self.technique}, including attack methods, indicators of compromise, and detection strategies. Include in text URL citations for resources."
        logger.info(f"AI Query: {query}")
        enrichment_result = enrich_data_with_ai(query)
        self.result_ready.emit(self.apt_name, enrichment_result)

class EnrichmentPopup(QDialog):
    def __init__(self, apt_name, enrichment_text, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"AI Enrichment - {apt_name} - Experimental")
        self.setFixedSize(600, 400)
        layout = QVBoxLayout()
        self.setLayout(layout)
        title_label = QLabel(f"<b>APT Name:</b> {apt_name}")
        title_label.setStyleSheet("font-size: 14px; color: white;")
        layout.addWidget(title_label)
        self.enrichment_textbox = QTextEdit()
        formatted_text = self.format_enrichment_text(enrichment_text)
        self.enrichment_textbox.setPlainText(formatted_text)
        self.enrichment_textbox.setStyleSheet("font-size: 12px; color: #AAAAAA; background-color: #333;")
        layout.addWidget(self.enrichment_textbox)
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("background-color: #444; color: white; padding: 5px; border-radius: 5px;")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)
        self.setStyleSheet("background-color: #222; border-radius: 10px;")

    def format_enrichment_text(self, text):
        return "\n".join([line.strip() for line in text.split("\n") if line.strip()])
    
class HelpMenu(QDialog):
    def __init__(self, title, message, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(500, 400)

        layout = QVBoxLayout(self)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)

        message_label = QLabel(message)
        message_label.setWordWrap(True)

        scroll_container = QLabel()
        scroll_container.setText(message)
        scroll_container.setWordWrap(True)
        scroll_area.setWidget(scroll_container)

        layout.addWidget(scroll_area)

        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        layout.addWidget(ok_button)

        self.setLayout(layout)
        

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PiranhaApp()
    app.main_window = window
    window.show()
    sys.exit(app.exec())
    

