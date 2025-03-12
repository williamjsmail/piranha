import sys
import pyqtgraph as pg
from pyqtgraph import QtGui
import networkx as nx
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QCheckBox, QLineEdit, QListWidget, QTableWidget, QHeaderView, QAbstractItemDelegate,
    QSizePolicy, QMenu, QListWidgetItem, QGraphicsView, QGraphicsScene, QGraphicsEllipseItem,
    QGraphicsTextItem, QGraphicsLineItem
)
from PyQt6.QtGui import QAction, QPen, QColor, QBrush
from PyQt6.QtCore import Qt
import qdarktheme


# Import your modules
from frontend.generate import generate_mitre_freq_table, generate_report, export_to_excel, InteractiveGraph
from frontend.keywords import *
from frontend.selection import *
from frontend.updates import *
from backend.loader import load_mitre_data
from backend.processor import get_apt_groups


class PiranhaApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Piranha v3.0.0")
        self.setGeometry(100, 100, 1200, 750)  # Adjust width for better layout


        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout()  # Main vertical layout
        main_widget.setLayout(main_layout)

        try:
            qdarktheme.load_stylesheet("dark")
        except:
            qdarktheme.setup_theme("auto")    

        #  Header (Centered)
        header_label = QLabel("Piranha T-Code Mapper")
        header_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        main_layout.addWidget(header_label, alignment=Qt.AlignmentFlag.AlignCenter)


        sub_label = QLabel("v3.0.0, Dev/POC: Sgt Smail, William J")
        sub_label.setStyleSheet("font-size: 10px;")
        main_layout.addWidget(sub_label, alignment=Qt.AlignmentFlag.AlignCenter)


        #  Upper Selection Layout (APT, Tactic, Graph)
        upper_layout = QHBoxLayout()
        main_layout.addLayout(upper_layout, 1)  # Takes priority over lower section


        #  Left Panel (APT Selection)
        left_panel = QVBoxLayout()
        upper_layout.addLayout(left_panel, 1)  # Left section


        apt_label = QLabel("Select APT(s):")
        left_panel.addWidget(apt_label)


        self.apt_listbox = QListWidget()
        self.apt_listbox.setFixedWidth(250)
        self.apt_listbox.setFixedHeight(450)
        self.apt_listbox.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.apt_listbox.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        left_panel.addWidget(self.apt_listbox)


        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText("Search APT(s)...")
        self.search_entry.setFixedWidth(250)
        left_panel.addWidget(self.search_entry)
        self.search_entry.textChanged.connect(lambda: self.update_apt_list(self.search_entry.text()))
        self.selected_apts = set()


        #  Center Panel (Tactic Selection)
        tactic_panel = QVBoxLayout()
        upper_layout.addLayout(tactic_panel, 2)  # Center section


        tactic_label = QLabel("Select Tactic(s):")
        tactic_panel.addWidget(tactic_label)


        self.tactic_listbox = QListWidget()
        self.tactic_listbox.setFixedWidth(250)
        self.tactic_listbox.setFixedHeight(450)
        self.tactic_listbox.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.tactic_listbox.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        tactic_panel.addWidget(self.tactic_listbox)


        #  Right Panel (Graph View) - This is the missing part
        self.graph_scene = InteractiveGraph([])
        self.graph_view = InteractiveGraphicsView(self.graph_scene)
        self.graph_view.setMinimumSize(800, 600)
        self.graph_view.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)


        graph_panel = QVBoxLayout()
        upper_layout.addLayout(graph_panel)  # Larger space for graph


        graph_panel.addWidget(QLabel("APT TCode Similarity Analysis"))
        graph_panel.addWidget(self.graph_view)


        #  Lower Section (Dataset Selection + Table)
        lower_layout = QVBoxLayout()
        main_layout.addLayout(lower_layout, 2)  # Lower section


        dataset_layout = QHBoxLayout()
        lower_layout.addLayout(dataset_layout)


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


        # Table
        self.table = EditableTableWidget()
        #self.table = QTableWidget()
        columns = ["APT", "Category", "T-Code", "Dataset Source", "Description", "IOC", "Detection Tool", "MITRE Detection"]
        self.table.setColumnCount(len(columns))
        self.table.setHorizontalHeaderLabels(columns)
        self.table.cellDoubleClicked.connect(lambda row, col: self.view_full_row())
        self.table.setRowCount(0)
        header = self.table.horizontalHeader()
        header.setStyleSheet("font-weight: bold;")
        self.table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.table.setMinimumHeight(400)
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
            self.table,
            self.graph_view
        ))
        button_layout.addWidget(generate_btn)


        manage_keywords_btn = QPushButton("Manage Keywords")
        manage_keywords_btn.clicked.connect(lambda: manage_keywords_popup(self))
        button_layout.addWidget(manage_keywords_btn)


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


        heatmap_btn = QPushButton("Generate Frequency Table")
        heatmap_btn.clicked.connect(lambda: generate_mitre_freq_table(self.get_table_data()))
        button_layout.addWidget(heatmap_btn)


        export_btn = QPushButton("Export to Excel")
        export_btn.clicked.connect(lambda: export_to_excel(
            self.include_detections, self.use_enterprise
        ))
        button_layout.addWidget(export_btn)


        # Load APTs and Tactics on Startup
        self.load_apts()
        self.load_tactics()
        # Ensure APT selection triggers graph update
        #self.apt_listbox.itemSelectionChanged.connect(self.update_apt_graph)




    def load_apts(self):
        selected_datasets = {
            "enterprise": True,  # Always load Enterprise by default
            "mobile": self.use_mobile.isChecked(),
            "ics": self.use_ics.isChecked()
        }


        self.mitre_data, _ = load_mitre_data(selected_datasets)
        if self.mitre_data is None:
            print("Error: MITRE data is empty. Check dataset paths and JSON format.")
            return
        
        self.apt_groups_for_graph = {}
        for obj in self.mitre_data["objects"]:
            if obj["type"] == "intrusion-set":
                self.apt_groups_for_graph[obj["name"]] = {"id": obj["id"], "techniques": {}}
        self.apt_groups = get_apt_groups(self.mitre_data)
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
        editor = self.table.indexWidget(self.table.currentIndex())
    
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
        self.selected_apts.update({self.apt_listbox.item(i).text() for i in range(self.apt_listbox.count()) if self.apt_listbox.item(i).isSelected()})
        self.apt_listbox.clear()
        if not self.apt_groups:
            return  
        search_term = search_term.strip().lower()
        for apt in sorted(self.apt_groups.keys()):
            if search_term in apt.lower():
                item = QListWidgetItem(apt)
                self.apt_listbox.addItem(item)
                if apt in self.selected_apts:
                    item.setSelected(True)
    

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
    """Enables zooming, panning, and infinite scrolling in the graph view."""
    def __init__(self, scene):
        super().__init__(scene)
        self.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)  # Enables panning
        self.scale_factor = 1.15

        #  Remove invisible boundaries for infinite scrolling
        self.setSceneRect(-99999, -99999, 199999, 199999)  # Large values for "infinite" space

    def wheelEvent(self, event):
        """Zoom in and out with the mouse scroll wheel."""
        factor = self.scale_factor if event.angleDelta().y() > 0 else 1 / self.scale_factor
        self.scale(factor, factor)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PiranhaApp()
    window.show()
    sys.exit(app.exec())
