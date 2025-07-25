from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QTextEdit, QPushButton, QMessageBox
from backend.loader import load_tcodes_for_cve

class CveTechniqueMapperDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("CVE to Technique Mapper")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Instructions
        instructions = QLabel("Enter one or more CVEs (one per line):")
        layout.addWidget(instructions)

        # Input field for CVEs
        self.cve_input = QTextEdit()
        self.cve_input.setPlaceholderText("Example:\nCVE-2023-12345\nCVE-2021-54321")
        self.cve_input.setMinimumHeight(100)
        layout.addWidget(self.cve_input)

        # Map button
        map_button = QPushButton("Map CVEs to Techniques")
        map_button.clicked.connect(self.map_cves)
        layout.addWidget(map_button)

        # Results box
        self.results_box = QTextEdit()
        self.results_box.setReadOnly(True)
        self.results_box.setMinimumHeight(200)
        layout.addWidget(self.results_box)

        self.setLayout(layout)
        self.setMinimumSize(400, 500)

    def map_cves(self):
        # Get CVEs from input
        raw_cves = self.cve_input.toPlainText().strip().splitlines()
        cves = [cve.strip() for cve in raw_cves if cve.strip().startswith("CVE")]

        if not cves:
            QMessageBox.warning(self, "Invalid Input", "Please enter at least one valid CVE (e.g., CVE-2023-12345).")
            self.results_box.clear()
            return

        # Map CVEs to techniques
        unique_techniques = set()
        for cve in cves:
            try:
                tcodes = load_tcodes_for_cve(cve)
                unique_techniques.update(tcodes)
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to map {cve}: {str(e)}")

        # Display results
        if unique_techniques:
            self.results_box.setText("\n".join(sorted(unique_techniques)))
        else:
            self.results_box.setText("No techniques found for the provided CVEs.")