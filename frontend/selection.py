from PyQt6.QtWidgets import QListWidget, QMessageBox, QDialog, QLabel, QTextEdit, QPushButton, QVBoxLayout, QTreeWidgetItem

def deselect_all_apts(apt_listbox: QListWidget):
    for i in range(apt_listbox.count()):
        apt_listbox.item(i).setSelected(False)

def select_all_apts(apt_listbox: QListWidget):
    for i in range(apt_listbox.count()):
        apt_listbox.item(i).setSelected(True)

def view_full_row(parent, tree):
    selected_items = tree.selectedItems()
    if not selected_items:
        QMessageBox.critical(parent, "Error", "No row selected.")
        return

    item: QTreeWidgetItem = selected_items[0]  # Get the first selected item
    row_data = [item.text(column) for column in range(tree.columnCount())]

    popup = QDialog(parent)
    popup.setWindowTitle("Row Details")
    popup.resize(600, 400)

    layout = QVBoxLayout()
    popup.setLayout(layout)

    layout.addWidget(QLabel("Full Row Details", alignment=1))

    text_area = QTextEdit()
    text_area.setReadOnly(True)
    layout.addWidget(text_area)

    column_headers = ["APT", "Category", "T-Code", "Dataset Source", "T-Code Description", "IOC", "Detection Tool", "MITRE Detection"]
    formatted_text = "\n".join(f"{header}: {value}" for header, value in zip(column_headers, row_data))

    text_area.setText(formatted_text)

    close_btn = QPushButton("Close")
    close_btn.clicked.connect(popup.accept)
    layout.addWidget(close_btn)

    popup.exec()