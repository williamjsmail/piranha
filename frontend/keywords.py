import os
import json
from PyQt6.QtWidgets import (
    QMessageBox, QDialog, QVBoxLayout, QLabel, QPushButton, QLineEdit, QTextEdit, QListWidget,
    QHBoxLayout, QScrollArea
)
from backend.logging_config import logger
from backend.loader import load_keyword_ioc_mapping

KEYWORD_IOC_MAPPING = load_keyword_ioc_mapping()
KEYWORD_IOC_FILE = os.path.join(os.path.dirname(__file__), "backend", "files", "KEYWORD_IOC_MAPPING.json")

def save_keyword_ioc_mapping():
    try:
        formatted_data = {
            key: {
                "ioc": value["ioc"],
                "tools": list(value["tools"])
            } 
            for key, value in KEYWORD_IOC_MAPPING.items()
        }

        with open(KEYWORD_IOC_FILE, "w", encoding="utf-8") as f:
            json.dump(formatted_data, f, indent=4)

        logger.info("Successfully saved updated keyword-to-IOC mapping.")

    except Exception as e:
        logger.error(f"Failed to save keyword mapping: {e}")

def add_keyword_popup(parent, listbox=None):
    popup = QDialog(parent)
    popup.setWindowTitle("Add New Keyword")
    popup.resize(400, 250)
    layout = QVBoxLayout()
    popup.setLayout(layout)

    keyword_entry = QLineEdit()
    ioc_entry = QLineEdit()
    tool_entry = QLineEdit()
    
    layout.addWidget(QLabel("Enter Keyword:"))
    layout.addWidget(keyword_entry)
    layout.addWidget(QLabel("Enter IOC:"))
    layout.addWidget(ioc_entry)
    layout.addWidget(QLabel("Enter Detection Tool:"))
    layout.addWidget(tool_entry)

    def save_keyword():
        keyword = keyword_entry.text().strip().lower()
        ioc = ioc_entry.text().strip()
        tool = tool_entry.text().strip()

        if not keyword or not ioc or not tool:
            QMessageBox.critical(parent, "Error", "All fields are required!")
            return

        if keyword in KEYWORD_IOC_MAPPING:
            if ioc not in KEYWORD_IOC_MAPPING[keyword]["ioc"]:
                KEYWORD_IOC_MAPPING[keyword]["ioc"].append(ioc)
            if tool not in KEYWORD_IOC_MAPPING[keyword]["tools"]:
                KEYWORD_IOC_MAPPING[keyword]["tools"].add(tool)
            QMessageBox.information(parent, "Info", f"Updated existing keyword '{keyword}'.")
        else:
            KEYWORD_IOC_MAPPING[keyword] = {"ioc": [ioc], "tools": {tool}}
            QMessageBox.information(parent, "Success", f"New keyword '{keyword}' added successfully.")

        save_keyword_ioc_mapping()

        if listbox:
            listbox.addItem(keyword)

        popup.accept()

    save_button = QPushButton("Save")
    save_button.clicked.connect(save_keyword)
    layout.addWidget(save_button)
    popup.exec()

def edit_keyword_popup(parent, listbox):
    selected_items = listbox.selectedItems()
    if not selected_items:
        QMessageBox.critical(parent, "Error", "Please select a keyword to edit.")
        return
    
    selected_keyword = selected_items[0].text()
    popup = QDialog(parent)
    popup.setWindowTitle(f"Edit Keyword: {selected_keyword}")
    popup.resize(500, 400)
    layout = QVBoxLayout()
    popup.setLayout(layout)

    ioc_text = QTextEdit()
    tool_text = QTextEdit()

    layout.addWidget(QLabel(f"Editing Keyword: {selected_keyword}"))
    layout.addWidget(QLabel("Modify IOC List:"))
    layout.addWidget(ioc_text)
    layout.addWidget(QLabel("Modify Detection Tool List:"))
    layout.addWidget(tool_text)

    ioc_text.setText("\n".join(KEYWORD_IOC_MAPPING[selected_keyword]["ioc"]))
    tool_text.setText("\n".join(KEYWORD_IOC_MAPPING[selected_keyword]["tools"]))

    def save_edits():
        new_iocs = [ioc.strip() for ioc in ioc_text.toPlainText().split("\n") if ioc.strip()]
        new_tools = {tool.strip() for tool in tool_text.toPlainText().split("\n") if tool.strip()}

        if not new_iocs or not new_tools:
            QMessageBox.critical(parent, "Error", "IOC and Tool fields cannot be empty.")
            return

        KEYWORD_IOC_MAPPING[selected_keyword]["ioc"] = new_iocs
        KEYWORD_IOC_MAPPING[selected_keyword]["tools"] = new_tools
        save_keyword_ioc_mapping()
        QMessageBox.information(parent, "Success", "Keyword updated successfully!")
        popup.accept()

    save_button = QPushButton("Save Changes")
    save_button.clicked.connect(save_edits)
    layout.addWidget(save_button)
    popup.exec()

def delete_keyword(parent, listbox):
    selected_items = listbox.selectedItems()
    if not selected_items:
        QMessageBox.critical(parent, "Error", "Please select a keyword to delete.")
        return
    
    selected_keyword = selected_items[0].text()
    confirm = QMessageBox.question(parent, "Confirm Delete", f"Are you sure you want to delete '{selected_keyword}'?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    
    if confirm == QMessageBox.StandardButton.Yes:
        del KEYWORD_IOC_MAPPING[selected_keyword]
        save_keyword_ioc_mapping()
        listbox.takeItem(listbox.row(selected_items[0]))
        QMessageBox.information(parent, "Success", f"Keyword '{selected_keyword}' deleted.")

def manage_keywords_popup(parent):
    popup = QDialog(parent)
    popup.setWindowTitle("Manage Keywords")
    popup.resize(600, 400)
    layout = QVBoxLayout()
    popup.setLayout(layout)

    search_entry = QLineEdit()
    search_entry.setPlaceholderText("Search Keywords")
    layout.addWidget(search_entry)

    keyword_listbox = QListWidget()
    layout.addWidget(keyword_listbox)

    keyword_listbox.addItems(sorted(KEYWORD_IOC_MAPPING.keys()))

    button_layout = QHBoxLayout()
    layout.addLayout(button_layout)

    add_btn = QPushButton("Add Keyword")
    add_btn.clicked.connect(lambda: add_keyword_popup(parent, keyword_listbox))
    button_layout.addWidget(add_btn)

    edit_btn = QPushButton("Edit Keyword")
    edit_btn.clicked.connect(lambda: edit_keyword_popup(parent, keyword_listbox))
    button_layout.addWidget(edit_btn)

    delete_btn = QPushButton("Delete Keyword")
    delete_btn.clicked.connect(lambda: delete_keyword(parent, keyword_listbox))
    button_layout.addWidget(delete_btn)

    close_btn = QPushButton("Close")
    close_btn.clicked.connect(popup.accept)
    layout.addWidget(close_btn)

    popup.exec()
