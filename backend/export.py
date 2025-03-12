import pandas as pd
from PyQt6.QtWidgets import QFileDialog, QMessageBox
from backend.logging_config import logger

def save_to_excel(table):
    """Save the generated output table to an Excel file."""
    if table.rowCount() == 0:
        logger.error("No data to export.")
        return

    # Ask the user where to save the file
    file_path, _ = QFileDialog.getSaveFileName(None, "Save Report", "", "Excel Files (*.xlsx);;All Files (*)")

    if not file_path:
        return  # User canceled the save dialog
    
    # Extract table data
    headers = [table.horizontalHeaderItem(i).text() for i in range(table.columnCount())]
    data = []

    for row in range(table.rowCount()):
        row_data = []
        for col in range(table.columnCount()):
            item = table.item(row, col)
            row_data.append(item.text() if item else "")
        data.append(row_data)

    # Create a DataFrame and save it to an Excel file
    df = pd.DataFrame(data, columns=headers)
    df.to_excel(file_path, index=False, engine="openpyxl")

    if file_path:
        QMessageBox.information(None, "Success", f"Data saved to {file_path}")
    else:
        QMessageBox.critical(None, "Error", f"Data failed to save to {file_path}")
