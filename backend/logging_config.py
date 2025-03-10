import os
import logging

LOG_DIR = os.path.join(os.path.expanduser("~"), "Documents", "PiranhaLogs")

def logging_setup():
    log_dir = LOG_DIR

    try:
        os.makedirs(log_dir, exist_ok=True)
    except Exception as e:
        log_dir = os.getcwd()
        print(f"Warning: Could not create log directory. Using {log_dir}. Error: {e}")

    log_file = os.path.join(log_dir, "APT_Report.log")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file, mode='w', encoding='utf-8'),
            logging.StreamHandler()
        ]
    )

    return logging.getLogger(__name__)

logger = logging_setup()
