# PIRANHA 🐟  
Piranha is an advanced cyber threat analysis and hunt planning tool that bridges the gap between intelligence analysts and defensive cyber operators. By simplifying the translation of Priority Intelligence Requirements (PIRs) into actionable hunt strategies, Piranha accelerates mission planning, enhances detection coverage, and supports data-driven decision making in cyber defense operations.

![piranha](images/piranha_logo.png)
![Piranha Desktop](https://startme-uploaded-files.s3.amazonaws.com/Uploaded-file-7881758-2025-9-8-599b2952f6d9e032.png)

## 🔍 Key Features

- **APT-Centric Analysis:** Instantly retrieve TTPs for selected threat actors.
- **IoM Graph Viewer:** Visualize adversary behavior by methodology, including overlaps & relationships.
- **Tactic Optimization Engine:** Get optimized tactic combinations for detection.
- **Radar Chart Visualization:** Analyze threat or hunt plan distribution across core data categories:
  - Host & Network Collection  
  - Host Interrogation  
  - Memory Analysis
- **Nessus Scan Integration:** Import XML scans, map CVEs to ATT&CK techniques, and generate heatmaps.
- **Threat Profile Builder:** Create and compare reusable threat profiles for defense planning.
- **Export/Import:** Export reports as Excel, import/craft profiles (.pir).
- **AI Enrichment:** Enrich report data using OpenAI's API.

## 🧠 Why Piranha?

Cyber intel teams often know **who** the threat actor is and **what** they're trying to do, but lack the technical time or tooling to pivot that into an effective hunt plan. Piranha simplifies this process by:

- Automatically mapping APTs to techniques and tools.
- Suggesting ideal tactic combinations based on analyst goals.
- Enabling live visual and data-driven analysis.
- Bridging data silos between threat intelligence and network defense.

## 📦 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/HackingForNoobs/piranha.git
cd piranha
git checkout fix/repository-repair
```

### 2. Install Python 3.8+ (if needed)

- [Download Python](https://www.python.org/downloads/) (choose "Add Python to PATH" during installation)
- Confirm installation: `python --version`

### 3. Set Up a Python Virtual Environment

Windows
```
python -m venv venv
.\venv\Scripts\activate
```

macOS/Linux
```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies
```
pip install --upgrade pip
pip install -r requirements.txt
```

### 5. [Optional] Install Qt Libraries (for Linux/Headless)

If you get Qt-related errors (on servers or minimal distros):
```bash
sudo apt-get install -y libxcb*-dev libx11-xcb-dev libglu1-mesa-dev libxrender-dev libxi-dev libxkbcommon-dev libxkbcommon-x11-dev
```

### 6. Run the Application

On desktop
```
python piranha.py
```

On headless environments
```
QT_QPA_PLATFORM=offscreen python piranha.py
```

### 7. Deactivate environment when done
```
deactivate
```

## Project Structure

```plaintext
├── piranha.py          # Main app entry point
├── requirements.txt    # Python requirements
├── backend/            # Backend logic and helpers
├── frontend/           # Frontend logic and UI modules
├── backend/files/      # Data JSONs (enterprise-attack.json, etc.)
├── profiles/           # Saved profile examples
├── tests/              # Automated tests
└── README.md           # Project documentation
