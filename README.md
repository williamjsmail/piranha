# PIRANHA 🐟  

![piranha](images/piranha_logo.png)

Piranha is an advanced cyber threat analysis and hunt planning tool that bridges the gap between intelligence analysts and defensive cyber operators. By simplifying the translation of Priority Intelligence Requirements (PIRs) into actionable hunt strategies, Piranha accelerates mission planning, enhances detection coverage, and supports data-driven decision making in cyber defense operations.

---

## 🔍 Key Features

- **APT-Centric Analysis**  
  Select one or more APTs to instantly retrieve their associated MITRE ATT&CK tactics and techniques, including overlaps and patterns.

- **IoM Graph Viewer**  
  Visualize attack behavior using Indicators of Methodology (IoMs), with graph-based tracking of adversary TTP overlap.

- **Tactic Optimization Engine**  
  Input a desired number of tactics and receive an optimized combination that closely aligns with an ideal detection strategy.

- **Radar Chart Visualization**  
  See how a threat profile or hunt plan distributes across data component categories:  
  - Host Collection  
  - Network Collection  
  - Host Interrogation  
  - Memory Analysis

- **Nessus Scan Integration**  
  Import Nessus XML scans to:
  - Extract CVEs and map to ATT&CK techniques using `cve2capec`.
  - Generate heatmaps based on APT usage, CVSS scores, and detection relevance.

- **Threat Profile Builder**  
  Define reusable profiles by combining APTs, tactics, and techniques for mission-specific or domain-focused threat modeling.

- **Compare to Profile**  
  Match imported scans against threat profiles and calculate a match score using F1 comparison logic.

- **Extra Tools**
  - Quick CVE mapper
  - Automated CVE -> Technique DB Updating.
  - AI Enrichment
---

## 🧠 Why Piranha?

Cyber intel teams often know **who** the threat actor is and **what** they're trying to do, but lack the technical time or tooling to pivot that into an effective hunt plan. Piranha simplifies this process by:

- Automatically mapping APTs to techniques and tools.
- Suggesting ideal tactic combinations based on analyst goals.
- Enabling live visual and data-driven analysis.
- Bridging data silos between threat intelligence and network defense.
---

## To Do
- Add support for multiple GPTs

## 📦 Installation

```bash
git clone https://github.com/williamjsmail/piranha
cd piranha
pip install -r requirements.txt
python piranha.py
```
