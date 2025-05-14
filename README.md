
# Piranha

## Overview
Piranha is a cyber threat intelligence and hunt plan development platform that bridges the fap between intelligence requirements and actionable detection strategies. It connects APTs, MITRE ATT&CK techniques, CVEs, Nessus scans, and CTI reports into a unified platform that empowers analysts of all skill levels to:
 
 - Build an Analytic Scheme of Maneuver (ASOM) in minutes
 - Enirch data with AI
 - Map vulnerabilities to adversary behaviors
 - Visualize relevant techniques on a 3D heatmap
 - Optimize hunt plans based on operational requirements
 - Build custom threat profiles
 - Etc.

## Importing Data
A user has the ability to import a few different files:

- .nessus/.xml for Nessus vulnerability scans
- .json for Barracuda exports
- .pir for importing Piranha Profiles

### Setup
```bash
pip install -r requirements.txt
python piranha.py
```

### Updates
Piranha is updated regularly with new features and bug fixes.
MITRE data is updated according to the regular MITRE update schedule (last updated April 22, 2025).
CVE mappings should be updated manually at least once weekly. Automatic updates will be included as a future feature.
```bash
python .\CVE2CAPEC\retrieve_cve.py
python .\CVE2CAPEC\cve2cwe.py
python .\CVE2CAPEC\cwe2capec.py
python .\CVE2CAPEC\capec2technique.py
```

## Authors

- [@williamjsmail](https://github.com/williamjsmail)

## Demo

For a live demonstation/brief, please contact 700CPT leadership.

