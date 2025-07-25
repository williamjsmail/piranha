{
  "profile_name": "Iranian Wiper Attacks",
  "guid": "d8452f23-4439-4a53-9068-f06b2db4084d",
  "description": "Iranian APT groups have increasingly employed disk-wiping malware and pseudo-ransomware in cyberattacks to destroy data on target networks. Actors like APT33 and OilRig (APT34) have used wipers (e.g., Shamoon and ZeroCleare) against regional adversaries and critical infrastructure, often following extended intrusions. These groups frequently exploit known vulnerabilities in internet-facing applications (for instance, Log4Shell) to gain initial access, then execute destructive payloads under the guise of ransomware or hacktivist activity to complicate attribution. The objective is typically to disrupt operations and intimidate victims by rendering systems and data unusable.",
  "created_by": "Piranha Default",
  "version": "1.0",
  "apts": [
    "APT33",
    "APT34",
    "Magic Hound",
    "MuddyWater"
  ],
  "tactics": [
    "Initial Access",
    "Lateral Movement",
    "Impact",
    "Persistence"
  ],
  "cves": [
    "CVE-2021-44228",
    "CVE-2022-47966",
    "CVE-2022-42475"
  ],
  "additional_techniques": [
    "T1190",
    "T1566.001",
    "T1486",
    "T1078"
  ],
  "all_techniques": [
    "T1021.001",
    "T1027",
    "T1036.001",
    "T1053.005",
    "T1078",
    "T1078.001",
    "T1078.002",
    "T1078.004",
    "T1098.002",
    "T1098.007",
    "T1134",
    "T1134.001",
    "T1134.002",
    "T1134.003",
    "T1136.001",
    "T1137.001",
    "T1189",
    "T1190",
    "T1210",
    "T1486",
    "T1505.003",
    "T1528",
    "T1539",
    "T1546.003",
    "T1547.001",
    "T1550.004",
    "T1553.002",
    "T1562.003",
    "T1566.001",
    "T1566.002",
    "T1566.003",
    "T1570",
    "T1574.002",
    "T1574.006",
    "T1574.007",
    "T1606"
  ]
}