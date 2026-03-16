# 🛡 SOC Log Analyzer & Threat Detection System

A purple-haze **mini SIEM** built for SOC / Blue Team portfolios. It simulates hostile authentication traffic, analyzes logs for suspicious behavior, and renders a dashboard inspired by modern security platforms.

## What this project includes

- **Complete GitHub-ready project structure**
- **Fake attack simulator** to generate realistic auth and API logs
- **Python detection engine** for brute-force and suspicious IP detection
- **Streamlit SOC dashboard** with a dark Splunk-style / security-platform UI
- **Sample generated dataset** so it runs immediately

## Preview modules

- Critical / High / Medium / Low event cards
- Top Address Activity heatmap
- Global suspicious IP map
- External exposure panel
- Investigation event table
- Raw log stream viewer

## Folder structure

```text
soc-log-analyzer/
├── analyzer/
│   └── detector.py
├── dashboard/
│   └── app.py
├── simulator/
│   └── attack_simulator.py
├── data/
│   └── generated_logs.csv
├── requirements.txt
└── README.md
```

## Tech stack

- Python
- Pandas
- Streamlit
- Plotly

## Detection logic

### 1) Brute-force detection
An IP is flagged when it exceeds the failed-login threshold within a rolling 5-minute window.

### 2) Suspicious IP scoring
IPs are scored based on:
- failed login count
- distinct targeted usernames
- success ratio
- total event volume

## Quick start

### 1. Create a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate  # Linux / macOS
# .venv\Scripts\activate   # Windows
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Generate logs

```bash
python simulator/attack_simulator.py --output data/generated_logs.csv --events 1500
```

### 4. Launch the dashboard

```bash
streamlit run dashboard/app.py
```

**SOC Log Analyzer & Threat Detection System**  
Developed a Python-based SIEM-style platform that simulates attack traffic, analyzes authentication logs for brute-force and suspicious IP activity, and visualizes real-time detections in a Splunk-inspired SOC dashboard using Streamlit and Plotly.

## Why this looks strong on GitHub

- Feels like a real SOC analyst project, not just a script
- Has visual output recruiters can understand quickly
- Demonstrates log analysis, detection engineering, and dashboarding in one repo
- Includes realistic test data generation so reviewers can run it instantly

## Suggested screenshots for GitHub

- dashboard overview
- heatmap panel
- IP geo map
- active alerts panel
- event investigation table

## Future upgrades

- Elastic / Logstash integration
- Sigma-style rules
- threat intel feed enrichment
- email / Slack alerting
- MITRE ATT&CK tagging
