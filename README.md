````markdown
# 🛡 SOC Log Analyzer & Threat Detection System

```

▒█▀▀▀█ ▒█▀▀▀█ ▒█▀▀█ 　 ▒█░░░ ▒█▀▀▀█ ▒█▀▀█ 　 ░█▀▀█ ▒█▄░▒█ ░█▀▀█ ▒█░░░ ▒█░░▒█ ▒█▀▀▀█ ▒█▀▀▀ ▒█▀▀█ 
░▀▀▀▄▄ ▒█░░▒█ ▒█░░░ 　 ▒█░░░ ▒█░░▒█ ▒█░▄▄ 　 ▒█▄▄█ ▒█▒█▒█ ▒█▄▄█ ▒█░░░ ▒█▄▄▄█ ░▄▄▄▀▀ ▒█▀▀▀ ▒█▄▄▀ 
▒█▄▄▄█ ▒█▄▄▄█ ▒█▄▄█ 　 ▒█▄▄█ ▒█▄▄▄█ ▒█▄▄█ 　 ▒█░▒█ ▒█░░▀█ ▒█░▒█ ▒█▄▄█ ░░▒█░░ ▒█▄▄▄█ ▒█▄▄▄ ▒█░▒█                   
````

A **mini SIEM-style threat detection platform** built for **SOC / Blue Team portfolios**.

This project simulates hostile authentication traffic, analyzes logs for suspicious activity, and visualizes detections in an interactive **Security Operations Center dashboard**.

---

# 🚀 Project Badges

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red)
![Security](https://img.shields.io/badge/Cybersecurity-SOC%20Project-purple)
![License](https://img.shields.io/badge/License-MIT-green)

---

# 🧠 Project Overview

The **SOC Log Analyzer** demonstrates practical **Security Operations Center (SOC)** capabilities:

* Log analysis
* Threat detection
* Security monitoring
* Incident investigation
* Attack simulation
* Dashboard visualization

This project is designed to showcase skills for roles like:

* SOC Analyst
* Security Operations Engineer
* Blue Team Analyst
* Detection Engineer

---

# 🏗 System Architecture

```
Attack Simulator
      │
      ▼
Generated Security Logs
      │
      ▼
Detection Engine (Python + Pandas)
      │
      ▼
Threat Analysis & Scoring
      │
      ▼
SOC Monitoring Dashboard (Streamlit)
```

---

# 📂 Project Structure

```
soc-log-analyzer/
│
├── analyzer/
│   └── detector.py
│
├── dashboard/
│   └── app.py
│
├── simulator/
│   └── attack_simulator.py
│
├── data/
│   └── generated_logs.csv
│
├── requirements.txt
│
└── README.md
```

---

# ⚙ Technology Stack

| Technology | Purpose          |
| ---------- | ---------------- |
| Python     | Detection engine |
| Pandas     | Log analysis     |
| Streamlit  | SOC dashboard    |
| Plotly     | Visualizations   |
| CSV Logs   | Event storage    |

---

# 🔍 Detection Engine

## Brute Force Detection

An IP address is flagged when the number of **failed login attempts exceeds a threshold within a rolling time window**.

Example detection:

```
Source IP: 185.92.220.10
Failed Attempts: 14
Time Window: 3 minutes

ALERT → Brute Force Attack
```

---

## Suspicious IP Scoring

Each IP receives a risk score based on:

* Failed login attempts
* Distinct targeted accounts
* Event frequency
* Success-to-failure ratio

Higher score → higher threat severity.

---

# 📊 SOC Dashboard

The interactive dashboard provides:

* Threat severity cards (Critical / High / Medium / Low)
* Login activity heatmap
* Suspicious IP geographic visualization
* Security investigation table
* Raw log viewer

The UI is inspired by professional tools such as:

* Splunk
* Elastic Security
* Microsoft Sentinel

---

# 🖥 Dashboard Preview

*(Add screenshots or a GIF here after running the dashboard)*

Example preview section:

```
docs/
├── dashboard_overview.png
├── attack_heatmap.png
├── suspicious_ip_map.png
```

Then embed images:

```markdown
![Dashboard Overview](docs/dashboard_overview.png)
![Attack Heatmap](docs/attack_heatmap.png)
![Suspicious IP Map](docs/suspicious_ip_map.png)
```

---

# 🧪 Setup & Installation

## 1️⃣ Clone the repository

```bash
git clone https://github.com/hr10j44t/SOC-log-analyzer.git
cd SOC-log-analyzer
```

---

## 2️⃣ Create virtual environment

```bash
python -m venv .venv
```

Activate environment

Linux

```bash
source .venv/bin/activate
```

Windows

```bash
.venv\Scripts\activate
```

---

## 3️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

---

## 4️⃣ Generate simulated attack logs

```bash
python simulator/attack_simulator.py --output data/generated_logs.csv --events 1500
```

This generates authentication events to simulate attack traffic.

---

## 5️⃣ Launch the SOC dashboard

```bash
streamlit run dashboard/app.py
```

The dashboard will automatically open in your browser.

---

# 🌐 Live Demo

If deployed, add the link here:

```
Live Demo → https://your-demo-link.streamlit.app
```

Streamlit Cloud is recommended for quick deployment.

---

# 🔮 Future Improvements

Potential enhancements:

* Elastic Stack integration
* Sigma rule detection support
* Threat intelligence enrichment
* Email / Slack alerts
* MITRE ATT&CK mapping
* Cloud log ingestion (AWS / Azure)

---

# 👨‍💻 Author

**Uday aka HR10J44T**<br>
Cyber Security Analyst

Focus Areas:

* Threat Detection
* Security Monitoring
* AI + Cybersecurity Systems
* Penetration Testing

---

# ⭐ Support

If you like this project:


*⭐ Star the repository*
*🍴 Fork the project*
*🔐 Contribute detection rules*

**Security is not a product, It is a continuous process.**

