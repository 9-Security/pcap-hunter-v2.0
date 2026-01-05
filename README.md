# PCAP Hunter

**PCAP Hunter** is an advanced, AI-enhanced threat hunting workbench designed to bridge the gap between manual packet analysis and automated security monitoring. It empowers SOC analysts and threat hunters to rapidly ingest, analyze, and extract actionable intelligence from raw PCAP files.

By combining industry-standard network analysis tools (**Zeek**, **Tshark**) with modern **Large Language Models (LLMs)** and **OSINT** APIs, PCAP Hunter automates the tedious parts of packet analysis—parsing, correlation, and enrichment—allowing analysts to focus on detection and response.

---

## 🚀 Key Features

### 1. 🧠 AI-Powered Threat Analysis
- **Automated Reporting**: Generates professional, SOC-ready reports summarizing key findings, suspicious indicators, and risk assessments.
- **Local & Cloud LLM Support**:
  - **Local Privacy**: Fully compatible with local models via [LM Studio](https://lmstudio.ai/) (e.g., Llama 3, Mistral) for air-gapped or privacy-sensitive analysis.
  - **Cloud Power**: Supports OpenAI-compatible APIs for leveraging larger models like GPT-4.
- **Multi-Language Support**: Generates reports in multiple languages (English, Traditional/Simplified Chinese, Japanese, Korean, Italian, Spanish, French, German) with region-specific terminology.
- **Context-Aware**: The AI is fed a structured summary of network flows, Zeek logs, and OSINT data, acting as an expert co-pilot.
- **MITRE ATT&CK Mapping**: Automated mapping of behaviors and indicators to the MITRE ATT&CK framework and Kill Chain phases.
- **Attack Narrative Synthesis**: Professional threat analysis that translates raw events into a coherent, actionable story.
- **Dedicated Analysis Tab**: LLM reports and narratives are isolated in a dedicated "LLM Analysis" tab for clear focus.

### 2. 🎯 IOC Priority Scoring
- **Automated Risk Assessment**: Dynamically ranks indicators (Critical, High, Medium, Low) using a weighted scoring engine.
- **Multi-Factor Analysis**: Scores are derived from OSINT reputation (VirusTotal, AbuseIPDB, GreyNoise), behavioral patterns (C2 beaconing), and forensic context (DGA, JA3 malware matches).

### 3. 📁 Case Management System
- **Investigation Workspace**: Save findings, manage observables, and track the progress of security incidents.
- **Evidence Tracking**: Store relevant flows and artifacts directly into investigation cases.

### 4. 🖨️ Professional PDF Export
- **Stakeholder Ready**: Generate formatted, professional PDF reports containing the full attack narrative, technical summaries, and dashboard visualizations.

### 6. 🔍 Deep Packet Inspection & Flow Analysis
- **Multi-Engine Pipeline**: Uses **PyShark** for granular packet inspection and **Tshark** for high-speed statistics.
- **Protocol Parsing**: Automatically extracts and visualizes metadata for major protocols:
  - **HTTP**: Methods, URIs, User-Agents.
  - **DNS**: Queries, responses, record types.
  - **TLS/SSL**: Server names (SNI), certificate details.
  - **SMB**: File shares and commands.

### 7. 🛡️ Zeek Integration
- **Automated Lifecycle**: Manages the execution of Zeek on uploaded PCAPs without requiring manual command-line intervention.
- **Log Analysis**: Parses and correlates core Zeek logs into interactive data tables:
  - `conn.log`: Connection summaries and state.
  - `dns.log`: Name resolution activity.
  - `http.log`: Web traffic details.
  - `ssl.log`: Encrypted traffic metadata.

### 8. 🕵️ Advanced DNS & TLS Forensics
- **DNS Analytics**:
  - **DGA Detection**: Uses Shannon Entropy to identify Domain Generation Algorithms.
  - **DNS Tunneling**: Detects high-volume/anomalous DNS payloads.
  - **Fast Flux**: Identifies domains resolving to rapidly changing IP addresses.
- **TLS Fingerprinting**:
  - **JA3/JA3S**: Calculates and matches SSL/TLS fingerprints against known malware database.
  - **Certificate Analysis**: Validates certificate chains and detects self-signed or expired certificates.

### 9. 📡 C2 Beaconing Detection
- **Heuristic Analysis**: Implements a statistical algorithm to detect Command & Control (C2) beaconing behavior.
- **Scoring Engine**: Ranks flows based on:
  - **Periodicity**: Regularity of communication intervals (low variance).
  - **Jitter**: Randomization attempts by C2 agents.
  - **Volume**: Consistency of payload sizes.

### 10. 📦 Payload Carving & Forensics
- **YARA Scanner**: Scan extracted files with custom YARA rules for immediate malware identification.
- **File Extraction**: Uses `tshark` to carve HTTP file bodies from the traffic.
- **Artifact Hashing**: Automatically calculates SHA256 hashes of extracted files for reputation checking.
- **Safe Storage**: Carved files are stored locally in a quarantined directory for manual analysis.

### 11. 🌍 Interactive World Map & Dashboard
- **Global Visibility**: Visualizes traffic sources and destinations on a large, interactive world map.
- **Traffic Volume**: Line thickness varies based on connection volume, highlighting major data flows.
- **Cross-Filtering**:
  - **Unified Drill-Down**: Selecting data in any chart (Map, Pie, or Timeline) filters the entire dashboard.
  - **Protocol Filter**: Click a slice in the Protocol Pie Chart to isolate that protocol.
  - **Time Filter**: Select a range on the Flow Timeline to focus on a specific time window.
- **Persistent View Options**:
  - **Exclude Private IPs**: A dedicated toggle at the top of the dashboard allows ignoring local traffic in analytics. The setting remains active during interactive exploration.
- **Reset Capability**: Includes a "Clear All Filters" button to easily reset the dashboard view, including the private IP toggle.

### 12. 📊 Integrated TopN & Metrics
- **Aggregated Views**: Horizontal bar charts and tables for Top IPs, Ports, Protocols, and Domains.
- **Packet Length Distribution**: Visualizes the payload size distribution across captured traffic.

### 13. 🌐 OSINT Enrichment
Integrates with leading threat intelligence providers to validate indicators of compromise (IOCs):
- [x] 📖 **[User Manual (English)](docs/en/USER_MANUAL.md)** | **[中文說明 (Traditional Chinese)](docs/zh-TW/README.md)**
- **VirusTotal**: File hash and IP/Domain reputation.
- **AbuseIPDB**: Crowdsourced IP abuse reports.
- **GreyNoise**: Identification of internet background noise and scanners.
- **OTX (AlienVault)**: Open Threat Exchange pulses and indicators.
- **Shodan**: Internet-facing device details and open ports.
- **Smart Caching**: SQLite-backed caching system to preserve API quotas and speed up repeated lookups.

---

## 🛠️ Installation

### Prerequisites
- **Python 3.10+**
- **Zeek**: `brew install zeek` (macOS) or via package manager (Linux).
- **Tshark**: `brew install wireshark` (macOS) or `sudo apt install tshark` (Linux).
- **Pango**: `brew install pango` (macOS) - Required for PDF generation (WeasyPrint).
- **LM Studio** (Optional): For local LLM inference.

### Quick Start
1. **Clone the repo**:
   ```bash
   git clone https://github.com/ninedter/pcap-hunter.git
   cd pcap-hunter
   ```
2. **Install dependencies**:
   ```bash
   make install
   ```
3. **Run the application**:
   ```bash
   make run
   ```

---

## 📖 Usage Guide

1. **Upload**: 
   - Drag and drop a `.pcap` file in the **Upload** tab.
2. **Configure**:
    - Set your LLM endpoint (default: `http://localhost:1234/v1`).
    - **Home Location**: Set your geographic location using cascading Continent -> Country -> City selectors for accurate map connectivity visualization.
    - Add API keys for OSINT services (optional but recommended).
    - Toggle specific analysis phases (e.g., enable/disable "OSINT Cache", "Carving").
    - **Re-run Report**: If you change the language or model, click "Re-run Report" to regenerate just the LLM report without re-processing the PCAP.
    - **Data Management**: Use granular "Clear" buttons in the Config tab to wipe PCAP data, OSINT cache, or the entire Cases database independently.
3. **Analyze**: Click **Extract & Analyze**.
4. **Monitor**: Watch the **Progress** tab as the pipeline executes:
   - *Packet Counting* -> *Parsing* -> *Zeek* -> *DNS/JA3* -> *Beaconing* -> *Carving* -> *OSINT* -> *Reporting*.
5. **Review**: Read the generated **Threat Report** and explore the raw data tables for deep dives.

---

## ⚙️ Configuration
Defaults are managed in `app/config.py`. Key settings include:
- `DATA_DIR`: Location for storing analysis artifacts (default: `./data`).
- `OSINT_CACHE_ENABLED`: Toggle for SQLite caching (default: True).
- `DEFAULT_PYSHARK_LIMIT`: Max packets to parse deeply (default: 200,000).
- `OSINT_TOP_IPS_DEFAULT`: Number of top talkers to enrich (default: 50).

## 🧑‍💻 Development
- **Test**: `PYTHONPATH=. make test`
- **Lint**: `make lint`
- **Format**: `make format`
- **Clean**: `make clean`


---

## 🔧 Troubleshooting

## 📄 License
MIT License. See `LICENSE` for details.
