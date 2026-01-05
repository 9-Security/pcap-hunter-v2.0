# PCAP Hunter User Manual

**PCAP Hunter** is an advanced threat hunting workbench that bridges the gap between manual packet analysis and automated security monitoring. It combines industry-standard tools (**Zeek**, **Tshark**) with modern AI (**LLMs**) and threat intelligence (**OSINT**) to rapidly ingest, analyze, and extract actionable intelligence from network traffic.

---

## 📚 Table of Contents
1. [Getting Started](#getting-started)
   - [Prerequisites](#prerequisites)
   - [Installation & Launch](#installation--launch)
2. [Core Workflows](#core-workflows)
   - [Data Ingestion (Upload)](#1-data-ingestion)
   - [Analysis Pipeline](#2-analysis-pipeline)
3. [Analysis Dashboard](#analysis-dashboard)
   - [Global Map & Filters](#global-map--filters)
   - [Charts & Visualizations](#charts--visualizations)
   - [Top Metrics](#top-metrics)
4. [Advanced Features](#advanced-features)
   - [AI Threat Report](#ai-threat-report)
   - [OSINT Enrichment](#osint-enrichment)
   - [Forensics (DNS, TLS, YARA, Carving)](#forensics)
5. [Configuration](#configuration)
   - [LLM Setup](#llm-setup)
   - [OSINT Keys](#osint-keys)
   - [Map Location](#map-location)
   - [Data Management](#data-management)
6. [Troubleshooting](#troubleshooting)

---

## Getting Started

### Prerequisites
Ensure the following tools are installed on your system:
- **Python 3.10+**: The core runtime.
- **Zeek**: Network security monitor for generating logs (`brew install zeek`).
- **Wireshark/Tshark**: Packet analyzer for parsing and statistics (`brew install wireshark`).
- **Pango**: Library required for PDF report generation (`brew install pango`).
- **LM Studio** (Optional): For running local AI models privacy-first.

### Installation & Launch
1. **Clone the repository**:
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
   The application will open in your default browser at `http://localhost:8501`.

---

## Core Workflows

### 1. Data Ingestion
Navigate to the **Load PCAP** tab to start.

#### File Upload
- **Drag & Drop**: Simply drag a `.pcap` or `.pcapng` file into the upload area.
- **Manual Path**: For large files (>200MB) that browsers struggle to upload, type the absolute path to the file on your disk (e.g., `/Users/name/capture.pcap`) and press Enter.

### 2. Analysis Pipeline
By default, PCAP Hunter executes a complete analysis pipeline. You can customize which phases run (e.g., disable Zeek or Carving) in the **Config** tab under the **Extraction / Analysis** section.

Click **Extract & Analyze** to begin. Monitor progress in the **Progress** tab.

---

## Analysis Dashboard

The **Dashboard** tab is your central mission control.

### Global Map & Filters
- **Interactive World Map**: Visualizes the geographic destination of your traffic.
  - **Selection**: Use **Box Select** or **Lasso Select** tools to highlight a region. This **cross-filters** the entire dashboard (charts, tables, timeline) to show only traffic relevant to that area.
  - **Home Location**: Configure your physical location in the **Config** tab to draw accurate connection lines.
- **Global Filters**:
  - **Exclude Private IPs**: Toggle this checkbox to hide RFC1918 (local LAN) traffic from the map and "Top 10" charts. This helps focus on external threats.
  - **Clear All Filters**: Instantly resets the dashboard view, clearing IP, protocol, and time selections.

### Charts & Visualizations
- **Protocol Distribution**: A pie chart showing protocol breakdown (TCP, UDP, TLS, HTTP, etc.). Click a slice to filter the dashboard by that protocol.
- **Flow Timeline**: A time-series chart showing traffic volume over time.
  - **Zoom**: Click and drag to create a time window. The dashboard will update to show only traffic from that specific period.

### Top Metrics
- **Top 10 Tables**: Tables and bar charts displaying the most active:
  - **Source IPs**
  - **Destination IPs**
  - **Destination Ports**
  - **Protocols** or **Domains**

---

## Advanced Features

### AI Threat Report
Located in the **LLM Analysis** tab.
- **Professional Narrative**: The AI synthesizes a coherent story of the network activity, rather than just listing logs.
- **Sections**: Includes Executive Summary, Key Findings, Indicators of Compromise (IOCs), Risk Assessment, and Recommended Actions.
- **PDF Export**: Click **Generate PDF Report** to download a formatted report. The PDF includes:
  - Cover Page with classification (TLP:CLEAR).
  - Full AI narrative.
  - Tables for detected IOCs (IPs, Domains, Hashes).
  - YARA Scan results.
  - TLS Analysis (expired/self-signed certs).

### OSINT Enrichment
Located in the **OSINT** tab.
- **IP Intelligence**: Displays reputation scores from VirusTotal, GreyNoise (noise vs. malicious), and PTR records.
- **Domain Intelligence**: Categories and reputation for queried domains.
- **WHOIS**: Click on an IP or Domain to view registration details in a popup.

### Forensics
- **DNS Analysis**:
  - **DGA Detection**: Uses Shannon Entropy to identify randomly generated domains used by malware.
  - **Tunneling**: Flags unusually large or frequent DNS queries indicative of data exfiltration.
- **TLS Analysis**:
  - **JA3 Fingerprinting**: Identifies client applications based on SSL hello packets.
  - **Certificate Hygiene**: Alerts on self-signed, expired, or unusual certificates.
- **YARA Scanning**: Automatically scans files extracted from HTTP traffic.
  - **Carved Files**: Stored in `./data/carved/`.
  - **Rules**: Uses custom or standard YARA rules to detect known malware families.

---

## Configuration

Customize the application in the **Config** tab.

### LLM Setup
- **Endpoint**: Default is `http://localhost:1234/v1` (LM Studio). consistent with OpenAI API standards.
- **Model**: Type the model name (e.g., `llama-3.2-3b-instruct`) or click **Fetch Models** to auto-populate from the server.
- **Language**: Select from **9 supported languages** (English, Chinese, Japanese, Korean, Italian, Spanish, French, German) for the report.
  - **Re-run Report**: If you change the language or model, use this button to regenerate *only* the report without re-processing the PCAP.

### OSINT Keys
Enter your API keys to enable enrichment. Keys are saved securely in your local configuration.
- **VirusTotal**: For file has and IP/Domain reputation.
- **AbuseIPDB**: For community-reported malicious IPs.
- **GreyNoise**: To identify internet scanners (benign vs. malicious).
- **Shodan**: For device fingerprinting.
- **OTX**: AlienVault Open Threat Exchange.

### Extraction / Analysis
Enable or disable specific pipeline steps to speed up analysis or skip unnecessary processing:
- **PyShark Parsing**: Deep packet inspection (Required for flow charts).
- **Packet Limit**: Max packets to parse (Default: 200,000) to prevents memory exhaustion.
- **Zeek Processing**: Toggles Zeek log generation.
- **Carve HTTP bodies**: Extracts files from HTTP traffic.
- **YARA Scan**: Scans carved files (requires Carving to be enabled).
- **Pre-count packets**: Counts total packets before parsing.
- **OSINT Cache**: Toggles local caching of API results.

### Map Location
Set your **Home Location** using the cascading selectors:
- **Continent** -> **Country** -> **City**
- This fixes the origin point for connection lines on the map.

### Data Management
Granular controls to manage disk usage:
- **Save/Load Config**: Persist your settings (keys, location, preferences) across sessions.
- **Clear PCAP Data**: Deletes all uploaded PCAPs, Zeek logs, and carved files to free disk space.
- **Clear OSINT Cache**: PCAP Hunter caches API responses to save quota. Use this to force fresh lookups.
- **Clear Cases**: Wipes the internal database of all investigation cases and notes.

---

## Troubleshooting

- **"Binaries not found"**:
  - The app attempts to auto-detect `zeek` and `tshark`.
  - If it fails, check the **System Health** section in the **Config** tab.
  - You can manually enter the binary paths (e.g., `/opt/homebrew/bin/zeek`) in the Config tab.
- **"LLM Generation Failed"**:
  - Ensure LM Studio is running and the "Start Server" button is active.
  - Verify the Base URL matches the one in LM Studio.
- **"PDF Generation Error"**:
  - Requires the `pango` library. Run: `brew install pango`.

---
*PCAP Hunter v0.5.1-alpha*
