# 🎯 PCAP Hunter User Manual

Welcome to **PCAP Hunter**, a state-of-the-art packet analysis and threat-hunting workbench. This manual will guide you through the initial setup, data ingestion, interactive analysis, and reporting capabilities of the platform.

---

## 🚀 1. Getting Started

PCAP Hunter is designed to handle both static PCAP files and live network traffic. Before you begin, ensure you have configured your environment in the **Config** tab.

### 📁 Uploading a PCAP
The landing page allows you to quickly start an investigation by uploading a `.pcap` or `.pcapng` file.

![Upload Tab](/Users/ninedter/.gemini/antigravity/brain/d6d2775b-1512-446c-a2fd-a40c06fe0892/upload_tab_1767606114125.png)

*   **Drag and Drop**: Simply drag your file into the upload area.
*   **Live Capture**: Switch to the "Live Capture" sub-tab to ingest traffic directly from a network interface (requires appropriate permissions).

---

## ⚙️ 2. Configuration

Robust analysis requires proper setup. Navigate to the **Config** tab to manage your environment.

````carousel
![LLM & OSINT Settings](/Users/ninedter/.gemini/antigravity/brain/d6d2775b-1512-446c-a2fd-a40c06fe0892/config_tab_upper_1767606212440.png)
<!-- slide -->
![Binary Paths & Limits](/Users/ninedter/.gemini/antigravity/brain/d6d2775b-1512-446c-a2fd-a40c06fe0892/config_tab_lower_1767606231075.png)
````

### Key Settings:
*   **LLM Configuration**: Set your API endpoint and model (supports OpenAI-compatible APIs like LM Studio or Ollama).
*   **Home Location**: Select your **Continent**, **Country**, and **City**. This anchors private IP traffic to your local position on the world map.
*   **API Keys**: Add keys for GreyNoise, AbuseIPDB, VirusTotal, and AlienVault OTX for automated enrichment.
*   **Data Management**: Use granular "Clear" buttons to independently wipe PCAP data, OSINT cache, or the Cases database.

---

## 🧠 3. Analysis Pipeline

Once you click **Extract & Analyze**, the platform triggers a multi-stage pipeline.

![Progress Tracking](/Users/ninedter/.gemini/antigravity/brain/d6d2775b-1512-446c-a2fd-a40c06fe0892/progress_tab_1767606125822.png)

1.  **Parsing**: Pyshark and Zeek extract metadata and core flows.
2.  **DNS & TLS**: Analyzes domain resolutions and TLS handshakes (SNI, Certificates).
3.  **Beaconing**: Identifies periodic heartbeats suggestive of C2 traffic.
4.  **Carving**: Extracts interesting files (HTTP/FTP) from the traffic for further inspection.
5.  **OSINT**: Queries external threat intelligence feeds for identified IPs and domains.

---

## 📊 4. Interactive Dashboard

The **Dashboard** is your primary hunting ground, providing a high-level visual summary.

![Interactive Dashboard](/Users/ninedter/.gemini/antigravity/brain/d6d2775b-1512-446c-a2fd-a40c06fe0892/dashboard_tab_1767606138933.png)

### Key Features:
*   **World Map**: Visualizes traffic connections globally. Lines represent traffic volume (thicker = more data).
*   **Protocol Distribution**: A donut chart showing the breakdown of network protocols.
*   **Timeline Analysis**: A dual-axis chart showing flow duration (scatter) and total volume (area) over time.
*   **Top 10 Insights**: Quick identification of anomalous IPs, Ports, and Domains.

> [!TIP]
> **Cross-Filtering**: Click on any map marker, pie slice, or bar chart entry to filter the entire dashboard by that indicator. Use "Clear All Filters" to reset.

---

## 🔍 5. Threat Intelligence (OSINT)

Deep-dive into specific indicators in the **OSINT** tab.

![OSINT Analysis](/Users/ninedter/.gemini/antigravity/brain/d6d2775b-1512-446c-a2fd-a40c06fe0892/osint_tab_ip_addresses_1767606168459.png)

*   **IP Addresses**: View enrichment from GreyNoise, AbuseIPDB, and VirusTotal.
*   **Domains**: Check categories and safety scores for resolved hostnames.
*   **Devices**: Identify hardware manufacturers based on MAC addresses.

---

## 📄 6. Raw Data & Forensics

For granular packet-level details, use the **Raw Data** tab.

![Raw Data Details](/Users/ninedter/.gemini/antigravity/brain/d6d2775b-1512-446c-a2fd-a40c06fe0892/raw_data_tab_1767606182866.png)

Explore sub-tabs for:
*   **Flows**: Detailed source/destination pairs and packet counts.
*   **DNS Analysis**: All queries and responses found in the PCAP.
*   **JA3 Fingerprints**: Identify potentially malicious TLS clients even without decryption.
*   **Carved Files**: Download files extracted automatically by the pipeline.

---

## 📂 7. Case Management

Document your findings and generate professional reports in the **Cases** and **LLM Analysis** tabs.

````carousel
![AI Reporting](/Users/ninedter/.gemini/antigravity/brain/d6d2775b-1512-446c-a2fd-a40c06fe0892/llm_analysis_tab_1767606154308.png)
<!-- slide -->
![Case Tracking](/Users/ninedter/.gemini/antigravity/brain/d6d2775b-1512-446c-a2fd-a40c06fe0892/cases_tab_list_1767606197130.png)
````

*   **AI Summary**: Generate a human-readable analysis of the entire PCAP using your configured LLM.
*   **Notes & IOCs**: Add findings to a case database for long-term tracking and compliance.
*   **CSV/JSON Exports**: Export any table or chart data for external reporting.

---
*Generated by PCAP Hunter Documentation Engine*
