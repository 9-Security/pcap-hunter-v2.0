# PCAP Hunter

[![CI](https://github.com/ninedter/pcap-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/ninedter/pcap-hunter/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](../../LICENSE)

> **[English README](../../README.md)**

**PCAP Hunter** 是一個 AI 增強的威脅獵捕工作台，旨在填補手動封包分析與自動化資安監控之間的鴻溝。它讓 SOC 分析師與威脅獵捕人員能夠從原始 PCAP 檔案中快速攝取、分析並提取可執行的情資。

透過結合業界標準的網路分析工具（**Zeek**、**Tshark**、**PyShark**）搭配**大型語言模型（LLMs）**及 **OSINT** APIs，PCAP Hunter 自動化了封包分析中繁瑣的部分——解析、關聯和豐富化——讓分析師能專注於偵測與回應。

---

## 目錄

- [主要功能](#主要功能)
- [系統架構](#系統架構)
- [安裝](#安裝)
- [快速開始](#快速開始)
- [使用指南](#使用指南)
- [設定](#設定)
- [Docker](#docker)
- [開發](#開發)
- [說明文件](#說明文件)
- [授權條款](#授權條款)

---

## 主要功能

### AI 驅動的威脅分析
- **自動化報告** — 產生專業、SOC 就緒的威脅報告，總結關鍵發現、可疑指標與風險評估。
- **本地與雲端 LLM 支援**
  - **本地隱私**：完全相容 [LM Studio](https://lmstudio.ai/)（Llama 3、Mistral 等），適合隔離網段或隱私敏感的環境。
  - **雲端運算**：支援任何 OpenAI 相容的 API 端點，可使用更大型的模型。
- **多語言報告** — 支援 9 種語言與地區術語：英文、繁體中文（台灣）、簡體中文、日文、韓文、義大利文、西班牙文、法文、德文。
- **MITRE ATT&CK 對應** — 自動將偵測到的行為與 IOC 對應至 ATT&CK 技術與攻擊鏈階段。
- **攻擊敘事合成** — 將原始事件轉譯為連貫、可執行的資安事件故事。

### IOC 優先級評分
- **加權評分引擎** — 動態將指標分級為嚴重、高、中、低。
- **多因子分析** — 分數來源：
  - OSINT 信譽（VirusTotal、AbuseIPDB、GreyNoise）— 45%
  - 行為訊號（C2 信標、連線次數、傳輸量、流量不對稱）— 35%
  - 情境訊號（JA3 惡意軟體比對、DGA、自簽憑證、NXDOMAIN 比率、Port 異常）— 20%

### 跨指標關聯引擎
- 彙整所有分析模組的訊號（OSINT、信標偵測、DNS、TLS、YARA、流量分析）。
- 為每個指標產生複合威脅分數，附帶判定分類（嚴重 / 高 / 中 / 低）。

### 流量分析與資料外洩偵測
- **資料外洩偵測** — 辨識每對來源/目的端的可疑上傳與下載位元組比率（預設門檻：10:1，最低 1 MB）。
- **Port 異常偵測** — 標記非標準 Port 使用、C2 常見 Port（4444、5555、6666 等）及高位 Port 配對。

### 深度封包檢測與流量分析
- **多引擎管道**：PyShark 進行細顆粒檢測，Tshark 進行高速統計。
- **協定解析**：自動提取 HTTP、DNS、TLS/SSL、SMB 協定的元資料。

### Zeek 整合
- 上傳 PCAP 後自動執行 Zeek — 無需手動下指令。
- 解析並關聯核心 Zeek Log：`conn.log`、`dns.log`、`http.log`、`ssl.log`。

### 進階 DNS 與 TLS 鑑識
- **DGA 偵測** — 基於夏農熵（Shannon Entropy）的網域生成演算法識別。
- **DNS 通道偵測** — 偵測高流量 / 異常的 DNS 酬載。
- **Fast Flux 偵測** — 辨識解析至快速變化 IP 位址的網域。
- **JA3/JA3S 指紋識別** — 比對 TLS 指紋與 90 筆以上已知惡意軟體特徵（Cobalt Strike、Trickbot、Emotet、QakBot 等）。
- **憑證分析** — 驗證憑證鏈；偵測自簽及過期憑證。

### C2 信標（Beaconing）偵測
- 統計演算法依據以下項目對流量評分：
  - **週期性** — 通訊間隔的規律性。
  - **抖動（Jitter）** — C2 代理程式的隨機化嘗試。
  - **傳輸量** — 酬載大小的一致性。

### 酬載提取（Carving）與 YARA 掃描
- 透過 `tshark` 提取 **HTTP 酬載**，自動計算 SHA256 雜湊。
- **YARA 掃描器** — 使用自訂 / 社群 YARA 規則掃描提取的檔案。
- **安全儲存** — 隔離目錄，具備路徑穿越與符號連結防護。

### 互動式儀表板與世界地圖
- **世界地圖** — 威脅等級著色、基於傳輸量的連線弧線粗細、可設定的自家位置。
- **交叉篩選** — 地圖、協定圓餅圖與流量時間軸的統一鑽取。
- **持久檢視選項** — 「排除私有 IP」切換在互動探索期間保持有效。
- **TopN 圖表** — 前幾名 IP、Port、協定、網域的彙整長條圖與指標。
- **封包長度分佈** — 酬載大小直方圖。

### OSINT 情資豐富化
整合領先的威脅情資提供商：
- **VirusTotal** — 檔案雜湊與 IP / 網域信譽。
- **AbuseIPDB** — 群眾回報的 IP 濫用報告。
- **GreyNoise** — 網際網路背景雜訊與掃描器識別。
- **OTX (AlienVault)** — 開放威脅交換脈衝與指標。
- **Shodan** — 面向網際網路的裝置詳情與開放 Port。
- **智慧快取** — SQLite 支援的快取系統，可設定 TTL 以節省 API 配額。

### 案件管理系統
- 建立、追蹤與結案調查案件。
- 儲存 IOC（IP、網域、雜湊、JA3、URL），附帶嚴重程度與情境說明。
- 調查筆記、標籤分類與搜尋功能。

### 專業 PDF 匯出
- 多頁 PDF 報告，包含執行摘要、關鍵發現、技術分析與建議事項。
- 透過 WeasyPrint 嵌入圖表 / 視覺化。
- 可設定 TLP 標記分類。

### 匯出格式
- **CSV / JSON** — 匯出任何資料表，內建 CSV 注入防護。
- **STIX 2.0/2.1** — 以標準 STIX 格式匯出指標。
- **ATT&CK Navigator** — 匯出技術對應至 MITRE ATT&CK Navigator。

---

## 系統架構

```
app/
├── analysis/        # 關聯引擎、流量分析、IOC 評分、敘事產生
├── database/        # 案件管理（SQLite）
├── llm/             # LLM 用戶端與多語言報告產生
├── pipeline/        # 10 階段分析管道
│   ├── beacon.py    # C2 信標偵測
│   ├── carve.py     # HTTP 酬載提取
│   ├── dns_analysis.py  # DGA、通道偵測、Fast Flux
│   ├── geoip.py     # GeoIP 解析
│   ├── ja3.py       # JA3/JA3S 指紋識別
│   ├── osint.py     # OSINT 提供商查詢
│   ├── osint_cache.py   # SQLite 快取層
│   ├── tls_certs.py # 憑證驗證
│   └── yara_scan.py # YARA 規則掃描
├── reports/         # PDF 報告產生
├── security/        # OPSEC 強化與資料清理
├── threat_intel/    # MITRE ATT&CK 對應
├── ui/              # Streamlit 介面（8 個分頁）
├── utils/           # 匯出、GeoIP、設定、執行檔探索、網路工具
├── config.py        # 應用程式預設值
└── main.py          # Streamlit 進入點
```

### 分析管道（10 個階段）

1. **封包計數** — 透過 tshark 快速初步計數
2. **封包解析** — 深度檢測最多 200,000 個封包（可設定）
3. **Zeek 處理** — 自動執行 Zeek 並解析 Log
4. **DNS 分析** — DGA、通道偵測、Fast Flux、NXDOMAIN、查詢頻率
5. **TLS 憑證分析** — 憑證鏈驗證、自簽 / 過期偵測
6. **信標偵測排名** — 時序模式分析以偵測 C2
7. **HTTP 酬載提取** — 酬載提取並計算 SHA256 雜湊
8. **YARA 掃描** — 基於規則的檔案掃描
9. **OSINT 豐富化** — 多提供商信譽查詢
10. **LLM 報告產生** — AI 驅動的威脅綜整

---

## 安裝

### 先決條件

| 工具 | macOS 安裝 | Linux 安裝 |
|------|-----------|-----------|
| **Python 3.10+** | `brew install python@3.12` | `sudo apt install python3` |
| **Zeek** | `brew install zeek` | [Zeek 套件](https://software.zeek.org/) |
| **Tshark** | `brew install wireshark` | `sudo apt install tshark` |
| **Pango**（PDF） | `brew install pango` | `sudo apt install libpango1.0-dev` |
| **LM Studio**（選用） | [lmstudio.ai](https://lmstudio.ai/) | [lmstudio.ai](https://lmstudio.ai/) |

### 安裝步驟

```bash
git clone https://github.com/ninedter/pcap-hunter.git
cd pcap-hunter
make install
```

---

## 快速開始

```bash
make run
```

在瀏覽器中開啟 `http://localhost:8501`。

---

## 使用指南

1. **上傳** — 在 Upload 分頁中拖放 `.pcap` 檔案。
2. **設定** — 在 Config 分頁中設定 LLM 端點、自家位置（洲 > 國家 > 城市）及 OSINT API 金鑰。
3. **分析** — 點擊 **Extract & Analyze** 啟動分析管道。
4. **監控** — 在 Progress 分頁觀察各階段執行：封包計數 > 解析 > Zeek > DNS/TLS > 信標偵測 > 酬載提取 > YARA > OSINT > LLM 報告。
5. **審閱** — 在 Dashboard、LLM Analysis、OSINT、Raw Data、Cases 分頁中瀏覽結果。
6. **匯出** — 下載 CSV/JSON 資料、PDF 報告、STIX 套件或 ATT&CK Navigator 圖層。

### 重新產生報告

更換了 LLM 模型或語言？點擊 **Re-run Report** 僅重新產生 AI 報告，無需重新處理整個 PCAP。

### 資料管理

使用 Config 分頁中細緻的 **Clear** 按鈕，分別清除 PCAP 資料、OSINT 快取或案件資料庫。

---

## 設定

預設值在 `app/config.py` 中管理，並持久化至 `.pcap_hunter_config.json`。

| 設定項 | 預設值 | 說明 |
|--------|--------|------|
| `LM_BASE_URL` | `http://localhost:1234/v1` | LLM API 端點 |
| `LM_MODEL` | `local` | 模型識別碼 |
| `LM_LANGUAGE` | `US English` | 報告語言 |
| `DEFAULT_PYSHARK_LIMIT` | `200,000` | 深度檢測的最大封包數 |
| `OSINT_TOP_IPS_DEFAULT` | `50` | 豐富化的前幾名 IP 數量（0 = 全部） |
| `OSINT_CACHE_ENABLED` | `True` | OSINT 結果的 SQLite 快取 |
| `DATA_DIR` | `./data` | 分析產物儲存位置 |

### OSINT API 金鑰

透過 Config 分頁或環境變數設定：

```bash
export OTX_KEY="your-key"
export VT_KEY="your-key"
export ABUSEIPDB_KEY="your-key"
export GREYNOISE_KEY="your-key"
export SHODAN_KEY="your-key"
```

---

## Docker

```bash
docker build -t pcap-hunter .
docker run -p 8501:8501 pcap-hunter
```

Docker 映像檔已預裝 Zeek 與 Tshark。掛載 volume 以持久化資料：

```bash
docker run -p 8501:8501 -v $(pwd)/data:/app/data pcap-hunter
```

---

## 開發

```bash
make test       # 執行測試並產生覆蓋率報告
make lint       # 使用 Ruff 進行 lint 檢查
make format     # 使用 Ruff 格式化程式碼
make clean      # 清除快取
```

### macOS 擷取權限

```bash
make fix-permissions
```

### CI/CD

GitHub Actions 在每次推送 / PR 至 `main` 時執行：
- Python 3.11 測試套件與覆蓋率
- Ruff lint 與格式檢查

---

## 說明文件

- [User Manual (English)](../en/USER_MANUAL.md)
- [使用手冊（繁體中文）](USER_MANUAL.md)
- [Changelog](../../CHANGELOG.md)

---

## 授權條款

MIT License. 詳情請見 [LICENSE](../../LICENSE)。

Copyright (c) 2025 ninedter
