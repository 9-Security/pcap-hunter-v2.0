# Phase 4 Implementation Plan

## Overview

Phase 4 focuses on **AI-enhanced analysis** and **export capabilities**, building upon the existing LLM integration and export utilities from Phase 1-3.

### Goals
1. **AI Enhancement** - Leverage LLM for deeper analysis
2. **Export Enhancement** - Standard formats for threat intel sharing

---

## 1. AI Enhancement

### 1.1 MITRE ATT&CK Auto-Mapping

**Purpose**: Automatically map detected behaviors to MITRE ATT&CK techniques.

#### Detection Rules

```python
# app/threat_intel/attack_mapping.py

DETECTION_TO_ATTACK = {
    # C2 Communication
    "beacon_score": {
        "threshold": 0.7,
        "techniques": [
            {"id": "T1071.001", "name": "Web Protocols", "tactic": "command-and-control"},
            {"id": "T1571", "name": "Non-Standard Port", "tactic": "command-and-control"},
        ]
    },
    # DNS-based
    "dns_tunneling": {
        "threshold": 0.6,
        "techniques": [
            {"id": "T1071.004", "name": "DNS", "tactic": "command-and-control"},
            {"id": "T1048.003", "name": "Exfiltration Over DNS", "tactic": "exfiltration"},
        ]
    },
    "dga_detected": {
        "threshold": 0.7,
        "techniques": [
            {"id": "T1568.002", "name": "Domain Generation Algorithms", "tactic": "command-and-control"},
        ]
    },
    # TLS/Encryption
    "self_signed_cert": {
        "techniques": [
            {"id": "T1587.003", "name": "Digital Certificates", "tactic": "resource-development"},
            {"id": "T1573.002", "name": "Asymmetric Cryptography", "tactic": "command-and-control"},
        ]
    },
    "ja3_malware": {
        "techniques": [
            {"id": "T1071.001", "name": "Web Protocols", "tactic": "command-and-control"},
        ]
    },
    # YARA matches
    "yara_critical": {
        "techniques": [
            {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
            {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "defense-evasion"},
        ]
    },
}
```

#### Core Functions

```python
@dataclass
class TechniqueMatch:
    technique_id: str       # T1071.001
    technique_name: str     # Web Protocols
    tactic: str             # command-and-control
    confidence: float       # 0.0 - 1.0
    evidence: list[str]     # What triggered this detection

@dataclass
class AttackMapping:
    techniques: list[TechniqueMatch]
    tactics_summary: dict[str, int]  # tactic -> count
    kill_chain_phase: str            # reconnaissance, initial-access, etc.
    overall_severity: str            # low, medium, high, critical

class ATTACKMapper:
    def __init__(self):
        """Initialize with detection rules."""

    def map_analysis(self,
                     features: dict,
                     dns_analysis: dict,
                     tls_analysis: dict,
                     yara_results: dict,
                     beacon_results: list) -> AttackMapping:
        """Map analysis results to ATT&CK techniques."""

    def enhance_with_llm(self,
                         mapping: AttackMapping,
                         report_md: str) -> AttackMapping:
        """Use LLM to refine mapping and add context."""
```

#### LLM Enhancement Prompt

```python
ATTACK_MAPPING_PROMPT = """
Based on the analysis findings below, identify additional MITRE ATT&CK techniques
that may apply. For each technique, provide:
1. Technique ID (e.g., T1071.001)
2. Confidence level (0.0-1.0)
3. Evidence from the analysis

Current findings:
{analysis_summary}

Already identified techniques:
{current_techniques}

Respond in JSON format:
{
  "additional_techniques": [
    {"id": "T1xxx", "confidence": 0.8, "evidence": "..."}
  ],
  "attack_narrative": "Brief description of the likely attack chain..."
}
"""
```

---

### 1.2 Attack Timeline Narrative

**Purpose**: Generate a human-readable story of the attack progression.

#### Core Functions

```python
class AttackNarrator:
    def __init__(self, llm_client):
        """Initialize with LLM client."""

    def generate_narrative(self,
                           features: dict,
                           dns_analysis: dict,
                           tls_analysis: dict,
                           attack_mapping: AttackMapping,
                           timeline_events: list) -> str:
        """Generate attack story using LLM."""

    def create_timeline(self, features: dict) -> list[TimelineEvent]:
        """Extract chronological events from analysis."""

@dataclass
class TimelineEvent:
    timestamp: datetime
    event_type: str         # connection, dns_query, file_download, alert
    description: str
    severity: str
    source_ip: str
    dest_ip: str
    iocs: list[str]
```

#### LLM Narrative Prompt

```python
NARRATIVE_PROMPT = """
Based on the timeline of events and detected techniques, write a concise
attack narrative that explains:

1. How the attack likely began (initial access)
2. What the attacker did (execution, persistence)
3. How they communicated with C2 (command and control)
4. What data may have been exfiltrated (if applicable)
5. Current status and recommended actions

Timeline:
{timeline_events}

Detected ATT&CK Techniques:
{techniques}

Key IOCs:
{iocs}

Write in {language}, using professional security terminology.
Keep the narrative to 3-5 paragraphs.
"""
```

---

### 1.3 IOC Priority Scoring

**Purpose**: Score IOCs by importance to help analysts focus on what matters.

#### Scoring Factors

```python
IOC_SCORING_WEIGHTS = {
    # OSINT signals
    "vt_detections": 0.25,          # VirusTotal detection ratio
    "greynoise_malicious": 0.20,    # GreyNoise classification
    "abuseipdb_score": 0.15,        # AbuseIPDB confidence

    # Behavioral signals
    "beacon_score": 0.15,           # C2 beaconing likelihood
    "connection_count": 0.10,       # Frequency of communication
    "data_volume": 0.05,            # Amount of data transferred

    # Context signals
    "ja3_malware_match": 0.10,      # Known malicious fingerprint
    "dga_match": 0.05,              # DGA domain
    "self_signed_cert": 0.05,       # Suspicious certificate
}

class IOCScorer:
    def __init__(self):
        """Initialize scorer."""

    def score_ioc(self,
                  ioc_value: str,
                  ioc_type: str,
                  osint_data: dict,
                  behavioral_data: dict) -> float:
        """Calculate priority score 0.0-1.0."""

    def rank_iocs(self,
                  iocs: list[dict],
                  osint: dict,
                  features: dict) -> list[dict]:
        """Return IOCs sorted by priority with scores."""

    def explain_score(self, ioc: dict) -> str:
        """Generate human-readable explanation of score."""
```

#### Output Example

```python
{
    "ioc": "185.220.101.45",
    "type": "ip",
    "priority_score": 0.92,
    "priority_label": "critical",
    "factors": {
        "vt_detections": {"value": 45, "contribution": 0.25},
        "greynoise": {"value": "malicious", "contribution": 0.20},
        "beacon_score": {"value": 0.85, "contribution": 0.15},
        "ja3_match": {"value": "Cobalt Strike", "contribution": 0.10}
    },
    "recommendation": "Immediate block recommended"
}
```

---

### 1.4 Interactive Q&A

**Purpose**: Allow analysts to ask questions about the analysis results.

#### Architecture

```python
class AnalysisQA:
    def __init__(self, llm_client, analysis_context: dict):
        """Initialize with analysis data as context."""
        self.context = analysis_context
        self.conversation_history = []

    def ask(self, question: str) -> str:
        """Ask a question about the analysis."""

    def get_suggested_questions(self) -> list[str]:
        """Return relevant questions based on findings."""

# Suggested questions based on findings
SUGGESTED_QUESTIONS = {
    "beacon_detected": [
        "What is the beaconing interval pattern?",
        "Which internal hosts are beaconing?",
        "What C2 infrastructure is being used?",
    ],
    "yara_match": [
        "What malware was detected?",
        "Which files triggered the YARA rules?",
        "What are the capabilities of this malware?",
    ],
    "dga_detected": [
        "How many DGA domains were found?",
        "What DGA algorithm might be in use?",
        "Are any DGA domains resolving?",
    ],
}
```

#### UI Integration

```python
def render_qa_section():
    """Render Q&A interface in Streamlit."""
    st.markdown("### Ask About This Analysis")

    # Show suggested questions
    suggestions = qa.get_suggested_questions()
    if suggestions:
        st.caption("Suggested questions:")
        for q in suggestions:
            if st.button(q, key=f"q_{hash(q)}"):
                st.session_state["qa_question"] = q

    # Question input
    question = st.text_input(
        "Your question:",
        value=st.session_state.get("qa_question", ""),
        placeholder="e.g., What is the most likely attack vector?"
    )

    if st.button("Ask"):
        with st.spinner("Analyzing..."):
            answer = qa.ask(question)
            st.markdown(answer)
```

---

## 2. Export Enhancement

### 2.1 IOC List Export

**Purpose**: Export IOCs in multiple formats for easy sharing.

#### Supported Formats

| Format | Use Case |
|--------|----------|
| CSV | Spreadsheets, quick review |
| JSON | Programmatic processing |
| TXT | Firewall block lists |
| STIX 2.1 | Threat intel platforms |

#### Core Functions

```python
# app/utils/ioc_export.py

class IOCExporter:
    def __init__(self, features: dict, osint: dict, scores: dict = None):
        """Initialize with analysis data."""

    def extract_iocs(self) -> list[dict]:
        """Extract all IOCs from analysis."""

    def export_csv(self, ioc_types: list[str] = None) -> bytes:
        """Export to CSV format."""

    def export_json(self, ioc_types: list[str] = None) -> bytes:
        """Export to JSON format."""

    def export_txt(self, ioc_types: list[str] = None) -> bytes:
        """Export plain text list (one IOC per line)."""

    def export_stix(self, ioc_types: list[str] = None) -> bytes:
        """Export as STIX 2.1 Bundle."""

# IOC structure
@dataclass
class IOCRecord:
    type: str               # ip, domain, hash, ja3, url
    value: str
    context: str            # Where it was found
    first_seen: datetime
    last_seen: datetime
    priority_score: float
    osint_summary: dict
    tags: list[str]
```

#### UI Integration

```python
def render_ioc_export():
    """Render IOC export controls."""
    st.markdown("### Export IOCs")

    col1, col2 = st.columns(2)

    with col1:
        ioc_types = st.multiselect(
            "IOC Types",
            ["ip", "domain", "hash", "ja3", "url"],
            default=["ip", "domain"]
        )

    with col2:
        format_choice = st.selectbox(
            "Format",
            ["CSV", "JSON", "Plain Text", "STIX 2.1"]
        )

    min_score = st.slider(
        "Minimum Priority Score",
        0.0, 1.0, 0.0,
        help="Filter to high-priority IOCs only"
    )

    if st.button("Export"):
        exporter = IOCExporter(features, osint, scores)

        if format_choice == "CSV":
            data = exporter.export_csv(ioc_types)
            filename = "iocs.csv"
            mime = "text/csv"
        elif format_choice == "JSON":
            data = exporter.export_json(ioc_types)
            filename = "iocs.json"
            mime = "application/json"
        elif format_choice == "Plain Text":
            data = exporter.export_txt(ioc_types)
            filename = "iocs.txt"
            mime = "text/plain"
        else:  # STIX
            data = exporter.export_stix(ioc_types)
            filename = "iocs_stix.json"
            mime = "application/json"

        st.download_button(
            f"Download {filename}",
            data=data,
            file_name=filename,
            mime=mime
        )
```

---

### 2.2 ATT&CK Navigator Layer

**Purpose**: Export detected techniques as ATT&CK Navigator layer for visualization.

#### Navigator Layer Format

```python
def export_navigator_layer(mapping: AttackMapping,
                           name: str = "PCAP Analysis") -> dict:
    """
    Generate ATT&CK Navigator layer JSON.
    Can be imported directly into https://mitre-attack.github.io/attack-navigator/
    """
    techniques = []

    for tech in mapping.techniques:
        techniques.append({
            "techniqueID": tech.technique_id,
            "tactic": tech.tactic,
            "score": int(tech.confidence * 100),
            "color": _severity_to_color(tech.confidence),
            "comment": "; ".join(tech.evidence),
            "enabled": True,
        })

    return {
        "name": name,
        "versions": {
            "attack": "14",
            "navigator": "4.9.1",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": f"Generated by PCAP Hunter on {datetime.now().isoformat()}",
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#ffeb3b", "#ff9800", "#f44336"],
            "minValue": 0,
            "maxValue": 100
        },
        "legendItems": [
            {"label": "Low Confidence", "color": "#ffeb3b"},
            {"label": "Medium Confidence", "color": "#ff9800"},
            {"label": "High Confidence", "color": "#f44336"},
        ]
    }
```

#### UI Integration

```python
def render_attack_export():
    """Render ATT&CK export controls."""
    st.markdown("### Export ATT&CK Mapping")

    layer_name = st.text_input(
        "Layer Name",
        value=f"PCAP Analysis - {datetime.now().strftime('%Y-%m-%d')}"
    )

    if st.button("Export Navigator Layer"):
        layer = export_navigator_layer(attack_mapping, layer_name)

        st.download_button(
            "Download Navigator Layer",
            data=json.dumps(layer, indent=2),
            file_name="attack_layer.json",
            mime="application/json"
        )

        st.info("Import this file at: https://mitre-attack.github.io/attack-navigator/")
```

---

### 2.3 STIX 2.1 Export

**Purpose**: Export findings in STIX 2.1 format for threat intel platforms.

#### STIX Objects Generated

| STIX Type | Source |
|-----------|--------|
| Indicator | IOCs (IP, Domain, Hash) |
| Malware | YARA matches |
| Attack Pattern | ATT&CK techniques |
| Relationship | Links between objects |
| Report | Analysis summary |

#### Core Functions

```python
# app/utils/stix_export.py

from stix2 import (
    Bundle, Indicator, Malware, AttackPattern,
    Relationship, Report, Identity
)

class STIXExporter:
    def __init__(self,
                 features: dict,
                 osint: dict,
                 attack_mapping: AttackMapping,
                 yara_results: dict):
        """Initialize with analysis data."""
        self.identity = self._create_identity()

    def _create_identity(self) -> Identity:
        """Create identity for the analysis tool."""
        return Identity(
            name="PCAP Hunter",
            identity_class="tool"
        )

    def create_indicators(self) -> list[Indicator]:
        """Create STIX Indicators from IOCs."""

    def create_malware(self) -> list[Malware]:
        """Create STIX Malware from YARA matches."""

    def create_attack_patterns(self) -> list[AttackPattern]:
        """Create STIX Attack Patterns from ATT&CK mapping."""

    def create_relationships(self) -> list[Relationship]:
        """Create relationships between objects."""

    def create_report(self, title: str) -> Report:
        """Create summary report object."""

    def export_bundle(self) -> Bundle:
        """Export complete STIX Bundle."""
```

#### STIX Indicator Example

```python
def _ioc_to_indicator(self, ioc: dict) -> Indicator:
    """Convert IOC to STIX Indicator."""

    # Build pattern based on IOC type
    if ioc["type"] == "ip":
        pattern = f"[ipv4-addr:value = '{ioc['value']}']"
    elif ioc["type"] == "domain":
        pattern = f"[domain-name:value = '{ioc['value']}']"
    elif ioc["type"] == "hash":
        pattern = f"[file:hashes.'SHA-256' = '{ioc['value']}']"

    return Indicator(
        name=f"Malicious {ioc['type']}: {ioc['value']}",
        pattern=pattern,
        pattern_type="stix",
        valid_from=datetime.now(),
        labels=ioc.get("tags", []),
        confidence=int(ioc.get("priority_score", 0.5) * 100),
        created_by_ref=self.identity.id,
        external_references=[
            {"source_name": "PCAP Hunter", "description": ioc.get("context", "")}
        ]
    )
```

---

## 3. Implementation Order

### Step 1: MITRE ATT&CK Mapping (Day 1-2)
1. Create `app/threat_intel/attack_mapping.py`
2. Define detection-to-technique rules
3. Integrate with LLM for enhancement
4. Add ATT&CK section to PDF report
5. Write tests

### Step 2: IOC Export (Day 2-3)
1. Create `app/utils/ioc_export.py`
2. Implement CSV/JSON/TXT export
3. Add export UI to Dashboard
4. Write tests

### Step 3: IOC Priority Scoring (Day 3-4)
1. Create `app/analysis/ioc_scorer.py`
2. Implement scoring algorithm
3. Integrate with export
4. Add score display to UI
5. Write tests

### Step 4: ATT&CK Navigator Export (Day 4)
1. Implement Navigator layer format
2. Add export button to UI
3. Write tests

### Step 5: Attack Narrative (Day 5)
1. Enhance LLM prompts
2. Add narrative section to report
3. Write tests

### Step 6: Interactive Q&A (Day 6)
1. Create `app/llm/qa.py`
2. Implement conversation context
3. Add Q&A UI section
4. Write tests

### Step 7: STIX Export (Day 7-8)
1. Create `app/utils/stix_export.py`
2. Implement STIX object creation
3. Add to export options
4. Write tests

---

## 4. New Files

```
app/
├── threat_intel/
│   ├── __init__.py
│   └── attack_mapping.py    # ATT&CK mapping engine
├── analysis/
│   ├── __init__.py
│   ├── ioc_scorer.py        # IOC priority scoring
│   └── narrator.py          # Attack narrative generation
├── llm/
│   └── qa.py                # Interactive Q&A
└── utils/
    ├── ioc_export.py        # IOC export (CSV/JSON/TXT)
    ├── stix_export.py       # STIX 2.1 export
    └── navigator_export.py  # ATT&CK Navigator layer

tests/
├── test_attack_mapping.py
├── test_ioc_scorer.py
├── test_ioc_export.py
├── test_stix_export.py
└── test_qa.py
```

---

## 5. Dependencies

```toml
# pyproject.toml additions
[project.optional-dependencies]
phase4 = [
    "stix2>=3.0.0",          # STIX 2.1 export
]
```

---

## 6. UI Changes

### Dashboard Tab Additions

```python
# New sections in layout.py

# After OSINT section:
with st.expander("🎯 ATT&CK Mapping", expanded=True):
    render_attack_mapping(attack_mapping)
    render_attack_export()

# After Report section:
with st.expander("📤 Export IOCs", expanded=False):
    render_ioc_export()

# New tab or section:
with st.expander("💬 Ask About Analysis", expanded=False):
    render_qa_section()
```

### PDF Report Additions

```
New sections:
6. MITRE ATT&CK Mapping
   - Detected techniques table
   - Tactics coverage
   - Attack narrative

7. IOC Priority Summary
   - Top 10 critical IOCs
   - Score explanations
```

---

## 7. Success Metrics

| Feature | Success Criteria |
|---------|------------------|
| ATT&CK Mapping | Correctly identifies 80%+ of applicable techniques |
| IOC Export | All formats export without errors |
| Priority Scoring | High-priority IOCs have OSINT correlation |
| Navigator Export | Layer imports correctly in Navigator |
| Attack Narrative | Coherent story matching timeline |
| Interactive Q&A | Accurate answers to common questions |
| STIX Export | Valid STIX 2.1 Bundle |
