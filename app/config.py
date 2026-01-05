from __future__ import annotations

import pathlib

APP_NAME = "PCAP Threat Hunting Workbench"

# Directories (local or container)
DATA_DIR = pathlib.Path("data").resolve()
CARVE_DIR = DATA_DIR / "carved"
ZEEK_DIR = DATA_DIR / "zeek"

# LM Studio defaults
LM_BASE_URL = "http://localhost:1234/v1"
LM_API_KEY = "lm-studio"  # LM Studio doesn’t enforce this; just needs a non-empty string
LM_MODEL = "local"
LM_LANGUAGE = "US English"

# OSINT keys (empty defaults, override with env or config UI)
OTX_KEY = ""
VT_KEY = ""
ABUSEIPDB_KEY = ""
GREYNOISE_KEY = ""
SHODAN_KEY = ""

# Analysis defaults
DEFAULT_PYSHARK_LIMIT = 200000
PRECNT_DEFAULT = True

# OSINT Top-N default (0 = all public IPs)
OSINT_TOP_IPS_DEFAULT = 50

# TShark fields to extract
TSHARK_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "frame.protocols",
    "eth.src",
    "eth.dst",
]
