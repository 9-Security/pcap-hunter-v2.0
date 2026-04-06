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

# Allowed directories for user-supplied PCAP paths
ALLOWED_PCAP_DIRS = [DATA_DIR, pathlib.Path("pcaps").resolve(), pathlib.Path("/data").resolve()]

# Analysis defaults
DEFAULT_PYSHARK_LIMIT = 200000
PRECNT_DEFAULT = True

# OSINT Top-N default (0 = all public IPs)
OSINT_TOP_IPS_DEFAULT = 50

# Parallel pipeline
PARALLEL_PARSE_ENABLED = True  # Run PyShark + Zeek in parallel
MAX_PARALLEL_WORKERS = 3  # Max worker threads for pipeline stages

# Reverse DNS
RDNS_CACHE_TTL_HOURS = 168  # 7 days
RDNS_MAX_WORKERS = 10  # Concurrent rDNS lookups

# Batch processing
BATCH_MAX_FILES = 50
BATCH_MAX_FILE_SIZE_BYTES = 1024 * 1024 * 1024  # 1 GB per file
BATCH_MAX_TOTAL_SIZE_BYTES = 5 * 1024 * 1024 * 1024  # 5 GB total

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
