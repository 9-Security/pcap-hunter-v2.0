"""
Backward-compatible re-exports from split utility modules.

This module maintains API compatibility while the actual implementations
have been moved to focused modules:
- network_utils: IP validation, DNS resolution, WHOIS lookup
- flow_filters: Flow filtering by IP, protocol, time
- file_utils: File operations, hashing
- string_utils: String manipulation, slugify
- binary_discovery: Binary tool location
"""

from __future__ import annotations

# Binary discovery
from app.utils.binary_discovery import find_bin

# File utilities
from app.utils.file_utils import ensure_dir, sha256_bytes

# Flow filters
from app.utils.flow_filters import filter_flows_by_ips, filter_flows_by_protocol, filter_flows_by_time

# Network utilities
from app.utils.network_utils import get_whois_info, is_public_ipv4, resolve_ip

# String utilities
from app.utils.string_utils import make_slug, uniq_sorted

__all__ = [
    # Network
    "resolve_ip",
    "get_whois_info",
    "is_public_ipv4",
    # Flow filters
    "filter_flows_by_ips",
    "filter_flows_by_protocol",
    "filter_flows_by_time",
    # File
    "sha256_bytes",
    "ensure_dir",
    # String
    "uniq_sorted",
    "make_slug",
    # Binary
    "find_bin",
]
