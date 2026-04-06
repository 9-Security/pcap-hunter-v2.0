from __future__ import annotations

import concurrent.futures
import logging
import threading
import time
from typing import Any
from urllib.parse import quote

from app.pipeline.geoip import GeoIP
from app.pipeline.osint_cache import get_osint_cache
from app.pipeline.state import PhaseHandle
from app.security.opsec import hardened_session
from app.utils.common import is_public_ipv4, resolve_ip

logger = logging.getLogger(__name__)

# Thread-local storage for per-thread HTTP sessions (connection pooling is
# per-session and requests.Session is not thread-safe).
_thread_local = threading.local()


def _get_session():
    """Get or create a thread-local hardened HTTP session."""
    if not hasattr(_thread_local, "session"):
        _thread_local.session = hardened_session(timeout=12)
    return _thread_local.session

# Global cache instance (lazy loaded)
_cache = None


def _get_cache():
    """Get or create cache instance with enabled state from config."""
    global _cache
    if _cache is None:
        _cache = get_osint_cache()

    # Update enabled state from session config
    try:
        import streamlit as st

        enabled = st.session_state.get("cfg_osint_cache_enabled", False)
        _cache.set_enabled(enabled)
    except Exception:
        pass  # Not in Streamlit context

    return _cache


def _j(url, headers=None, params=None):
    session = _get_session()
    try:
        r = session.get(url, headers=headers or {}, params=params or {})
        if r.status_code == 200:
            try:
                return r.json()
            except Exception:
                return {"_raw": r.text}
        return {"_error": f"HTTP {r.status_code}", "_url": url}
    except Exception as e:
        return {"_error": str(e), "_url": url}


def _cached_query(indicator: str, provider: str, query_fn) -> dict:
    """
    Query with caching support.

    Args:
        indicator: IP or domain to query
        provider: Provider name for cache key
        query_fn: Function to call if cache miss

    Returns:
        Cached or fresh response
    """
    cache = _get_cache()

    # Try cache first
    cached = cache.get(indicator, provider)
    if cached is not None:
        cached["_cached"] = True
        return cached

    # Cache miss - make API call
    result = query_fn()

    # Only cache successful responses
    if "_error" not in result:
        cache.set(indicator, provider, result)

    return result


def _query_provider(
    indicator: str,
    provider: str,
    key_name: str,
    keys: dict[str, str],
    url: str,
    *,
    headers: dict | None = None,
    params: dict | None = None,
) -> tuple[dict | None, bool]:
    """Query a single OSINT provider with caching.

    Returns (result_dict, was_cached) or (None, False) if the key is missing.
    """
    api_key = keys.get(key_name)
    if not api_key:
        return None, False

    final_headers = {k: (api_key if v == "__KEY__" else v) for k, v in (headers or {}).items()}
    final_params = {k: (api_key if v == "__KEY__" else v) for k, v in (params or {}).items()}

    result = _cached_query(
        indicator, provider, lambda: _j(url, headers=final_headers or None, params=final_params or None)
    )
    return result, bool(result.get("_cached"))


# Provider definitions: (result_key, cache_provider, key_name, url_template, headers, params)
_IP_PROVIDERS = [
    (
        "greynoise", "greynoise", "GREYNOISE_KEY",
        "https://api.greynoise.io/v3/community/{indicator}",
        {"key": "__KEY__", "Accept": "application/json"}, None,
    ),
    (
        "abuseipdb", "abuseipdb", "ABUSEIPDB_KEY",
        "https://api.abuseipdb.com/api/v2/check",
        {"Key": "__KEY__", "Accept": "application/json"},
        {"ipAddress": "{indicator}", "maxAgeInDays": "90"},
    ),
    (
        "vt", "vt_ip", "VT_KEY",
        "https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
        {"x-apikey": "__KEY__"}, None,
    ),
    (
        "shodan", "shodan", "SHODAN_KEY",
        "https://api.shodan.io/shodan/host/{indicator}",
        None, {"key": "__KEY__"},
    ),
]

_DOMAIN_PROVIDERS = [
    (
        "vt", "vt_domain", "VT_KEY",
        "https://www.virustotal.com/api/v3/domains/{indicator}",
        {"x-apikey": "__KEY__"}, None,
    ),
    (
        "otx", "otx", "OTX_KEY",
        "https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/general",
        {"X-OTX-API-KEY": "__KEY__"}, None,
    ),
]


def _query_single_provider_task(
    indicator: str,
    safe_indicator: str,
    result_key: str,
    cache_prov: str,
    key_name: str,
    url_tpl: str,
    hdr_tpl: dict | None,
    param_tpl: dict | None,
    keys: dict[str, str],
) -> tuple[str, dict | None, bool]:
    """Query a single provider — designed to run inside a thread pool."""
    url = url_tpl.replace("{indicator}", safe_indicator)
    headers = {
        k: v.replace("{indicator}", indicator) if isinstance(v, str) else v
        for k, v in (hdr_tpl or {}).items()
    }
    params = {
        k: v.replace("{indicator}", indicator) if isinstance(v, str) else v
        for k, v in (param_tpl or {}).items()
    }
    result, cached = _query_provider(
        indicator, cache_prov, key_name, keys, url, headers=headers, params=params,
    )
    return result_key, result, cached


def _query_providers(
    indicator: str, provider_defs: list, keys: dict[str, str],
) -> tuple[dict, int]:
    """Run all configured providers for an indicator in parallel."""
    # URL-encode the indicator to prevent SSRF / injection via crafted values
    safe_indicator = quote(indicator, safe="")

    obj: dict[str, Any] = {}
    cache_hits = 0

    # Query providers concurrently using a thread pool
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(len(provider_defs), 1)) as executor:
        futures = {
            executor.submit(
                _query_single_provider_task,
                indicator, safe_indicator,
                result_key, cache_prov, key_name, url_tpl, hdr_tpl, param_tpl, keys,
            ): result_key
            for result_key, cache_prov, key_name, url_tpl, hdr_tpl, param_tpl in provider_defs
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                rkey, result, cached = future.result()
                if result is not None:
                    obj[rkey] = result
                    if cached:
                        cache_hits += 1
            except Exception as e:
                name = futures[future]
                logger.warning("Provider %s failed for %s: %s", name, indicator, e)

    return obj, cache_hits


def enrich(
    artifacts: dict[str, list], keys: dict[str, str], phase: PhaseHandle | None = None, throttle: float = 0.35
) -> dict[str, Any]:
    if phase and phase.should_skip():
        phase.done("OSINT skipped.")
        return {"ips": {}, "domains": {}, "ja3": {}}

    ips = [ip for ip in artifacts.get("ips", []) if is_public_ipv4(ip)]
    doms = artifacts.get("domains", [])
    total = len(ips) + len(doms)
    done = 0
    res: dict[str, Any] = {"ips": {}, "domains": {}, "ja3": {}}

    def tick(msg):
        nonlocal done
        done += 1
        if phase and total > 0:
            phase.set(10 + int((done / total) * 80), msg)

    if phase:
        phase.set(5, f"Querying {len(ips)} IPs and {len(doms)} domains…")

    for ip in ips:
        if phase and phase.should_skip():
            break

        obj, cache_hits = _query_providers(ip, _IP_PROVIDERS, keys)

        # Reverse DNS (not cached - fast local operation)
        ptr = resolve_ip(ip)
        if ptr:
            obj["ptr"] = ptr

        # GeoIP (City/Country)
        geo = GeoIP.lookup(ip)
        if geo:
            obj["city"] = geo.get("city")
            obj["country"] = geo.get("country")

        res["ips"][ip] = obj
        cache_status = f" (cached: {cache_hits})" if cache_hits > 0 else ""
        tick(f"OSINT IP {ip}{cache_status}")

        # Only throttle if we made actual API calls
        if cache_hits == 0:
            time.sleep(throttle)

    for dom in doms:
        if phase and phase.should_skip():
            break

        obj, cache_hits = _query_providers(dom, _DOMAIN_PROVIDERS, keys)

        res["domains"][dom] = obj
        cache_status = f" (cached: {cache_hits})" if cache_hits > 0 else ""
        tick(f"OSINT domain {dom}{cache_status}")

        # Only throttle if we made actual API calls
        if cache_hits == 0:
            time.sleep(throttle)

    # MAC Manufacturer Lookup
    macs = artifacts.get("macs", [])
    if macs:
        res["macs"] = {}
        for mac in macs:
            res["macs"][mac] = {"manufacturer": get_mac_manufacturer(mac)}

    if phase:
        phase.done("OSINT enrichment complete." if not phase.should_skip() else "OSINT skipped.")
    return res


def get_mac_manufacturer(mac: str) -> str:
    """Simple MAC manufacturer lookup based on OUI."""
    if not mac or ":" not in mac:
        return "Unknown"

    # Simple dictionary of some common OUIs
    COMMON_OUIS = {
        "00:05:5D": "D-Link",
        "00:0C:29": "VMware",
        "00:50:56": "VMware",
        "08:00:27": "VirtualBox",
        "00:15:5D": "Microsoft (Hyper-V)",
        "00:1C:42": "Parallels",
        "00:16:3E": "Xen",
        "00:25:90": "Supermicro",
        "00:1A:11": "Google",
        "3C:5A:B4": "Google",
        "00:03:FF": "Microsoft",
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
    }

    oui = mac.upper()[:8]
    return COMMON_OUIS.get(oui, "Unknown")
