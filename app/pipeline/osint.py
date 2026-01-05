from __future__ import annotations

import time
from typing import Any, Dict

from app.pipeline.osint_cache import get_osint_cache
from app.pipeline.state import PhaseHandle
from app.security.opsec import hardened_session
from app.utils.common import is_public_ipv4, resolve_ip

S = hardened_session(timeout=12)

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
    try:
        r = S.get(url, headers=headers or {}, params=params or {})
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


def enrich(
    artifacts: Dict[str, list], keys: Dict[str, str], phase: PhaseHandle | None = None, throttle: float = 0.35
) -> Dict[str, Any]:
    if phase and phase.should_skip():
        phase.done("OSINT skipped.")
        return {"ips": {}, "domains": {}, "ja3": {}}

    ips = [ip for ip in artifacts.get("ips", []) if is_public_ipv4(ip)]
    doms = artifacts.get("domains", [])
    total = len(ips) + len(doms)
    done = 0
    res = {"ips": {}, "domains": {}, "ja3": {}}

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
        obj = {}
        cache_hits = 0

        if keys.get("GREYNOISE_KEY"):
            obj["greynoise"] = _cached_query(
                ip,
                "greynoise",
                lambda: _j(
                    f"https://api.greynoise.io/v3/community/{ip}",
                    headers={"key": keys["GREYNOISE_KEY"], "Accept": "application/json"},
                ),
            )
            if obj["greynoise"].get("_cached"):
                cache_hits += 1

        if keys.get("ABUSEIPDB_KEY"):
            obj["abuseipdb"] = _cached_query(
                ip,
                "abuseipdb",
                lambda: _j(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": keys["ABUSEIPDB_KEY"], "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                ),
            )
            if obj["abuseipdb"].get("_cached"):
                cache_hits += 1

        if keys.get("VT_KEY"):
            obj["vt"] = _cached_query(
                ip,
                "vt_ip",
                lambda: _j(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": keys["VT_KEY"]},
                ),
            )
            if obj["vt"].get("_cached"):
                cache_hits += 1

        if keys.get("SHODAN_KEY"):
            obj["shodan"] = _cached_query(
                ip,
                "shodan",
                lambda: _j(
                    f"https://api.shodan.io/shodan/host/{ip}",
                    params={"key": keys["SHODAN_KEY"]},
                ),
            )
            if obj["shodan"].get("_cached"):
                cache_hits += 1

        # Reverse DNS (not cached - fast local operation)
        ptr = resolve_ip(ip)
        if ptr:
            obj["ptr"] = ptr

        res["ips"][ip] = obj
        cache_status = f" (cached: {cache_hits})" if cache_hits > 0 else ""
        tick(f"OSINT IP {ip}{cache_status}")

        # Only throttle if we made actual API calls
        if cache_hits == 0:
            time.sleep(throttle)

    for dom in doms:
        if phase and phase.should_skip():
            break
        obj = {}
        cache_hits = 0

        if keys.get("VT_KEY"):
            obj["vt"] = _cached_query(
                dom,
                "vt_domain",
                lambda: _j(
                    f"https://www.virustotal.com/api/v3/domains/{dom}",
                    headers={"x-apikey": keys["VT_KEY"]},
                ),
            )
            if obj["vt"].get("_cached"):
                cache_hits += 1

        if keys.get("OTX_KEY"):
            obj["otx"] = _cached_query(
                dom,
                "otx",
                lambda: _j(
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{dom}/general",
                    headers={"X-OTX-API-KEY": keys["OTX_KEY"]},
                ),
            )
            if obj["otx"].get("_cached"):
                cache_hits += 1

        res["domains"][dom] = obj
        cache_status = f" (cached: {cache_hits})" if cache_hits > 0 else ""
        tick(f"OSINT domain {dom}{cache_status}")

        # Only throttle if we made actual API calls
        if cache_hits == 0:
            time.sleep(throttle)

    if phase:
        phase.done("OSINT enrichment complete." if not phase.should_skip() else "OSINT skipped.")
    return res
