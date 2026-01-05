from __future__ import annotations

import ipaddress
import socket


def resolve_ip(ip: str) -> str | None:
    """Resolve IP to domain name (Reverse DNS)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def get_whois_info(target: str) -> dict | str:
    """
    Retrieve WHOIS information for a domain or IP.
    For IPs, uses RDAP (Registration Data Access Protocol).
    For domains, uses whois library.
    """
    import whois
    import requests

    try:
        if is_public_ipv4(target):
            # RDAP Lookup for IPs
            # Using ARIN's bootstrap service as a proxy or just common rdap.net
            url = f"https://rdap.arin.net/registry/ip/{target}"
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                data = r.json()
                # Map RDAP fields to common schema
                res = {
                    "domain_name": data.get("handle", target),
                    "registrar": data.get("name", "n/a"),
                    "creation_date": "n/a",
                    "expiration_date": "n/a",
                    "name": "n/a",
                    "org": "n/a",
                    "country": data.get("country", "n/a"),
                    "emails": "n/a",
                }
                # Extraction of Org/Entity info
                entities = data.get("entities", [])
                if entities:
                    ent = entities[0]
                    org_name = ent.get("vcardArray", [None, [["fn", {}, "text", "n/a"]]])[1][0][3]
                    res["org"] = org_name
                    res["name"] = org_name
                    # Try to find emails
                    vcard = ent.get("vcardArray", [None, []])[1]
                    emails = [item[3] for item in vcard if item[0] == "email"]
                    if emails:
                        res["emails"] = emails
                
                # Try to get events (created/updated)
                events = data.get("events", [])
                for ev in events:
                    if ev.get("eventAction") == "registration":
                        res["creation_date"] = ev.get("eventDate")
                    elif ev.get("eventAction") == "last changed":
                        res["expiration_date"] = ev.get("eventDate") # Using as 'last updated/expires' proxy
                
                return res
            else:
                return f"RDAP lookup failed (HTTP {r.status_code})"
        
        # Domain Lookup
        w = whois.whois(target)
        if hasattr(w, "text"):
            return w
        return dict(w)
    except Exception as e:
        return f"WHOIS lookup failed for {target}: {e}"


def is_public_ipv4(s: str) -> bool:
    """Check if string is a valid *public* IPv4 address."""
    try:
        ip = ipaddress.ip_address(s)
        return isinstance(ip, ipaddress.IPv4Address) and ip.is_global
    except (ValueError, TypeError):
        return False
