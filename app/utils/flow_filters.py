from __future__ import annotations


def filter_flows_by_ips(flows: list[dict], selected_ips: set[str]) -> list[dict]:
    """
    Return a list of flows where src or dst is in selected_ips.
    """
    if not selected_ips:
        return flows
    return [f for f in flows if (f.get("src") in selected_ips) or (f.get("dst") in selected_ips)]


def filter_flows_by_protocol(flows: list[dict], protocols: set[str]) -> list[dict]:
    """Filter flows by protocol."""
    if not protocols:
        return flows
    return [f for f in flows if f.get("proto") in protocols]


def filter_flows_by_time(flows: list[dict], start_ts: float | None, end_ts: float | None) -> list[dict]:
    """Filter flows by time range based on earliest packet time."""
    if start_ts is None or end_ts is None:
        return flows
    res = []
    for f in flows:
        times = f.get("pkt_times")
        if not times:
            continue
        t = min(times)
        if start_ts <= t <= end_ts:
            res.append(f)
    return res
