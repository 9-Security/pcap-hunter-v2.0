from __future__ import annotations

from typing import Any, Dict, List

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


def plot_world_map(
    ip_data: List[Dict[str, Any]], flows: List[Dict[str, Any]] = None, home_loc: tuple[float, float] = (0.0, 0.0)
) -> go.Figure:
    """
    Plots a world map with markers for IP locations and connectivity lines.
    ip_data: list of dicts with keys: ip, country, city, lat, lon
    flows: list of dicts with keys: src, dst, count (optional, for drawing lines)
    home_loc: (lat, lon) to use for private IPs that don't have geo data.
    """
    if not ip_data and not flows:
        return go.Figure()

    # Create a lookup for lat/lon by IP
    loc_map = {d["ip"]: (d["lat"], d["lon"]) for d in ip_data}

    df = pd.DataFrame(ip_data) if ip_data else pd.DataFrame()
    if not df.empty and "count" not in df.columns:
        df["count"] = 1

    fig = go.Figure()

    # 1. Markers
    if not df.empty:
        df_agg = (
            df.groupby(["lat", "lon", "city", "country"])
            .agg({"count": "sum", "ip": lambda x: list(x)})
            .reset_index()
        )
        fig.add_trace(
            go.Scattergeo(
                lat=df_agg["lat"],
                lon=df_agg["lon"],
                text=df_agg["city"] + ", " + df_agg["country"] + " (" + df_agg["count"].astype(str) + ")",
                customdata=df_agg["ip"],
                marker=dict(
                    size=df_agg["count"] * 5,
                    sizemode="area",
                    sizemin=5,
                    color="cyan",
                    line=dict(width=1, color="#333"),
                ),
                name="Locations",
                hoverinfo="text",
            )
        )

    # 2. Connectivity Lines (Arcs)
    if flows:
        from app.utils.common import is_public_ipv4

        # Aggregate flows between src-dst pairs
        conn_counts = {}
        for f in flows:
            src, dst = f.get("src"), f.get("dst")
            count = f.get("count", 1)
            if src and dst and src != dst:
                # Resolve locations
                sloc = loc_map.get(src)
                if not sloc and not is_public_ipv4(src):
                    sloc = home_loc

                dloc = loc_map.get(dst)
                if not dloc and not is_public_ipv4(dst):
                    dloc = home_loc

                if sloc and dloc:
                    pair = tuple(sorted((src, dst)))
                    conn_counts[pair] = conn_counts.get(pair, 0) + count

                    # Update loc_map temporarily for the drawing loop
                    if src not in loc_map: loc_map[src] = sloc
                    if dst not in loc_map: loc_map[dst] = dloc

        if conn_counts:
            max_count = max(conn_counts.values())

            def get_lines_for_width(width_threshold_min, width_threshold_max, line_width, color):
                lats, lons = [], []
                for (src, dst), count in conn_counts.items():
                    if width_threshold_min <= count <= width_threshold_max:
                        slat, slon = loc_map[src]
                        dlat, dlon = loc_map[dst]
                        lats.extend([slat, dlat, None])
                        lons.extend([slon, dlon, None])
                if lats:
                    fig.add_trace(
                        go.Scattergeo(
                            lat=lats,
                            lon=lons,
                            mode="lines",
                            line=dict(width=line_width, color=color),
                            name=f"Traffic ({line_width}px)",
                            hoverinfo="skip",
                        )
                    )

            t1, t2 = max_count * 0.33, max_count * 0.66
            get_lines_for_width(0, t1, 1.5, "rgba(255, 100, 100, 0.4)")
            get_lines_for_width(t1 + 0.001, t2, 3.5, "rgba(255, 100, 100, 0.6)")
            get_lines_for_width(t2 + 0.001, float("inf"), 6.0, "rgba(255, 50, 50, 0.8)")

    fig.update_geos(
        showcountries=True,
        countrycolor="#444",
        showocean=True,
        oceancolor="#111",
        showland=True,
        landcolor="#222",
        bgcolor="#000",
        projection_type="equirectangular",
        lataxis_range=[-60, 90],
    )
    fig.update_layout(
        title="Global Traffic Origins & Connectivity",
        template="plotly_dark",
        margin={"r": 0, "t": 30, "l": 0, "b": 0},
        height=600,
        geo=dict(projection_scale=1.1, center=dict(lat=20, lon=0)),
        legend=dict(orientation="h", yanchor="bottom", y=0, xanchor="right", x=1),
    )
    return fig


def plot_protocol_distribution(protocol_counts: Dict[str, int]) -> go.Figure:
    """
    Plots a donut chart of protocol distribution.
    """
    if not protocol_counts:
        return go.Figure()

    labels = list(protocol_counts.keys())
    values = list(protocol_counts.values())

    fig = px.pie(
        names=labels,
        values=values,
        hole=0.4,
        title="Protocol Distribution",
        template="plotly_dark",
        color_discrete_sequence=px.colors.qualitative.Pastel,
    )
    fig.update_traces(textposition="inside", textinfo="percent+label", customdata=labels)
    fig.update_layout(
        margin={"r": 0, "t": 30, "l": 0, "b": 0},
        height=400,
    )
    return fig


def plot_flow_timeline(flows: List[Dict[str, Any]]) -> go.Figure:
    """
    Plots a dual-axis chart:
    - Primary Y (Scatter): Flow duration over time.
    - Secondary Y (Area): Aggregate traffic volume over time.
    Refined for a 'premium' look: subtle colors, better scaling, and less clutter.
    """
    if not flows:
        return go.Figure()

    data = []
    for f in flows:
        if not f.get("pkt_times"): continue
        start_ts = min(f["pkt_times"])
        duration = max(f["pkt_times"]) - start_ts
        proto = f.get("proto", "Unknown")
        size = f.get("count", 1)
        data.append({
            "ts": pd.to_datetime(start_ts, unit="s"),
            "duration": duration,
            "proto": proto,
            "packets": size,
            "src": f.get("src"),
            "dst": f.get("dst")
        })

    if not data: return go.Figure()
    df = pd.DataFrame(data).sort_values("ts")

    # 1. Aggregate volume for area chart
    df_vol = df.resample("1s", on="ts").agg({"packets": "sum"}).fillna(0).reset_index()

    fig = go.Figure()

    # Trace 1: Volume (Area) on secondary Y - subtle professional color
    fig.add_trace(
        go.Scatter(
            x=df_vol["ts"],
            y=df_vol["packets"],
            fill="tozeroy",
            name="Volume",
            line=dict(color="rgba(100, 150, 255, 0.2)", width=1),
            fillcolor="rgba(100, 150, 255, 0.1)",
            yaxis="y2",
            hoverinfo="skip" # Focus on flows
        )
    )

    # Trace 2: Flows (Scatter) on primary Y
    unique_protos = df["proto"].unique()
    colors = px.colors.qualitative.Pastel
    for i, p in enumerate(unique_protos):
        sub = df[df["proto"] == p]
        fig.add_trace(
            go.Scatter(
                x=sub["ts"],
                y=sub["duration"],
                mode="markers",
                name=p,
                # Refined marker scale: smaller bubbles
                marker=dict(
                    size=sub["packets"].apply(lambda x: min(2 + x * 0.5, 18)), 
                    opacity=0.5, 
                    color=colors[i % len(colors)],
                    line=dict(width=0.5, color="rgba(255,255,255,0.2)")
                ),
                customdata=sub[["src", "dst", "packets"]],
                hovertemplate="<b>%{name}</b><br>Time: %{x}<br>Duration: %{y}s<br>Src: %{customdata[0]}<br>Dst: %{customdata[1]}<br>Packets: %{customdata[2]}<extra></extra>"
            )
        )

    fig.update_layout(
        title="Analysis Timeline (Flows & Volume)",
        template="plotly_dark",
        height=500,
        xaxis_title=None,
        yaxis_title="Flow Duration (s)",
        yaxis=dict(
            gridcolor="rgba(255,255,255,0.05)",
            zerolinecolor="rgba(255,255,255,0.1)"
        ),
        yaxis2=dict(
            title="Volume (pkts/sec)", 
            overlaying="y", 
            side="right", 
            showgrid=False, 
            rangemode="tozero",
            tickfont=dict(color="rgba(100, 150, 255, 0.6)"),
            title_font=dict(color="rgba(100, 150, 255, 0.6)")
        ),
        legend=dict(
            orientation="h", 
            yanchor="top", 
            y=-0.15, 
            xanchor="center", 
            x=0.5,
            font=dict(size=10),
            bgcolor="rgba(0,0,0,0)"
        ),
        hovermode="closest",
        margin=dict(l=50, r=50, t=80, b=40),
        xaxis=dict(
            gridcolor="rgba(255,255,255,0.05)",
            rangeslider=dict(visible=False) # Removal of rangeslider for cleaner look
        )
    )
    return fig


def plot_top_n_charts(data: Dict[str, Dict[str, int]], title: str) -> go.Figure:
    """
    Plots horizontal bar charts for TopN analysis.
    data: { "category": { "label": count, ... }, ... }
    Refined with 'premium' styling.
    """
    if not data:
        return go.Figure()

    labels = list(data.keys())
    values = list(data.values())

    # Sort for display
    sorted_items = sorted(zip(labels, values), key=lambda x: x[1], reverse=True)[:10] # Top 10 focus
    if not sorted_items:
        return go.Figure()

    labels, values = zip(*sorted_items)

    fig = px.bar(
        x=values,
        y=labels,
        orientation="h",
        title=title,
        template="plotly_dark",
        labels={"x": "Frequency", "y": ""}, # Hide redundant 'Indicator' label
        color_discrete_sequence=["#4A90E2"] # Professional blue
    )
    fig.update_layout(
        margin={"r": 20, "t": 40, "l": 20, "b": 20}, 
        height=350, 
        yaxis={"categoryorder": "total ascending"},
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        title_font=dict(size=14, color="#DDD")
    )
    fig.update_traces(
        marker_color="rgba(74, 144, 226, 0.7)",
        marker_line_color="rgba(74, 144, 226, 1)",
        marker_line_width=1
    )
    return fig

