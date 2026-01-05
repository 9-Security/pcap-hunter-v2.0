from __future__ import annotations

from app.pipeline.osint import get_mac_manufacturer
from app.ui.charts import plot_flow_timeline, plot_top_n_charts


def test_mac_manufacturer_lookup():
    assert get_mac_manufacturer("00:0C:29:11:22:33") == "VMware"
    assert get_mac_manufacturer("B8:27:EB:AA:BB:CC") == "Raspberry Pi"
    assert get_mac_manufacturer("00:00:00:00:00:00") == "Unknown"
    assert get_mac_manufacturer("invalid") == "Unknown"
    assert get_mac_manufacturer(None) == "Unknown"


def test_timeline_slider_enabled():
    flows = [{"pkt_times": [1000.0, 1001.0], "proto": "TCP", "src": "1.1.1.1", "dst": "2.2.2.2", "count": 2}]
    fig = plot_flow_timeline(flows)
    # Slider is now intentionally hidden for a cleaner look
    assert fig.layout.xaxis.rangeslider.visible is False


def test_top_n_charts_empty():
    fig = plot_top_n_charts({}, "Test")
    assert len(fig.data) == 0


def test_top_n_charts_with_data():
    data = {"1.1.1.1": 10, "2.2.2.2": 20}
    fig = plot_top_n_charts(data, "Top IPs")
    assert len(fig.data) == 1
    assert fig.layout.title.text == "Top IPs"
