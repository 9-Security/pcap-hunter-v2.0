from unittest.mock import MagicMock, patch

from app.utils.common import is_public_ipv4, make_slug, uniq_sorted


def test_is_public_ipv4():
    assert is_public_ipv4("8.8.8.8") is True
    assert is_public_ipv4("192.168.1.1") is False
    assert is_public_ipv4("10.0.0.1") is False
    assert is_public_ipv4("127.0.0.1") is False
    assert is_public_ipv4("invalid") is False
    assert is_public_ipv4(None) is False


def test_make_slug():
    assert make_slug("Hello World") == "hello_world"
    assert make_slug("  Test  ") == "__test__"
    assert make_slug("Foo_Bar") == "foo_bar"


def test_uniq_sorted():
    assert uniq_sorted([3, 1, 2, 1]) == [1, 2, 3]


def test_filter_flows_by_ips():
    from app.utils.common import filter_flows_by_ips

    flows = [
        {"src": "1.1.1.1", "dst": "2.2.2.2"},
        {"src": "3.3.3.3", "dst": "4.4.4.4"},
        {"src": "1.1.1.1", "dst": "5.5.5.5"},
    ]

    # Test empty selection (return all)
    assert len(filter_flows_by_ips(flows, set())) == 3

    # Test selection
    selected = {"1.1.1.1"}
    filtered = filter_flows_by_ips(flows, selected)
    assert len(filtered) == 2
    assert filtered[0]["dst"] == "2.2.2.2"
    assert filtered[1]["dst"] == "5.5.5.5"

    # Test no match
    assert len(filter_flows_by_ips(flows, {"9.9.9.9"})) == 0
    assert uniq_sorted([]) == []
    assert uniq_sorted(None) == []


def test_resolve_ip():
    import socket

    from app.utils.common import resolve_ip

    # Test success
    with patch("socket.gethostbyaddr", return_value=("google-public-dns-a.google.com", [], ["8.8.8.8"])):
        assert resolve_ip("8.8.8.8") == "google-public-dns-a.google.com"

    # Test failure
    with patch("socket.gethostbyaddr", side_effect=socket.herror("Host not found")):
        assert resolve_ip("1.2.3.4") is None


def test_get_whois_info():
    from app.utils.common import get_whois_info

    # Create a mock whois module
    mock_whois_module = MagicMock()

    # Test success (dict)
    mock_whois_module.whois.return_value = {"domain_name": "example.com"}
    with patch.dict("sys.modules", {"whois": mock_whois_module}):
        info = get_whois_info("example.com")
        assert isinstance(info, dict)
        assert info["domain_name"] == "example.com"

    # Test success (object with text)
    mock_w = MagicMock()
    mock_w.text = "Domain Name: EXAMPLE.COM"
    mock_whois_module.whois.return_value = mock_w
    with patch.dict("sys.modules", {"whois": mock_whois_module}):
        info = get_whois_info("example.com")
        assert info == mock_w

    # Test failure
    mock_whois_module.whois.side_effect = Exception("Lookup failed")
    with patch.dict("sys.modules", {"whois": mock_whois_module}):
        info = get_whois_info("example.com")
        assert isinstance(info, str)
        assert "WHOIS lookup failed" in info


def test_filter_flows_by_protocol():
    from app.utils.common import filter_flows_by_protocol

    flows = [
        {"proto": "HTTP", "count": 10},
        {"proto": "DNS", "count": 5},
        {"proto": "HTTP", "count": 2},
        {"proto": "SSH", "count": 1},
    ]

    # Test empty selection (return all)
    assert len(filter_flows_by_protocol(flows, set())) == 4

    # Test selection
    filtered = filter_flows_by_protocol(flows, {"HTTP"})
    assert len(filtered) == 2
    assert all(f["proto"] == "HTTP" for f in filtered)

    # Test multiple
    filtered = filter_flows_by_protocol(flows, {"HTTP", "SSH"})
    assert len(filtered) == 3

    # Test no match
    assert len(filter_flows_by_protocol(flows, {"FTP"})) == 0


def test_filter_flows_by_time():
    from app.utils.common import filter_flows_by_time

    flows = [
        {"pkt_times": [100, 105], "id": 1},
        {"pkt_times": [200, 210], "id": 2},
        {"pkt_times": [300, 305], "id": 3},
        {"pkt_times": [], "id": 4},  # No times
    ]

    # Test range covering all
    filtered = filter_flows_by_time(flows, 0, 400)
    assert len(filtered) == 3  # id 4 excluded

    # Test range covering some
    filtered = filter_flows_by_time(flows, 150, 250)
    assert len(filtered) == 1
    assert filtered[0]["id"] == 2

    # Test exact match start
    filtered = filter_flows_by_time(flows, 100, 100)
    assert len(filtered) == 1
    assert filtered[0]["id"] == 1

    # Test no match
    filtered = filter_flows_by_time(flows, 500, 600)
    assert len(filtered) == 0

    # Test None inputs
    assert len(filter_flows_by_time(flows, None, None)) == 4
