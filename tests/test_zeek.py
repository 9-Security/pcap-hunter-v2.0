import pandas as pd

from app.pipeline.zeek import merge_zeek_dns


def test_merge_zeek_dns():
    # Setup initial state
    features = {"artifacts": {"domains": ["existing.com"]}}

    # Mock Zeek tables with DNS log
    zeek_tables = {"dns.log": pd.DataFrame({"query": ["new.com", "existing.com", "another.org", None]})}

    # Run merge
    updated = merge_zeek_dns(zeek_tables, features)

    # Verify
    domains = updated["artifacts"]["domains"]
    assert "existing.com" in domains
    assert "new.com" in domains
    assert "another.org" in domains
    assert len(domains) == 3  # Should be unique (existing.com was dup)
    assert None not in domains


def test_merge_zeek_dns_empty():
    features = {"artifacts": {"domains": []}}
    zeek_tables = {}

    updated = merge_zeek_dns(zeek_tables, features)
    assert updated["artifacts"]["domains"] == []


def test_merge_zeek_dns_no_query_col():
    features = {"artifacts": {"domains": []}}
    zeek_tables = {"dns.log": pd.DataFrame({"other": [1, 2, 3]})}

    updated = merge_zeek_dns(zeek_tables, features)
    assert updated["artifacts"]["domains"] == []
