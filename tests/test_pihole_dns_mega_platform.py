"""Regression test: the urlhaus_recent_hosts feed extracts hostnames from
malicious URLs, not domain-level indicators, so legitimate mega-platforms
abused for a single bad link (google.com, github.com, ...) land in the feed.
DNS resolution alone can't see the URL path, so PiholeDnsIngestor must not
alert on the bare apex of a mega-platform - live data on 2026-07-21 showed
this firing on www.google.com as a "known-malware domain" alert."""
from __future__ import annotations

from shallots.ingest.pihole_dns import PiholeDnsIngestor, _is_mega_platform


def test_mega_platform_apex_and_subdomains_recognized():
    assert _is_mega_platform("google.com")
    assert _is_mega_platform("www.google.com")
    assert _is_mega_platform("drive.google.com")
    assert _is_mega_platform("github.com")
    assert not _is_mega_platform("microsoftupdater.info")
    assert not _is_mega_platform("evil-lookalike-google.com")


def test_match_malware_skips_mega_platform_even_if_in_feed():
    ing = PiholeDnsIngestor(cfg=None, db=None, alert_queue=None)
    ing._malware_domains = {"google.com", "evil-c2-domain.ru"}
    assert ing._match_malware("www.google.com") is None
    assert ing._match_malware("beacon.evil-c2-domain.ru") == "evil-c2-domain.ru"
