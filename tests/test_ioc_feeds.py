import pytest

from shallots.ioc_feeds import IocFeedWorker, extract_domain_candidates, normalize_indicator_values


def test_normalizes_ip_indicator():
    assert normalize_indicator_values("ip", " 8.8.8.8 ") == ["8.8.8.8"]


def test_rejects_invalid_ip_indicator():
    assert normalize_indicator_values("ip", "not-an-ip") == []


def test_extracts_domain_from_urlhaus_url():
    assert normalize_indicator_values(
        "domain",
        "https://maxwhywtk.betbuf90.com/a285bef4-0a7b-4125",
    ) == ["maxwhywtk.betbuf90.com"]


def test_extracts_domain_from_host_path():
    assert normalize_indicator_values("domain", "example.evil/path/file") == ["example.evil"]


def test_rejects_ip_in_domain_feed():
    assert normalize_indicator_values("domain", "http://27.215.182.105:50867/i") == []


def test_extracts_domain_candidates_from_alert_text():
    assert extract_domain_candidates(
        "callback to MaxWhyWTK.betbuf90.com and maxwhywtk.betbuf90.com/path"
    ) == ["maxwhywtk.betbuf90.com"]


class FakeIocDB:
    async def check_ioc(self, value):
        if value == "maxwhywtk.betbuf90.com":
            return [{
                "feed_name": "urlhaus_recent_hosts",
                "indicator_type": "domain",
                "value": value,
                "context": "Feed: urlhaus_recent_hosts",
            }]
        return []


@pytest.mark.asyncio
async def test_match_alert_checks_domain_candidates_exactly():
    worker = IocFeedWorker(cfg=type("Cfg", (), {"feeds": []})(), db=FakeIocDB())
    matches = await worker.match_alert({
        "src_ip": "",
        "dst_ip": "",
        "title": "callback to maxwhywtk.betbuf90.com",
        "description": "",
    })
    assert matches == [{
        "field": "title/description",
        "value": "maxwhywtk.betbuf90.com",
        "feed": "urlhaus_recent_hosts",
        "indicator_type": "domain",
        "indicator": "maxwhywtk.betbuf90.com",
        "context": "Feed: urlhaus_recent_hosts",
    }]
