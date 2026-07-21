"""Regression test: the free-text IoC scan in match_alert() draws on the
same urlhaus_recent_hosts feed as PiholeDnsIngestor and was independently
vulnerable to the same false positive - any alert whose title/description
merely mentions google.com/github.com/etc (e.g. a benign exec-monitoring
"curl drive.google.com" alert) would force-escalate to critical/0.95
confidence, since check_ioc() does an exact-value lookup with no awareness
that the feed contains URL hostnames, not domain-level indicators."""
from __future__ import annotations

import pytest

from shallots.config import IocFeedConfig
from shallots.ioc_feeds import IocFeedWorker, _is_mega_platform


def test_mega_platform_recognized():
    assert _is_mega_platform("google.com")
    assert _is_mega_platform("drive.google.com")
    assert not _is_mega_platform("evil-c2-domain.ru")


class _FakeDB:
    def __init__(self, rows):
        self._rows = rows
        self.queried = []

    async def check_ioc(self, value):
        self.queried.append(value)
        return self._rows.get(value, [])


@pytest.mark.asyncio
async def test_match_alert_skips_mega_platform_domain_mention():
    db = _FakeDB({
        "google.com": [{"feed_name": "urlhaus_recent_hosts", "indicator_type": "domain",
                         "value": "google.com", "context": ""}],
    })
    worker = IocFeedWorker(cfg=IocFeedConfig(), db=db)
    matches = await worker.match_alert({
        "src_ip": "", "dst_ip": "",
        "title": "exec: curl", "description": "curl https://drive.google.com/uc?id=x",
    })
    assert matches == []
    # never even queried the mega-platform apex once extracted
    assert "google.com" not in db.queried


@pytest.mark.asyncio
async def test_match_alert_still_catches_real_malicious_domain():
    db = _FakeDB({
        "evil-c2-domain.ru": [{"feed_name": "urlhaus_recent_hosts", "indicator_type": "domain",
                                "value": "evil-c2-domain.ru", "context": ""}],
    })
    worker = IocFeedWorker(cfg=IocFeedConfig(), db=db)
    matches = await worker.match_alert({
        "src_ip": "", "dst_ip": "",
        "title": "beacon", "description": "callback to evil-c2-domain.ru observed",
    })
    assert len(matches) == 1
    assert matches[0]["indicator"] == "evil-c2-domain.ru"
