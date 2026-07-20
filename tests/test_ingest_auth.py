"""Auth boundary tests for unauthenticated ingest endpoints."""

from __future__ import annotations

from shallots.web.api.agents import _secret_rejection


class FakeRequest:
    def __init__(self, headers: dict[str, str]):
        self.headers = headers


def test_secret_rejection_fails_closed_when_unconfigured() -> None:
    # Write-capable ingest must fail CLOSED: no configured secret -> 503, never open.
    response = _secret_rejection(FakeRequest({}), "", "X-Test-Secret")
    assert response is not None
    assert response.status == 503


def test_secret_rejection_rejects_missing_configured_secret() -> None:
    response = _secret_rejection(FakeRequest({}), "expected", "X-Test-Secret")

    assert response is not None
    assert response.status == 401


def test_secret_rejection_rejects_wrong_configured_secret() -> None:
    response = _secret_rejection(
        FakeRequest({"X-Test-Secret": "wrong"}),
        "expected",
        "X-Test-Secret",
    )

    assert response is not None
    assert response.status == 401


def test_secret_rejection_accepts_matching_configured_secret() -> None:
    request = FakeRequest({"X-Test-Secret": "expected"})

    assert _secret_rejection(request, "expected", "X-Test-Secret") is None
