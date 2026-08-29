"""Regression tests for the D31 settlement-witness auth headers this service
attaches to its outbound /settlement-witness/attest calls.

Covers the durable canonicalization of the auth-header wiring that was
already live in production (uncommitted) — see
reports/readiness/settlement-witness-attest-auth-staging-implementation-20260826-evidence/
for the original staging proof this reproduces against real source control.
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import attest_service as svc  # noqa: E402


def test_auth_headers_contain_bearer_timestamp_and_nonce(monkeypatch):
    monkeypatch.setenv("SETTLEMENT_ATTEST_API_KEY", "test-key-123")
    before = int(time.time())
    headers = svc._settlement_attest_auth_headers()
    after = int(time.time())

    assert headers["Authorization"] == "Bearer test-key-123"
    assert before <= int(headers["X-Settlement-Timestamp"]) <= after
    assert len(headers["X-Settlement-Nonce"]) == 32
    int(headers["X-Settlement-Nonce"], 16)  # uuid4().hex is valid hex


def test_auth_headers_fail_closed_with_empty_bearer_when_key_unset(monkeypatch):
    monkeypatch.delenv("SETTLEMENT_ATTEST_API_KEY", raising=False)
    headers = svc._settlement_attest_auth_headers()
    assert headers["Authorization"] == "Bearer "


def test_auth_headers_never_leak_key_by_repr_or_str(monkeypatch):
    monkeypatch.setenv("SETTLEMENT_ATTEST_API_KEY", "super-secret-value")
    headers = svc._settlement_attest_auth_headers()
    # the key appears only inside the Authorization header, never duplicated
    # into other fields, log-adjacent structures, etc.
    assert list(headers.keys()) == [
        "Authorization",
        "X-Settlement-Timestamp",
        "X-Settlement-Nonce",
    ]


def test_two_consecutive_calls_produce_different_nonces(monkeypatch):
    monkeypatch.setenv("SETTLEMENT_ATTEST_API_KEY", "test-key-123")
    h1 = svc._settlement_attest_auth_headers()
    h2 = svc._settlement_attest_auth_headers()
    assert h1["X-Settlement-Nonce"] != h2["X-Settlement-Nonce"]


def test_post_json_forwards_headers_to_requests_post(monkeypatch):
    captured = {}

    class _Resp:
        status_code = 200

        def json(self):
            return {"ok": True}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        return _Resp()

    monkeypatch.setattr(svc.requests, "post", fake_post)
    result = svc.post_json("http://example.invalid/x", {"a": 1}, headers={"Authorization": "Bearer abc"})

    assert result == {"ok": True}
    assert captured["headers"] == {"Authorization": "Bearer abc"}


def test_post_json_headers_default_to_none_for_unrelated_callers(monkeypatch):
    captured = {}

    class _Resp:
        status_code = 200

        def json(self):
            return {"ok": True}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["headers"] = headers
        return _Resp()

    monkeypatch.setattr(svc.requests, "post", fake_post)
    svc.post_json("http://example.invalid/x", {"a": 1})
    assert captured["headers"] is None


def _source_calls_auth_headers_at(line_no: int, source_lines: list[str]) -> bool:
    return "headers=_settlement_attest_auth_headers()" in source_lines[line_no - 1]


def test_all_three_sar_call_sites_use_the_auth_helper():
    source_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "attest_service.py")
    with open(source_path) as f:
        lines = f.readlines()

    call_site_lines = [
        i + 1 for i, line in enumerate(lines) if "post_json(SAR_URL," in line and "sar_payload" in line
    ]
    # 3 original D31-authenticated routes + the bounded public demo route,
    # all sharing the same SAR_URL (the demo route must NOT use a different
    # settlement-witness endpoint -- see the 2026-08-29 rollback: pointing it
    # at SAR_URL + "/attest" hit a different, JWS-wrapped response shape with
    # no top-level receipt_id and caused false-negative failures).
    assert len(call_site_lines) == 4, f"expected exactly 4 SAR_URL call sites, found {call_site_lines}"
    for line_no in call_site_lines:
        assert "headers=_settlement_attest_auth_headers()" in lines[line_no - 1], (
            f"call site at line {line_no} is missing the D31 auth headers"
        )
