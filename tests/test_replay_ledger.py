"""Durable replay ledger (replay_ledger.SQLiteNonceStore) tests.

Everything here operates on tmp_path-scoped SQLite files. No production
data directory is ever touched -- see test_no_default_path_touched_by_import
below for an explicit guard on that.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import threading
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from authenticated_submission import NonceStoreUnavailableError, ReplayedNonceError  # noqa: E402
from replay_ledger import SQLiteNonceStore  # noqa: E402

MAX_SKEW = timedelta(seconds=300)


def _now():
    return datetime.now(timezone.utc)


def test_basic_claim_then_replay_rejected(tmp_path):
    store = SQLiteNonceStore(tmp_path / "ledger.sqlite3")
    now = _now()
    store.check_and_record("producer:a", "n1", now, MAX_SKEW)
    with pytest.raises(ReplayedNonceError):
        store.check_and_record("producer:a", "n1", now, MAX_SKEW)


def test_restart_survival_reopen_store(tmp_path):
    db_path = tmp_path / "ledger.sqlite3"
    now = _now()
    store1 = SQLiteNonceStore(db_path)
    store1.check_and_record("producer:a", "n1", now, MAX_SKEW)
    del store1  # simulate process exit -- no explicit close needed, nothing is held open

    store2 = SQLiteNonceStore(db_path)
    with pytest.raises(ReplayedNonceError):
        store2.check_and_record("producer:a", "n1", now, MAX_SKEW)


def test_different_nonce_same_producer_accepted(tmp_path):
    store = SQLiteNonceStore(tmp_path / "ledger.sqlite3")
    now = _now()
    store.check_and_record("producer:a", "n1", now, MAX_SKEW)
    store.check_and_record("producer:a", "n2", now, MAX_SKEW)  # must not raise


def test_cross_producer_same_nonce_value_is_not_a_collision(tmp_path):
    store = SQLiteNonceStore(tmp_path / "ledger.sqlite3")
    now = _now()
    store.check_and_record("producer:a", "shared-nonce", now, MAX_SKEW)
    store.check_and_record("producer:b", "shared-nonce", now, MAX_SKEW)  # must not raise -- different producer


def test_cross_route_reuse_of_same_producer_nonce_rejected(tmp_path):
    store = SQLiteNonceStore(tmp_path / "ledger.sqlite3")
    now = _now()
    store.check_and_record("producer:a", "n1", now, MAX_SKEW, route_id="/v1/attest/authenticated")
    with pytest.raises(ReplayedNonceError):
        store.check_and_record("producer:a", "n1", now, MAX_SKEW, route_id="/v1/attest/other-route")


def test_cross_subject_reuse_of_same_producer_nonce_rejected(tmp_path):
    store = SQLiteNonceStore(tmp_path / "ledger.sqlite3")
    now = _now()
    store.check_and_record("producer:a", "n1", now, MAX_SKEW, subject_agent_id="agent:x")
    with pytest.raises(ReplayedNonceError):
        store.check_and_record("producer:a", "n1", now, MAX_SKEW, subject_agent_id="agent:y")


def test_changed_payload_same_nonce_rejected(tmp_path):
    store = SQLiteNonceStore(tmp_path / "ledger.sqlite3")
    now = _now()
    store.check_and_record("producer:a", "n1", now, MAX_SKEW, envelope_digest_hex="aaaa")
    with pytest.raises(ReplayedNonceError):
        store.check_and_record("producer:a", "n1", now, MAX_SKEW, envelope_digest_hex="bbbb")


def test_exact_duplicate_resubmission_is_deterministic_replay_failure(tmp_path):
    # Idempotency policy: an exact duplicate is a replay failure, not a
    # cached-success return -- matches the pre-existing in-memory NonceStore
    # contract (test_duplicate_submission_same_nonce_rejected_even_if_identical
    # in test_authenticated_submission_envelope.py).
    store = SQLiteNonceStore(tmp_path / "ledger.sqlite3")
    now = _now()
    kwargs = dict(route_id="/v1/attest/authenticated", subject_agent_id="agent:x", envelope_digest_hex="aaaa")
    store.check_and_record("producer:a", "n1", now, MAX_SKEW, **kwargs)
    with pytest.raises(ReplayedNonceError):
        store.check_and_record("producer:a", "n1", now, MAX_SKEW, **kwargs)


def test_concurrent_duplicate_claims_exactly_one_wins(tmp_path):
    store = SQLiteNonceStore(tmp_path / "ledger.sqlite3")
    now = _now()
    results = []
    barrier = threading.Barrier(8)

    def attempt():
        barrier.wait()
        try:
            store.check_and_record("producer:a", "contended-nonce", now, MAX_SKEW)
            results.append("accepted")
        except ReplayedNonceError:
            results.append("rejected")
        except Exception as exc:  # pragma: no cover - diagnostic aid on failure
            results.append(f"error:{exc}")

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count("accepted") == 1, results
    assert results.count("rejected") == 7, results


def test_expired_assertion_can_still_be_claimed_by_verifier_but_ledger_itself_has_no_opinion_on_age(tmp_path):
    # Age/timestamp-window rejection is verify_authenticated_submission's
    # job (TimestampWindowError), not the ledger's -- the ledger only knows
    # replay identity. This test documents that boundary: the ledger will
    # happily record a claim for an old timestamp if asked to (the caller
    # is responsible for having already rejected it on age grounds).
    store = SQLiteNonceStore(tmp_path / "ledger.sqlite3")
    old = _now() - timedelta(days=1)  # already past the 4*max_skew retention window
    store.check_and_record("producer:a", "n1", old, MAX_SKEW)  # must not raise
    # Because this entry's own retention window has already elapsed, the
    # opportunistic per-claim cleanup sweeps it before the second claim's
    # INSERT runs, so the second claim also succeeds -- an already-expired
    # entry provides no replay protection past its own retention, by
    # design (retention == the outer bound on how long a replay claim is
    # honored at all). A verifier must reject the assertion on age
    # (TimestampWindowError) well before this ever matters in practice.
    store.check_and_record("producer:a", "n1", old, MAX_SKEW)  # must not raise either


def test_cleanup_does_not_remove_still_replayable_entries(tmp_path):
    store = SQLiteNonceStore(tmp_path / "ledger.sqlite3")
    now = _now()
    store.check_and_record("producer:a", "fresh-nonce", now, MAX_SKEW)
    deleted = store.cleanup(now=now)
    assert deleted == 0
    with pytest.raises(ReplayedNonceError):
        store.check_and_record("producer:a", "fresh-nonce", now, MAX_SKEW)


def test_cleanup_removes_entries_past_retention_window(tmp_path):
    store = SQLiteNonceStore(tmp_path / "ledger.sqlite3")
    old = _now() - timedelta(days=2)  # well past 4 * max_skew (20 min) retention
    store.check_and_record("producer:a", "old-nonce", old, MAX_SKEW)
    deleted = store.cleanup(now=_now())
    assert deleted == 1
    # nonce is no longer tracked -- a resubmission with the same (producer,
    # nonce) now succeeds because it fell out of the retention window. This
    # is expected/inherent to any retention-bounded replay store: the
    # signed timestamp itself is already outside the timestamp-window check
    # any verifier would apply long before retention expiry is relevant.
    store.check_and_record("producer:a", "old-nonce", old, MAX_SKEW)


def test_retention_window_derived_from_max_skew(tmp_path):
    from replay_ledger import RETENTION_SKEW_MULTIPLE

    store = SQLiteNonceStore(tmp_path / "ledger.sqlite3")
    now = _now()
    just_inside = now - (MAX_SKEW * RETENTION_SKEW_MULTIPLE) + timedelta(seconds=5)
    just_outside = now - (MAX_SKEW * RETENTION_SKEW_MULTIPLE) - timedelta(seconds=5)

    store.check_and_record("producer:a", "inside", just_inside, MAX_SKEW)
    store.check_and_record("producer:a", "outside", just_outside, MAX_SKEW)

    deleted = store.cleanup(now=now)
    assert deleted == 1  # only the entry past retention is removed

    with pytest.raises(ReplayedNonceError):
        store.check_and_record("producer:a", "inside", just_inside, MAX_SKEW)
    store.check_and_record("producer:a", "outside", just_outside, MAX_SKEW)  # no longer tracked, succeeds


def test_ledger_unavailable_fails_closed_on_init(tmp_path):
    # Point the "directory" at a path that is actually a file, so SQLite
    # cannot create the database there -- this must raise
    # NonceStoreUnavailableError, never silently fall back to anything.
    blocking_file = tmp_path / "not_a_directory"
    blocking_file.write_text("x")
    bad_path = blocking_file / "ledger.sqlite3"
    with pytest.raises(NonceStoreUnavailableError):
        SQLiteNonceStore(bad_path)


def test_ledger_unavailable_fails_closed_on_claim(tmp_path, monkeypatch):
    store = SQLiteNonceStore(tmp_path / "ledger.sqlite3")

    def _boom(self):
        raise sqlite3.OperationalError("disk I/O error (simulated)")

    monkeypatch.setattr(SQLiteNonceStore, "_connect", _boom)
    with pytest.raises(NonceStoreUnavailableError):
        store.check_and_record("producer:a", "n1", _now(), MAX_SKEW)


def test_db_file_created_with_owner_only_permissions(tmp_path):
    db_path = tmp_path / "ledger.sqlite3"
    SQLiteNonceStore(db_path)
    mode = oct(os.stat(db_path).st_mode & 0o777)
    assert mode == oct(0o600)


def test_wal_and_shm_sidecars_get_owner_only_permissions_after_write(tmp_path):
    db_path = tmp_path / "ledger.sqlite3"
    store = SQLiteNonceStore(db_path)
    store.check_and_record("producer:a", "n1", _now(), MAX_SKEW)
    for suffix in ("-wal", "-shm"):
        sidecar = db_path.with_name(db_path.name + suffix)
        if sidecar.exists():
            assert oct(os.stat(sidecar).st_mode & 0o777) == oct(0o600)


def test_no_default_path_touched_by_import():
    # Importing authenticated_submission_api must never create the
    # production ledger file merely as a side effect of import (tests and
    # other tooling import it freely).
    import authenticated_submission_api as api

    assert api._nonce_store is None or isinstance(api._nonce_store, SQLiteNonceStore)
    assert not api._default_nonce_ledger_path.exists()
