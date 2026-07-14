"""ds.authenticated_submission replay ledger -- durable nonce store (Phase C
follow-up).

`authenticated_submission.NonceStore` (in-memory) is correct for tests and
for verifying the acceptance pipeline in isolation, but its own docstring
already says a persisted variant is required before any live deployment:
a process restart empties it, reopening the replay window for any envelope
whose signed `timestamp` is still inside the acceptance window at the
moment of restart. `attest-service.service` sets `Restart=always`, so this
is not hypothetical.

`SQLiteNonceStore` is a swap-in replacement implementing the exact same
`check_and_record(producer_id, nonce, timestamp, max_skew, ...)` interface,
backed by a single-file SQLite database so the replay record survives
process restart, crash, or redeploy.

Design choices (see readiness packet for the full writeup):

- Uniqueness / atomic claim: a UNIQUE constraint on (producer_id, nonce),
  claimed via a single `INSERT` inside an immediate-mode transaction. SQLite
  serializes writers at the file level, so two concurrent claims for the
  same (producer_id, nonce) cannot both succeed -- the loser's INSERT
  raises `sqlite3.IntegrityError`, mapped to `ReplayedNonceError`.
- Idempotency policy: exact-duplicate resubmission (same producer_id,
  nonce, and everything else identical) is treated as a **replay failure**,
  not a cached-success return. This matches the pre-existing in-memory
  `NonceStore` contract and the existing regression test
  `test_duplicate_submission_same_nonce_rejected_even_if_identical` in
  `tests/test_authenticated_submission_envelope.py` -- changing that
  contract here would be a silent behavior change to an already-reviewed
  security property, not a persistence upgrade. A resubmission must use a
  fresh nonce, full stop.
- Binding: `route_id`, `subject_agent_id`, and `envelope_digest_hex` are
  recorded alongside the identity key for audit/forensic purposes (so a
  reviewer can see exactly what a given (producer_id, nonce) pair was
  claimed for). They do not widen the replay-identity key -- the key
  remains (producer_id, nonce), which is what `verify_authenticated_
  submission` already scopes nonces to per-producer. A different
  route/subject/digest under the same (producer_id, nonce) is still
  rejected as a replay (not silently accepted as "different enough"),
  which is the conservative, fail-closed choice: nonce reuse is nonce
  reuse regardless of what else changed in the payload.
- Retention: mechanically derived, not a magic number. The verifier only
  ever accepts a `timestamp` within `max_skew` of `now` (past or future),
  so the maximum possible age of an accepted assertion at the moment it is
  recorded is `max_skew`. Add another `max_skew` for downstream clock skew
  tolerance during the retention check itself, then double the whole thing
  as an explicit safety margin against clock jitter/NTP drift across a
  restart -- i.e. `retention = 4 * max_skew`, matching the multiplier the
  original in-memory `NonceStore._prune` already used, so behavior is
  unchanged, only durability is added. Cleanup never deletes a row whose
  `assertion_timestamp` is still within `retention` of `now`, so it cannot
  remove a still-replayable entry.
- Fail closed: any `sqlite3.Error` (disk full, locked beyond busy_timeout,
  corrupt file, permission denied) is caught and re-raised as
  `NonceStoreUnavailableError`, a subclass of `AuthenticatedSubmissionError`.
  It is never swallowed and there is no in-memory fallback path -- an
  unavailable ledger means the submission is rejected (401 at the API
  layer), not silently accepted.
- Permissions: the database file is created (if absent) and then chmod'd to
  0o600 before any data is written. No production credential is stored in
  this database -- only nonce/replay bookkeeping -- but it is still
  restricted to the owning account as a matter of course.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Kept identical to the original in-memory NonceStore._prune multiplier so
# persisting the store does not change retention behavior, only durability.
RETENTION_SKEW_MULTIPLE = 4

_SCHEMA = """
CREATE TABLE IF NOT EXISTS nonce_ledger (
    producer_id           TEXT NOT NULL,
    nonce                 TEXT NOT NULL,
    request_id            TEXT,
    route_id              TEXT,
    subject_agent_id      TEXT,
    envelope_digest_hex   TEXT,
    assertion_timestamp   TEXT NOT NULL,  -- ISO-8601, the envelope's signed `timestamp`
    accepted_at           TEXT NOT NULL,  -- ISO-8601, wall-clock time of this claim
    expiry_at             TEXT NOT NULL,  -- ISO-8601, assertion_timestamp + retention
    result_state          TEXT NOT NULL DEFAULT 'accepted',
    PRIMARY KEY (producer_id, nonce)
);
CREATE INDEX IF NOT EXISTS idx_nonce_ledger_expiry ON nonce_ledger (expiry_at);
"""


# NonceStoreUnavailableError is defined in authenticated_submission.py (as a
# subclass of AuthenticatedSubmissionError, so existing call sites that only
# catch that base class still reject-closed unchanged) and imported here
# lazily, matching the ReplayedNonceError pattern below, to avoid a circular
# import at module load time (authenticated_submission imports this module).


class SQLiteNonceStore:
    """Durable, restart-surviving, swap-in replacement for the in-memory
    NonceStore. One physical SQLite file per store instance; safe for
    concurrent use from multiple threads within one process (a fresh
    connection is opened per operation; SQLite serializes writers at the
    file level via its own locking, backstopped here by a process-local
    lock so concurrent threads in this same process don't even contend on
    SQLite's busy-timeout path under normal load)."""

    def __init__(self, db_path: str | Path, *, busy_timeout_ms: int = 5000) -> None:
        self.db_path = Path(db_path)
        self._busy_timeout_ms = busy_timeout_ms
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=self._busy_timeout_ms / 1000.0, isolation_level=None)
        conn.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = OFF")
        return conn

    def _secure_permissions(self) -> None:
        """Restrict the main db file and its WAL/SHM sidecars to the owning
        account, regardless of umask. WAL mode creates `-wal`/`-shm` files
        lazily on first read/write, not necessarily at connect time, so
        this is called after every operation that may have created or
        touched them -- not just once at __init__ -- otherwise a sidecar
        created later than the very first connection would be left at
        whatever the process umask happens to produce."""
        try:
            if self.db_path.exists():
                os.chmod(self.db_path, 0o600)
            for suffix in ("-wal", "-shm"):
                sidecar = self.db_path.with_name(self.db_path.name + suffix)
                if sidecar.exists():
                    os.chmod(sidecar, 0o600)
        except OSError:
            # Best-effort: a permission tightening failure here does not
            # itself weaken anything already-secured, and the caller's own
            # operation (init/claim/cleanup) still ran its real work under
            # its own try/except with fail-closed semantics.
            pass

    def _init_db(self) -> None:
        from authenticated_submission import NonceStoreUnavailableError  # local import: avoids circular import

        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = self._connect()
            try:
                conn.executescript(_SCHEMA)
            finally:
                conn.close()
        except OSError as exc:
            raise NonceStoreUnavailableError(f"could not initialize replay ledger at {self.db_path}: {exc}") from exc
        except sqlite3.Error as exc:
            raise NonceStoreUnavailableError(f"could not initialize replay ledger at {self.db_path}: {exc}") from exc
        self._secure_permissions()

    def check_and_record(
        self,
        producer_id: str,
        nonce: str,
        timestamp: datetime,
        max_skew: timedelta,
        *,
        request_id: str | None = None,
        route_id: str | None = None,
        subject_agent_id: str | None = None,
        envelope_digest_hex: str | None = None,
    ) -> None:
        """Atomically claim (producer_id, nonce). Raises ReplayedNonceError
        (imported lazily to avoid a circular import) if already claimed,
        NonceStoreUnavailableError if the ledger cannot commit."""
        # local imports: avoid a circular import at module load time (authenticated_submission imports this module)
        from authenticated_submission import NonceStoreUnavailableError, ReplayedNonceError

        retention = max_skew * RETENTION_SKEW_MULTIPLE
        now = datetime.now(timezone.utc)
        accepted_at = now.isoformat()
        expiry_at = (timestamp + retention).isoformat()

        with self._lock:
            try:
                conn = self._connect()
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    # Opportunistic cleanup of rows that can no longer be
                    # replayed against, in the same transaction as the
                    # claim so it is atomic with respect to concurrent
                    # writers and never races a still-valid row's deletion
                    # against its own replay check.
                    conn.execute("DELETE FROM nonce_ledger WHERE expiry_at < ?", (now.isoformat(),))
                    try:
                        conn.execute(
                            """
                            INSERT INTO nonce_ledger
                                (producer_id, nonce, request_id, route_id, subject_agent_id,
                                 envelope_digest_hex, assertion_timestamp, accepted_at, expiry_at, result_state)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'accepted')
                            """,
                            (
                                producer_id,
                                nonce,
                                request_id,
                                route_id,
                                subject_agent_id,
                                envelope_digest_hex,
                                timestamp.isoformat(),
                                accepted_at,
                                expiry_at,
                            ),
                        )
                    except sqlite3.IntegrityError:
                        conn.execute("ROLLBACK")
                        raise ReplayedNonceError(f"nonce {nonce!r} already used by producer {producer_id!r}")
                    conn.execute("COMMIT")
                finally:
                    conn.close()
            except sqlite3.Error as exc:
                raise NonceStoreUnavailableError(
                    f"replay ledger unavailable/could not commit atomic claim: {exc}"
                ) from exc
        self._secure_permissions()

    def cleanup(self, now: datetime | None = None) -> int:
        """Explicit, on-demand cleanup entry point (in addition to the
        opportunistic per-claim cleanup above). Returns the number of rows
        deleted. Only ever deletes rows whose expiry_at has passed -- never
        a row that could still be a valid replay target."""
        from authenticated_submission import NonceStoreUnavailableError  # local import: avoids circular import

        now = now or datetime.now(timezone.utc)
        with self._lock:
            try:
                conn = self._connect()
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    cur = conn.execute("DELETE FROM nonce_ledger WHERE expiry_at < ?", (now.isoformat(),))
                    deleted = cur.rowcount
                    conn.execute("COMMIT")
                finally:
                    conn.close()
            except sqlite3.Error as exc:
                raise NonceStoreUnavailableError(f"replay ledger unavailable during cleanup: {exc}") from exc
        self._secure_permissions()
        return deleted

    def close(self) -> None:
        """No persistent connection is held open between calls, so this is
        a no-op provided for symmetry/interface parity with store types
        that do hold one open."""
        return None
