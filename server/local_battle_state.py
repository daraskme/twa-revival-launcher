"""Durable, idempotent lifecycle storage for local Arena battles.

The HTTP stack and native relay run independently, so battle completion must
not live only in either process' memory.  This module deliberately contains no
HTTP or native-wire code.  It stores the small server-owned lifecycle and the
validated final result payloads in SQLite, where each mutation is atomic.

The lifecycle is monotonic::

    allocated -> enrolled -> ticking -> result_reported -> result_ready
              -> settled -> delivered

Final-event retries and settlement retries are accepted only when their
canonical content is identical.  A changed retry raises ``BattleStateError``;
this prevents a client from replacing a result or receiving a second reward.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path


PHASES = (
    "allocated",
    "enrolled",
    "ticking",
    "result_reported",
    "result_ready",
    "settled",
    "delivered",
)
PHASE_INDEX = {phase: index for index, phase in enumerate(PHASES)}
MAX_IDENTIFIER_BYTES = 128
MAX_CONTEXT_BYTES = 64 * 1024
MAX_FINAL_EVENT_BYTES = 2 * 1024 * 1024
MAX_RESULTS_BYTES = 2 * 1024 * 1024
MAX_SETTLEMENT_BYTES = 256 * 1024
DEFAULT_BATTLE_STATE_PATH = Path(__file__).with_name("local_battle_state.sqlite3")


class BattleStateError(ValueError):
    """A stable error code suitable for a local HTTP error response."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _identifier(value: object, name: str) -> str:
    if type(value) is not str or not value:
        raise BattleStateError(f"invalid_{name}")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise BattleStateError(f"invalid_{name}") from None
    if len(encoded) > MAX_IDENTIFIER_BYTES:
        raise BattleStateError(f"invalid_{name}")
    if any(ord(char) < 0x20 for char in value):
        raise BattleStateError(f"invalid_{name}")
    return value


def _canonical(value: object, *, maximum: int, kind: str) -> tuple[str, str]:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise BattleStateError(f"invalid_{kind}") from None
    raw = encoded.encode("utf-8")
    if len(raw) > maximum:
        raise BattleStateError(f"{kind}_too_large")
    return encoded, hashlib.sha256(raw).hexdigest()


def _decoded(encoded: str):
    # Values only enter the database through _canonical.  Deep-copy semantics
    # come for free and callers cannot mutate the persisted value in memory.
    return json.loads(encoded)


def _battle_key_digest(value: object) -> str:
    if type(value) is int:
        number = value
    elif type(value) is str and value.isascii() and value.isdigit():
        number = int(value)
        if value != str(number):
            raise BattleStateError("invalid_battle_key")
    else:
        raise BattleStateError("invalid_battle_key")
    if not 1 <= number < 2**64:
        raise BattleStateError("invalid_battle_key")
    return hashlib.sha256(str(number).encode("ascii")).hexdigest()


class LocalBattleState:
    """Thread-safe SQLite store shared by the local HTTP and relay processes.

    ``path`` may be ``":memory:"`` for tests.  A file-backed instance creates
    its parent directory and uses WAL mode, allowing the HTTP and relay
    processes to open the same file concurrently.
    """

    def __init__(self, path: str | Path, *, clock_ms: Callable[[], int] | None = None):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.path,
            timeout=10,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 10000")
        if self.path != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
        self._create_schema()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "LocalBattleState":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def _create_schema(self) -> None:
        # sqlite3.executescript controls its own transaction boundary.  Keep
        # the in-process lock, while SQLite serializes concurrent initializers.
        with self._lock:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS battles (
                    battle_id TEXT PRIMARY KEY,
                    phase TEXT NOT NULL CHECK (phase IN (
                        'allocated','enrolled','ticking','result_reported',
                        'result_ready','settled','delivered'
                    )),
                    users_json TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    context_digest TEXT NOT NULL,
                    results_json TEXT,
                    results_digest TEXT,
                    created_ms INTEGER NOT NULL,
                    updated_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS enrollments (
                    battle_id TEXT NOT NULL REFERENCES battles(battle_id) ON DELETE CASCADE,
                    user_id TEXT NOT NULL,
                    enrolled_ms INTEGER NOT NULL,
                    PRIMARY KEY (battle_id, user_id)
                );
                CREATE TABLE IF NOT EXISTS battle_credentials (
                    battle_id TEXT PRIMARY KEY REFERENCES battles(battle_id) ON DELETE CASCADE,
                    key_digest TEXT NOT NULL,
                    expected_players INTEGER NOT NULL CHECK (expected_players BETWEEN 1 AND 20)
                );
                CREATE TABLE IF NOT EXISTS final_events (
                    battle_id TEXT NOT NULL REFERENCES battles(battle_id) ON DELETE CASCADE,
                    user_id TEXT NOT NULL,
                    seq_id INTEGER NOT NULL,
                    event_json TEXT NOT NULL,
                    event_digest TEXT NOT NULL,
                    reported_ms INTEGER NOT NULL,
                    PRIMARY KEY (battle_id, user_id)
                );
                CREATE TABLE IF NOT EXISTS settlements (
                    battle_id TEXT NOT NULL REFERENCES battles(battle_id) ON DELETE CASCADE,
                    user_id TEXT NOT NULL,
                    settlement_json TEXT NOT NULL,
                    settlement_digest TEXT NOT NULL,
                    settled_ms INTEGER NOT NULL,
                    PRIMARY KEY (battle_id, user_id)
                );
                CREATE TABLE IF NOT EXISTS deliveries (
                    battle_id TEXT NOT NULL REFERENCES battles(battle_id) ON DELETE CASCADE,
                    user_id TEXT NOT NULL,
                    delivered_ms INTEGER NOT NULL,
                    PRIMARY KEY (battle_id, user_id)
                );
                CREATE TABLE IF NOT EXISTS battle_wire_aliases (
                    wire_battle_id TEXT PRIMARY KEY,
                    battle_id TEXT NOT NULL REFERENCES battles(battle_id),
                    updated_ms INTEGER NOT NULL
                );
                """
            )

    class _Transaction:
        def __init__(self, owner: "LocalBattleState"):
            self.owner = owner

        def __enter__(self):
            self.owner._lock.acquire()
            try:
                self.owner._connection.execute("BEGIN IMMEDIATE")
            except BaseException:
                self.owner._lock.release()
                raise

        def __exit__(self, exc_type, _exc, _tb):
            try:
                self.owner._connection.execute("ROLLBACK" if exc_type else "COMMIT")
            finally:
                self.owner._lock.release()

    def _transaction(self) -> "LocalBattleState._Transaction":
        return self._Transaction(self)

    def _battle(self, battle_id: str) -> sqlite3.Row:
        row = self._connection.execute(
            "SELECT * FROM battles WHERE battle_id = ?", (battle_id,)
        ).fetchone()
        if row is None:
            raise BattleStateError("battle_not_found")
        return row

    @staticmethod
    def _users(row: sqlite3.Row) -> list[str]:
        return json.loads(row["users_json"])

    @staticmethod
    def _require_user(row: sqlite3.Row, user_id: str) -> None:
        if user_id not in LocalBattleState._users(row):
            raise BattleStateError("user_not_in_battle")

    def _set_phase(self, battle_id: str, phase: str) -> None:
        self._connection.execute(
            "UPDATE battles SET phase = ?, updated_ms = ? WHERE battle_id = ?",
            (phase, self._clock_ms(), battle_id),
        )

    def bind_wire_battle_id(self, wire_battle_id: object,
                            battle_id: object) -> str:
        """Atomically publish the current room UUID -> battle UUID alias.

        The connection and relay processes share this table. A private room can
        therefore keep its native wire UUID while each rematch retains a unique
        immutable row in ``battles``. Public battles need no alias.
        """
        wire = _identifier(wire_battle_id, "wire_battle_id")
        internal = _identifier(battle_id, "battle_id")
        with self._transaction():
            self._battle(internal)
            self._connection.execute(
                """INSERT INTO battle_wire_aliases(wire_battle_id,battle_id,updated_ms)
                   VALUES(?,?,?)
                   ON CONFLICT(wire_battle_id) DO UPDATE SET
                       battle_id=excluded.battle_id, updated_ms=excluded.updated_ms""",
                (wire, internal, self._clock_ms()),
            )
        return internal

    def resolve_wire_battle_id(self, wire_battle_id: object) -> str:
        """Resolve a private alias, falling back to the unchanged public ID."""
        wire = _identifier(wire_battle_id, "wire_battle_id")
        with self._lock:
            row = self._connection.execute(
                "SELECT battle_id FROM battle_wire_aliases WHERE wire_battle_id=?",
                (wire,),
            ).fetchone()
            internal = wire if row is None else row["battle_id"]
            self._battle(internal)
            return internal

    def allocate(
        self,
        battle_id: str,
        user_ids: Sequence[str],
        context: dict | None = None,
        *,
        battle_key: str | int | None = None,
        expected_players: int | None = None,
    ) -> tuple[dict, bool]:
        """Create an immutable roster/context; identical allocation is a retry.

        Returns ``(snapshot, created)``.
        """
        battle_id = _identifier(battle_id, "battle_id")
        if isinstance(user_ids, (str, bytes)) or not isinstance(user_ids, Sequence):
            raise BattleStateError("invalid_user_ids")
        users = [_identifier(value, "user_id") for value in user_ids]
        if not users or len(set(users)) != len(users):
            raise BattleStateError("invalid_user_ids")
        context = {} if context is None else context
        if not isinstance(context, dict):
            raise BattleStateError("invalid_context")
        users_json, _ = _canonical(users, maximum=MAX_CONTEXT_BYTES, kind="user_ids")
        context_json, context_digest = _canonical(
            context, maximum=MAX_CONTEXT_BYTES, kind="context"
        )
        if (battle_key is None) != (expected_players is None):
            raise BattleStateError("invalid_battle_credentials")
        key_digest = None
        if battle_key is not None:
            key_digest = _battle_key_digest(battle_key)
            if type(expected_players) is not int or not 1 <= expected_players <= 20:
                raise BattleStateError("invalid_expected_players")
        created = False
        with self._transaction():
            existing = self._connection.execute(
                "SELECT users_json, context_digest FROM battles WHERE battle_id = ?",
                (battle_id,),
            ).fetchone()
            if existing is None:
                now = self._clock_ms()
                self._connection.execute(
                    """INSERT INTO battles
                       (battle_id,phase,users_json,context_json,context_digest,created_ms,updated_ms)
                       VALUES (?, 'allocated', ?, ?, ?, ?, ?)""",
                    (battle_id, users_json, context_json, context_digest, now, now),
                )
                if key_digest is not None:
                    self._connection.execute(
                        "INSERT INTO battle_credentials VALUES (?, ?, ?)",
                        (battle_id, key_digest, expected_players),
                    )
                created = True
            elif existing["users_json"] != users_json or existing["context_digest"] != context_digest:
                raise BattleStateError("allocation_conflict")
            else:
                credential = self._connection.execute(
                    "SELECT key_digest,expected_players FROM battle_credentials WHERE battle_id=?",
                    (battle_id,),
                ).fetchone()
                if ((credential is None) != (key_digest is None)
                        or credential is not None and (
                            not hmac.compare_digest(credential["key_digest"], key_digest)
                            or credential["expected_players"] != expected_players)):
                    raise BattleStateError("allocation_conflict")
        return self.snapshot(battle_id), created

    def validate_relay_join(
        self,
        battle_id: str,
        battle_key: str | int,
        user_id: str,
        expected_players: int,
    ) -> dict:
        """Verify native GAME_JOIN credentials without returning the key."""
        battle_id = _identifier(battle_id, "battle_id")
        user_id = _identifier(user_id, "user_id")
        digest = _battle_key_digest(battle_key)
        if type(expected_players) is not int or not 1 <= expected_players <= 20:
            raise BattleStateError("invalid_expected_players")
        with self._lock:
            battle = self._battle(battle_id)
            self._require_user(battle, user_id)
            if battle["phase"] not in {"enrolled", "ticking"}:
                raise BattleStateError("battle_not_joinable")
            credential = self._connection.execute(
                "SELECT key_digest,expected_players FROM battle_credentials WHERE battle_id=?",
                (battle_id,),
            ).fetchone()
            if credential is None:
                raise BattleStateError("battle_credentials_missing")
            if not hmac.compare_digest(credential["key_digest"], digest):
                raise BattleStateError("battle_key_mismatch")
            if credential["expected_players"] != expected_players:
                raise BattleStateError("battle_roster_mismatch")
            return {
                "battle_id": battle_id,
                "user_id": user_id,
                "expected_players": expected_players,
                "phase": battle["phase"],
            }

    def validate_final_credential(
        self,
        battle_id: str,
        battle_key: str | int,
        user_id: str,
    ) -> dict:
        """Verify a final HTTP report without exposing the stored credential.

        Unlike GAME_JOIN validation, a same-content HTTP retry can arrive in a
        result phase. Credential retirement still fails closed; the caller may
        separately allow only an already-persisted exact event retry.
        """
        battle_id = _identifier(battle_id, "battle_id")
        user_id = _identifier(user_id, "user_id")
        digest = _battle_key_digest(battle_key)
        with self._lock:
            battle = self._battle(battle_id)
            self._require_user(battle, user_id)
            if PHASE_INDEX[battle["phase"]] < PHASE_INDEX["ticking"]:
                raise BattleStateError("battle_not_ticking")
            credential = self._connection.execute(
                "SELECT key_digest FROM battle_credentials WHERE battle_id=?",
                (battle_id,),
            ).fetchone()
            if credential is None:
                raise BattleStateError("battle_credentials_missing")
            if not hmac.compare_digest(credential["key_digest"], digest):
                raise BattleStateError("battle_key_mismatch")
            return {
                "battle_id": battle_id,
                "user_id": user_id,
                "phase": battle["phase"],
            }

    def retire_relay_join(self, battle_id: str) -> bool:
        """Permanently retire one battle's relay credential.

        A retained transport may reconnect while its credential exists.  Once
        that transport has completed or its resume window expires, deleting
        the credential makes an old GAME_JOIN fail closed, including after a
        relay-process restart.  Result delivery and economy settlement do not
        depend on this credential.
        """
        battle_id = _identifier(battle_id, "battle_id")
        with self._transaction():
            self._battle(battle_id)
            cursor = self._connection.execute(
                "DELETE FROM battle_credentials WHERE battle_id=?", (battle_id,)
            )
        return cursor.rowcount == 1

    def active_battle_for_user(self, user_id: str) -> str:
        """Resolve the sole active battle when a native final event omits ID."""
        user_id = _identifier(user_id, "user_id")
        with self._lock:
            rows = self._connection.execute(
                "SELECT battle_id,phase,users_json FROM battles "
                "WHERE phase IN ('ticking','result_reported','result_ready','settled') "
                "ORDER BY updated_ms DESC"
            ).fetchall()
            matches = [row["battle_id"] for row in rows if user_id in self._users(row)]
            if not matches:
                raise BattleStateError("active_battle_not_found")
            if len(matches) != 1:
                raise BattleStateError("active_battle_ambiguous")
            return matches[0]

    def has_pending_settlement(self, user_id: str, *, mode: str | None = None) -> bool:
        """Return whether one settled, undelivered result belongs to a user.

        This is a read-only protocol hint.  It lets the HTTP layer distinguish
        a post-battle profile read from an ordinary hangar profile read. Public
        battles consume it before ``GET /battle_results``; private battles may
        instead consume their battle-local performance panel before returning
        to the retained room. The authoritative result and settlement remain
        in their existing tables; no profile or economy state is changed by
        this query.
        """
        user_id = _identifier(user_id, "user_id")
        if mode is not None:
            mode = _identifier(mode, "mode")
        with self._lock:
            rows = self._connection.execute(
                "SELECT b.users_json,b.context_json FROM battles AS b "
                "WHERE b.phase='settled' AND NOT EXISTS ("
                "SELECT 1 FROM deliveries AS d "
                "WHERE d.battle_id=b.battle_id AND d.user_id=?"
                ") ORDER BY b.updated_ms DESC",
                (user_id,),
            ).fetchall()
            for row in rows:
                if user_id not in self._users(row):
                    continue
                context = _decoded(row["context_json"])
                if mode is None or context.get("mode") == mode:
                    return True
            return False

    def battle_for_user_party(self, user_id: object, party_id: object, *,
                              battle_id: object = None) -> str:
        """Bind the reported party to the enrolled user's frozen battle.

        Older allocations used the battle ID as their party ID. New ones
        supply the explicit battle ID and retain a separate native party.
        The caller also verifies the frozen relay credential.
        """
        user_id = _identifier(user_id, "user_id")
        # Empty means a solo seat, never a battle lookup key. Resolve it only
        # through the authenticated caller's explicit frozen battle.
        if party_id != "" or battle_id is None:
            party_id = _identifier(party_id, "party_id")
        with self._lock:
            resolved = party_id if battle_id is None else _identifier(battle_id, "battle_id")
            battle = self._battle(resolved)
            self._require_user(battle, user_id)
            context = _decoded(battle["context_json"])
            if context.get("party_id") != party_id:
                raise BattleStateError("battle_party_mismatch")
            return resolved

    def enroll(self, battle_id: str, user_id: str) -> tuple[dict, bool]:
        """Enroll one roster member and enter ``enrolled`` once all have joined."""
        battle_id = _identifier(battle_id, "battle_id")
        user_id = _identifier(user_id, "user_id")
        created = False
        with self._transaction():
            battle = self._battle(battle_id)
            self._require_user(battle, user_id)
            if PHASE_INDEX[battle["phase"]] > PHASE_INDEX["enrolled"]:
                # A delayed duplicate enrollment is harmless.
                exists = self._connection.execute(
                    "SELECT 1 FROM enrollments WHERE battle_id=? AND user_id=?",
                    (battle_id, user_id),
                ).fetchone()
                if exists is None:
                    raise BattleStateError("enrollment_after_start")
            cursor = self._connection.execute(
                "INSERT OR IGNORE INTO enrollments VALUES (?, ?, ?)",
                (battle_id, user_id, self._clock_ms()),
            )
            created = cursor.rowcount == 1
            enrolled = self._connection.execute(
                "SELECT COUNT(*) FROM enrollments WHERE battle_id=?", (battle_id,)
            ).fetchone()[0]
            if battle["phase"] == "allocated" and enrolled == len(self._users(battle)):
                self._set_phase(battle_id, "enrolled")
        return self.snapshot(battle_id), created

    def start_ticking(self, battle_id: str) -> dict:
        battle_id = _identifier(battle_id, "battle_id")
        with self._transaction():
            battle = self._battle(battle_id)
            phase = battle["phase"]
            if phase == "enrolled":
                self._set_phase(battle_id, "ticking")
            elif phase == "allocated":
                raise BattleStateError("battle_not_enrolled")
            elif PHASE_INDEX[phase] < PHASE_INDEX["ticking"]:
                raise BattleStateError("invalid_phase")
            # Later calls are idempotent observations of an already-started battle.
        return self.snapshot(battle_id)

    def report_final_event(
        self,
        battle_id: str,
        user_id: str,
        seq_id: int,
        event: dict,
    ) -> tuple[dict, bool]:
        """Persist one final client event; only an identical retry is accepted."""
        battle_id = _identifier(battle_id, "battle_id")
        user_id = _identifier(user_id, "user_id")
        if type(seq_id) is not int or not 0 <= seq_id < 2**63:
            raise BattleStateError("invalid_seq_id")
        if not isinstance(event, dict):
            raise BattleStateError("invalid_final_event")
        event_json, digest = _canonical(
            event, maximum=MAX_FINAL_EVENT_BYTES, kind="final_event"
        )
        created = False
        with self._transaction():
            battle = self._battle(battle_id)
            self._require_user(battle, user_id)
            if PHASE_INDEX[battle["phase"]] < PHASE_INDEX["ticking"]:
                raise BattleStateError("battle_not_ticking")
            existing = self._connection.execute(
                "SELECT seq_id,event_digest FROM final_events WHERE battle_id=? AND user_id=?",
                (battle_id, user_id),
            ).fetchone()
            if existing is None:
                self._connection.execute(
                    "INSERT INTO final_events VALUES (?, ?, ?, ?, ?, ?)",
                    (battle_id, user_id, seq_id, event_json, digest, self._clock_ms()),
                )
                created = True
                if battle["phase"] == "ticking":
                    self._set_phase(battle_id, "result_reported")
            elif existing["seq_id"] != seq_id or existing["event_digest"] != digest:
                raise BattleStateError("final_event_conflict")
        return _decoded(event_json), created

    def final_event(self, battle_id: str, user_id: str) -> dict | None:
        battle_id = _identifier(battle_id, "battle_id")
        user_id = _identifier(user_id, "user_id")
        with self._lock:
            battle = self._battle(battle_id)
            self._require_user(battle, user_id)
            row = self._connection.execute(
                "SELECT event_json FROM final_events WHERE battle_id=? AND user_id=?",
                (battle_id, user_id),
            ).fetchone()
            return None if row is None else _decoded(row["event_json"])

    def publish_results(self, battle_id: str, results: list) -> tuple[list, bool]:
        """Make the canonical raw JSON array available to battle-results GET."""
        battle_id = _identifier(battle_id, "battle_id")
        if not isinstance(results, list):
            raise BattleStateError("invalid_results")
        results_json, digest = _canonical(
            results, maximum=MAX_RESULTS_BYTES, kind="results"
        )
        created = False
        with self._transaction():
            battle = self._battle(battle_id)
            if PHASE_INDEX[battle["phase"]] < PHASE_INDEX["result_reported"]:
                raise BattleStateError("result_not_reported")
            if battle["results_json"] is None:
                self._connection.execute(
                    """UPDATE battles SET results_json=?, results_digest=?, phase='result_ready',
                       updated_ms=? WHERE battle_id=?""",
                    (results_json, digest, self._clock_ms(), battle_id),
                )
                created = True
            elif battle["results_digest"] != digest:
                raise BattleStateError("results_conflict")
        return _decoded(results_json), created

    def get_battle_results(self, battle_id: str) -> list | None:
        """Return a raw JSON-compatible array, or ``None`` while not ready."""
        battle_id = _identifier(battle_id, "battle_id")
        with self._lock:
            battle = self._battle(battle_id)
            value = battle["results_json"]
            return None if value is None else _decoded(value)

    def settle_once(
        self,
        battle_id: str,
        user_id: str,
        settlement: dict,
    ) -> tuple[dict, bool]:
        """Store one server-computed settlement for ``(battle_id,user_id)``.

        The returned ``created`` flag is true only for the first atomic insert.
        Retry callers receive the original value; changed reward data conflicts.
        """
        battle_id = _identifier(battle_id, "battle_id")
        user_id = _identifier(user_id, "user_id")
        if not isinstance(settlement, dict):
            raise BattleStateError("invalid_settlement")
        settlement_json, digest = _canonical(
            settlement, maximum=MAX_SETTLEMENT_BYTES, kind="settlement"
        )
        created = False
        with self._transaction():
            battle = self._battle(battle_id)
            self._require_user(battle, user_id)
            if PHASE_INDEX[battle["phase"]] < PHASE_INDEX["result_ready"]:
                raise BattleStateError("results_not_ready")
            existing = self._connection.execute(
                "SELECT settlement_json,settlement_digest FROM settlements "
                "WHERE battle_id=? AND user_id=?",
                (battle_id, user_id),
            ).fetchone()
            if existing is None:
                self._connection.execute(
                    "INSERT INTO settlements VALUES (?, ?, ?, ?, ?)",
                    (battle_id, user_id, settlement_json, digest, self._clock_ms()),
                )
                created = True
            elif existing["settlement_digest"] != digest:
                raise BattleStateError("settlement_conflict")
            else:
                settlement_json = existing["settlement_json"]
            count = self._connection.execute(
                "SELECT COUNT(*) FROM settlements WHERE battle_id=?", (battle_id,)
            ).fetchone()[0]
            if count == len(self._users(battle)) and battle["phase"] == "result_ready":
                self._set_phase(battle_id, "settled")
        return _decoded(settlement_json), created

    def settlement(self, battle_id: str, user_id: str) -> dict | None:
        battle_id = _identifier(battle_id, "battle_id")
        user_id = _identifier(user_id, "user_id")
        with self._lock:
            battle = self._battle(battle_id)
            self._require_user(battle, user_id)
            row = self._connection.execute(
                "SELECT settlement_json FROM settlements WHERE battle_id=? AND user_id=?",
                (battle_id, user_id),
            ).fetchone()
            return None if row is None else _decoded(row["settlement_json"])

    def deliver_results(self, battle_id: str, user_id: str) -> tuple[list, bool]:
        """Return results and record that this settled roster member received them."""
        battle_id = _identifier(battle_id, "battle_id")
        user_id = _identifier(user_id, "user_id")
        created = False
        with self._transaction():
            battle = self._battle(battle_id)
            self._require_user(battle, user_id)
            if battle["results_json"] is None:
                raise BattleStateError("results_not_ready")
            settled = self._connection.execute(
                "SELECT 1 FROM settlements WHERE battle_id=? AND user_id=?",
                (battle_id, user_id),
            ).fetchone()
            if settled is None:
                raise BattleStateError("user_not_settled")
            cursor = self._connection.execute(
                "INSERT OR IGNORE INTO deliveries VALUES (?, ?, ?)",
                (battle_id, user_id, self._clock_ms()),
            )
            created = cursor.rowcount == 1
            count = self._connection.execute(
                "SELECT COUNT(*) FROM deliveries WHERE battle_id=?", (battle_id,)
            ).fetchone()[0]
            if count == len(self._users(battle)) and battle["phase"] == "settled":
                self._set_phase(battle_id, "delivered")
            results_json = battle["results_json"]
        return _decoded(results_json), created

    def snapshot(self, battle_id: str) -> dict:
        battle_id = _identifier(battle_id, "battle_id")
        with self._lock:
            battle = self._battle(battle_id)
            users = self._users(battle)
            credential = self._connection.execute(
                "SELECT expected_players FROM battle_credentials WHERE battle_id=?",
                (battle_id,),
            ).fetchone()

            def members(table: str, column: str) -> list[str]:
                rows = self._connection.execute(
                    f"SELECT {column} FROM {table} WHERE battle_id=? ORDER BY {column}",
                    (battle_id,),
                ).fetchall()
                return [row[0] for row in rows]

            return {
                "battle_id": battle_id,
                "phase": battle["phase"],
                "user_ids": users,
                "context": _decoded(battle["context_json"]),
                # Public roster count only; the battle key digest remains
                # private. GAME_JOIN counts human rows and excludes CPUs.
                "expected_players": (None if credential is None
                                     else credential["expected_players"]),
                "enrolled_user_ids": members("enrollments", "user_id"),
                "reported_user_ids": members("final_events", "user_id"),
                "settled_user_ids": members("settlements", "user_id"),
                "delivered_user_ids": members("deliveries", "user_id"),
                "results_ready": battle["results_json"] is not None,
                "created_ms": battle["created_ms"],
                "updated_ms": battle["updated_ms"],
            }
