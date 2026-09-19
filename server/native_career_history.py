"""Read completed, same-account native results without mutating source databases."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
import sqlite3


_RUN_NAME = re.compile(r"[0-9a-f]{64}")


def _unalias_path(path: Path) -> Path:
    """Reject symlinks, junctions and aliased ancestors, including missing leaves.

    ``is_symlink`` alone does not cover Windows directory junctions. Resolving
    the complete path also checks existing ancestors of a not-yet-created DB.
    """
    path = Path(path).absolute()
    try:
        resolved = path.resolve()
    except RuntimeError:
        raise ValueError("career_aliased_path") from None
    if path.is_symlink() or resolved != path:
        raise ValueError("career_aliased_path")
    return path


def career_storage_paths(battle_state_path: Path) -> tuple[Path, Path | None]:
    """Keep companion careers across runs; standalone labs stay beside their DB.

    Only the launcher's exact bridge-runs/<nonce>/battle_state.sqlite3 layout
    permits scanning siblings. No environment default or user-home fallback is
    used, so an isolated test cannot silently open the real account's files.
    """
    source = _unalias_path(battle_state_path)
    run = source.parent
    if (source.name == "battle_state.sqlite3" and _RUN_NAME.fullmatch(run.name)
            and run.parent.name == "bridge-runs"):
        runs = run.parent
        return runs.parent / "career.sqlite3", runs
    return run / "career.sqlite3", None


def completed_rows(source: Path, user_id: str):
    """Yield canonical evidence only when the lifecycle has a settlement.

    Counters and allocation identities are validated by the career store; SQL
    does not infer a win from score or turn an unfinished battle into a result.
    """
    source = _unalias_path(source)
    if not isinstance(user_id, str) or not user_id:
        raise ValueError("invalid_career_user")
    connection = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA busy_timeout = 3000")
        for battle_id, users, context, event, settlement in connection.execute(
            "SELECT b.battle_id,b.users_json,b.context_json,f.event_json,s.settlement_json "
            "FROM battles b JOIN final_events f ON f.battle_id=b.battle_id "
            "JOIN settlements s ON s.battle_id=f.battle_id AND s.user_id=f.user_id "
            # A same-user settlement is durable before every other member has
            # settled. The shared battle can legitimately remain result_ready.
            "WHERE f.user_id=? AND b.phase IN ('result_ready','settled','delivered') "
            "ORDER BY s.settled_ms,b.battle_id", (user_id,)
        ):
            if any(not isinstance(raw, str) or len(raw.encode('utf-8')) > limit for raw, limit in (
                (users, 64 * 1024), (context, 64 * 1024), (event, 2 * 1024 * 1024),
                (settlement, 256 * 1024)
            )):
                raise ValueError("career_oversize_source")
            members = json.loads(users)
            if (not isinstance(members, list) or user_id not in members
                    or not all(isinstance(member, str) for member in members)):
                raise ValueError("career_source_user_not_in_roster")
            yield battle_id, json.loads(context), json.loads(event), json.loads(settlement)
    finally:
        connection.close()


def backfill_completed(store, user_id: str, current_source: Path,
                       runs_root: Path | None = None) -> dict:
    """Replay persisted finals; the store's unique battle key makes this safe.

    Returns counts only, never authentication data, native IDs, or raw reports.
    A damaged historical DB does not prevent other histories being recovered.
    """
    current_source = _unalias_path(current_source)
    paths = {current_source}
    counts = Counter(sources=0, completed=0, source_errors=0, record_errors=0)
    if runs_root is not None:
        root = _unalias_path(runs_root)
        if (root.name != "bridge-runs"
                or current_source.name != "battle_state.sqlite3"
                or not _RUN_NAME.fullmatch(current_source.parent.name)
                or current_source.parent.parent != root):
            raise ValueError("invalid_career_history_root")
        try:
            for child in root.iterdir():
                if not _RUN_NAME.fullmatch(child.name) or not child.is_dir():
                    continue
                candidate = child / "battle_state.sqlite3"
                try:
                    candidate = _unalias_path(candidate)
                    if candidate.is_file():
                        paths.add(candidate)
                except (OSError, ValueError):
                    counts["source_errors"] += 1
        except OSError:
            # The caller's current DB can still be read when sibling discovery
            # is unavailable; a history-directory error must not abort launch.
            counts["source_errors"] += 1
    for source in sorted(paths):
        if not source.is_file():
            continue
        counts["sources"] += 1
        try:
            for battle_id, context, event, settlement in completed_rows(source, user_id):
                # Matching the source table and credential-free event also
                # prevents a copied row being relabeled as another battle.
                if (not isinstance(context, dict) or not isinstance(event, dict)
                        or not isinstance(settlement, dict)
                        or event.get("battle_id") != battle_id):
                    counts["record_errors"] += 1
                    continue
                try:
                    store.record_completed(context, event, settlement, user_id)
                    counts["completed"] += 1
                except (ValueError, KeyError, TypeError, OSError, sqlite3.Error):
                    counts["record_errors"] += 1
        except (ValueError, KeyError, TypeError, OSError, sqlite3.Error):
            counts["source_errors"] += 1
    return dict(counts)
