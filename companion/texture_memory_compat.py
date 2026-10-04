"""Activate signed low-memory texture packs only for a proven software renderer.

The signed game updater owns the inert top-level ``.bin`` files. This module
owns only the copied ``data/zz_twa_texture_memory_XX.pack`` names and its
client-local marker. The authenticated launch holds ``client_operation_lock``
before calling :func:`reconcile`, and Arena must still be stopped.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .config import Config
from .updater import (
    UpdaterError, _is_reparse_point, _lexists, _require_real_directory,
    _require_safe_update_boundaries, _require_unshared_regular_or_missing,
    _safe_client_target, is_arena_running,
)


class TextureMemoryCompatError(RuntimeError):
    """The renderer decision or an owned texture file cannot be trusted."""


@dataclass(frozen=True)
class TexturePack:
    cache: str
    active: str
    sha256: str
    size: int


TEXTURE_PACKS = (
    TexturePack("twa_warp_texture_00.bin", "data/zz_twa_texture_memory_00.pack", "6a0517ab5d6f7db90f4ba22edb21c14e642a9ccae16ad47ce9a4e1e90211023c", 31717573),
    TexturePack("twa_warp_texture_01.bin", "data/zz_twa_texture_memory_01.pack", "a175979c972e556d997e2548c4aeefdfd9805fc91d3cb91e9ed12182a99044ac", 31716963),
    TexturePack("twa_warp_texture_02.bin", "data/zz_twa_texture_memory_02.pack", "8d1a14c1aea7434581e82be91b9ac7ccd29c3a9b057334ad8837feaf6749dce1", 31716554),
    TexturePack("twa_warp_texture_03.bin", "data/zz_twa_texture_memory_03.pack", "35baa95d52a490d056342dfcfae916b0db6f8b828916095d873f095a77d55ba8", 31717064),
    TexturePack("twa_warp_texture_04.bin", "data/zz_twa_texture_memory_04.pack", "be24ff48c2607dae7310e21d747a817154b26adff23df34463660458ba5cb02e", 31717879),
    TexturePack("twa_warp_texture_05.bin", "data/zz_twa_texture_memory_05.pack", "e52135c183be78e459b6f1007fa75e4a145f5783781dedca06b27504b500e965", 31717199),
    TexturePack("twa_warp_texture_06.bin", "data/zz_twa_texture_memory_06.pack", "4d25d1d0c309df6b7f183cba39364fd1fcb747ee1d0ec44e83deee16e5a51324", 31717946),
    TexturePack("twa_warp_texture_07.bin", "data/zz_twa_texture_memory_07.pack", "72c22e77e96972a2fad14cdb7b25fd57a786d8d66ea7b7dc6d30405034e28fb9", 31717111),
    TexturePack("twa_warp_texture_08.bin", "data/zz_twa_texture_memory_08.pack", "e0660dbc9dd24d9d79798b850e81b09800b1f65ed0d7f2d505a0bf6c615e8f13", 31717762),
    TexturePack("twa_warp_texture_09.bin", "data/zz_twa_texture_memory_09.pack", "06430c66a05d4d7d9e020ca63e62d2f5ab042ed77429b48bda20af0e391e98fb", 31716615),
    TexturePack("twa_warp_texture_10.bin", "data/zz_twa_texture_memory_10.pack", "9e041187105c1709981724ec9123cfcb43f02c797067b959818c1fa0a486ae86", 31717269),
    TexturePack("twa_warp_texture_11.bin", "data/zz_twa_texture_memory_11.pack", "917eb4cec5bc2e594cd0b564d057f6f1709ed2c920ea0cbd730f2ce0876bef96", 31716618),
    TexturePack("twa_warp_texture_12.bin", "data/zz_twa_texture_memory_12.pack", "91ca0dc221f2d43fd3f54631d84c8a717557eea7f609e324d05e010b83e3d3b8", 31716574),
    TexturePack("twa_warp_texture_13.bin", "data/zz_twa_texture_memory_13.pack", "edeefc9716b754c82bc9887885c95b1f2067de8b499499c41bfa0b9f37f2b6bb", 31717898),
    TexturePack("twa_warp_texture_14.bin", "data/zz_twa_texture_memory_14.pack", "940af5291b160a65565dad23029ab93482a8fa18329afbdcdb22fe2b8d13db55", 31716593),
    TexturePack("twa_warp_texture_15.bin", "data/zz_twa_texture_memory_15.pack", "eac700ddd98a39a3a14d1cf4c489d5cd33afc22775d9c9e83ddada9563035476", 31717303),
)

# Exact complete generations previously recognized by reversible QA tooling.
# These are not per-file alternatives: reconciliation accepts a generation
# only when all 16 files match the same tuple of hashes and sizes.
_CAP256_V1 = (
    ("6e6b21261e07e0b4f87ff3d3291c03daa6b69639e021de11cad09ea44447b5b1", 26914202),
    ("3703721000f21372ebc425447bbbbfa66f30ffd2d229cfdf5ff1a413365ae661", 26914575),
    ("394968a5441bb06e5a5c50536b8a33a2216d73080796ba49abeacebae99782f0", 26915132),
    ("fbde8371b101ffea0b154eacd96a1e41ec29cdce776b2e15ddaccf0467697a81", 26914101),
    ("0d59c2a5a5ca63de4d4e83c244f624d329d611590c1f4a63c7d43300adf528c4", 26913777),
    ("6c42964598a1f8543200649852bfbcafe1c20e8fc1df2f1506d69ef6561c39bb", 26914630),
    ("741845dd288944edbbc51458c98902eb8f891a078817f073f37c74dc5ae27841", 26914324),
    ("91dc00a12d372b93d953f35d8d235a5d39fd9ecae6fcc1780830560a0a81cbc5", 26914602),
    ("e7de9e3fd7c31a95c467eb526f607f27abb324461361df6c3673ef7d403cb479", 26913409),
    ("9adcd0d3086d70db5739b2d1df8d737204f23a3ed3b4052a968853cdc511912c", 26913787),
    ("069182181c7780ed42ee9607c24316e1286020516c63a55aa901e6b6fc5bc3f6", 26914486),
    ("79821001b2336359508a628153e0bbb4f206db1b8b247c2bb6130064bb1c6608", 26914353),
    ("f7372975a10bd0eb44cd4c74084ba98fca7e30762c4208c54b7ce8358b5ec212", 26914147),
    ("c67477ec6e5ca40d3e2524614af7417597cf22c1fdddba8c4ff06f6ff5c89846", 26914389),
    ("401ceb467b410df7e1bd43eb9a73c55b82b1009105ccb4f47403d8bca25497f1", 26913761),
    ("025ce8ec6540caa9264918b1f727103ea487e2d5c17fb8daab93caff2ea8e683", 26915002),
)
_CAP512_V1 = (
    ("a69504a18d09dfb08f5aaaaf51493de90cd51c27c5a906d40752ba41099bef5e", 55303074),
    ("26461733d855c34760c77ae1c293ba6b8f7f41e9f7333b0f4779d0f5b873cbf6", 55297446),
    ("33fa44c7b9511e6616134840b174b73d2f711761a2876b4f0112c04b7bf5d968", 55297432),
    ("a4af0fcb81d427f7df48141180ee7ef83869e2eefebf564bb40496b3d0936756", 55300709),
    ("4a01f5b384dfd5af56cc359a9f0eb3eded1211c9587680cc910df000184531bd", 55297492),
    ("2005a779f3abea4433584ed1a1e6c6a378e510e2845433279c7b0fb4625c1023", 55297494),
    ("e2ada5ad5c2d60ea46298a04f6c2c6d3f992407778a9e7e737ec052e40f57b98", 55298226),
    ("b6373e267d2fde8473c7bc5a1375ffdbbe780320b90871865b3dc9a228564a62", 55298158),
    ("b1cffc543f2147583955fa926c68b0ae588203f232ace4c122ae0efeda2aa0b7", 55297417),
    ("5bf6772cac948fdd2301d69ef7007b49139e8593a9dd436e1efb92802cdd011d", 55297454),
    ("8961c69606b4b5d219380cfad28ddf513471d52b68348b0cf16c6282d9c7eeaa", 55300652),
    ("af436e46bbd329f4c9fb5b7a467d9072bc59e55666de70983108950115a928fa", 55308301),
    ("289701d4cd63d49eeed7f807bb6e68e62d43dcaff1b72a09c02b3a52b5c3d80f", 55297557),
    ("96ff344b960d6125ceabac98aca86b45438cad2bbd7f1d948bac0c98bf095491", 55297513),
    ("ba3184f4a675358971a9683dcb0974064ec23f29a284fd7152e4ce58d602c143", 55308394),
    ("9534e33d41229a2791f2115b47051462f62ba90b71a5da530b3ddcbce2b459c7", 55303075),
)
LEGACY_TEXTURE_GENERATIONS = tuple(
    tuple(TexturePack(pack.cache, pack.active, digest, size)
          for pack, (digest, size) in zip(TEXTURE_PACKS, generation))
    for generation in (_CAP256_V1, _CAP512_V1)
)

_MARKER_NAME = ".twa-warp-texture-owned-v1"
_STAGING = b"TWA_WARP_TEXTURE_V1:staging\n"
_ACTIVE = b"TWA_WARP_TEXTURE_V1:active\n"
_DEACTIVATING = b"TWA_WARP_TEXTURE_V1:deactivating\n"
_MIGRATING = b"TWA_WARP_TEXTURE_V1:migrating\n"
_STAGE_SUFFIX = ".twa-warp-stage"
_HELD_SUFFIX = ".twa-warp-held"


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _matches(path: Path, pack: TexturePack) -> bool:
    return path.stat().st_size == pack.size and _digest(path) == pack.sha256


def _require_not_running(arena_running: Callable[[], bool]) -> None:
    if arena_running():
        raise TextureMemoryCompatError("Arena must be stopped for texture activation")


def _copy_exclusive(source: Path, target: Path, pack: TexturePack) -> None:
    # Exclusive creation prevents an unknown staging file from being replaced.
    with source.open("rb") as incoming, target.open("xb") as outgoing:
        for chunk in iter(lambda: incoming.read(1024 * 1024), b""):
            outgoing.write(chunk)
        outgoing.flush()
        os.fsync(outgoing.fileno())
    if not _matches(target, pack):
        raise TextureMemoryCompatError("staged texture hash mismatch")


def _marker(config: Config) -> Path:
    root = Path(os.path.abspath(config.client_dir))
    _require_real_directory(root, "client directory")
    marker = root / _MARKER_NAME
    _require_unshared_regular_or_missing(marker, "texture ownership marker")
    return marker


def _validated_paths(config: Config, *, require_cache: bool) -> tuple[tuple[TexturePack, Path, Path], ...]:
    entries = []
    for pack in TEXTURE_PACKS:
        cache = _safe_client_target(config, pack.cache)
        active = _safe_client_target(config, pack.active)
        if require_cache and (not cache.is_file() or not _matches(cache, pack)):
            raise TextureMemoryCompatError("signed texture cache is missing or corrupt")
        entries.append((pack, cache, active))
    return tuple(entries)


def _known_generations(entries):
    current = tuple(row[0] for row in entries)
    yield current
    expected_names = tuple((pack.cache, pack.active) for pack in current)
    for generation in LEGACY_TEXTURE_GENERATIONS:
        if (len(generation) == len(current)
                and tuple((pack.cache, pack.active) for pack in generation) == expected_names):
            yield tuple(generation)


def _active_generation(entries):
    for generation in _known_generations(entries):
        if all(_lexists(entries[index][2]) and _matches(entries[index][2], pack)
               for index, pack in enumerate(generation)):
            return generation
    return None


def _known_pack_match(entries, index: int, path: Path) -> bool:
    return any(index < len(generation) and _matches(path, generation[index])
               for generation in _known_generations(entries))


def _known_cache_prefix(path: Path, cache: Path, pack: TexturePack) -> bool:
    """Accept only an exact prefix of the verified signed cache as a torn copy."""
    try:
        if _is_reparse_point(path) or not path.is_file() or not _matches(cache, pack):
            return False
        size = path.stat().st_size
        if size > pack.size:
            return False
        with path.open("rb") as partial, cache.open("rb") as source:
            remaining = size
            while remaining:
                amount = min(1024 * 1024, remaining)
                left = partial.read(amount)
                right = source.read(amount)
                if len(left) != amount or left != right:
                    return False
                remaining -= amount
        return True
    except OSError:
        return False


def reconcile(
    config: Config, decision: str, *, arena_running: Callable[[], bool] = is_arena_running,
) -> dict[str, int | str]:
    """Bring owned packs into the data directory for software, out for hardware.

    Unknown detection leaves a clean installation unchanged. The caller must
    hold ``client_operation_lock``.
    """
    if decision not in ("software", "hardware", "unknown"):
        raise TextureMemoryCompatError("invalid renderer decision")
    try:
        _require_safe_update_boundaries(config)
        _require_not_running(arena_running)
        entries = _validated_paths(config, require_cache=decision == "software")
        marker = _marker(config)
        state = marker.read_bytes() if _lexists(marker) else None
        if state not in (None, _STAGING, _ACTIVE, _DEACTIVATING, _MIGRATING):
            raise TextureMemoryCompatError("texture ownership marker is invalid")
        transition = marker.with_name(marker.name + ".transition")
        _require_unshared_regular_or_missing(transition, "texture marker transition")
        if _lexists(transition):
            if state is None or transition.read_bytes() not in (_ACTIVE, _DEACTIVATING, _MIGRATING):
                raise TextureMemoryCompatError("unowned marker transition")
            if decision == "unknown":
                raise TextureMemoryCompatError("incomplete marker transition")
            transition.unlink()
        owned = state is not None
        for index, (pack, _cache, active) in enumerate(entries):
            _require_unshared_regular_or_missing(active, "active texture pack")
            if _lexists(active) and not owned:
                raise TextureMemoryCompatError("unowned active texture pack")
            for suffix in (_STAGE_SUFFIX, _HELD_SUFFIX):
                sidecar = active.with_name(active.name + suffix)
                _require_unshared_regular_or_missing(sidecar, "texture sidecar")
                if _lexists(sidecar) and not owned:
                    raise TextureMemoryCompatError("unowned texture sidecar")
                if (_lexists(sidecar) and suffix == _HELD_SUFFIX
                        and (state not in (_DEACTIVATING, _MIGRATING)
                             or not _known_pack_match(entries, index, sidecar))):
                    raise TextureMemoryCompatError("unowned or changed held texture pack")
                if _lexists(sidecar) and suffix == _STAGE_SUFFIX and state not in (_STAGING, _MIGRATING):
                    raise TextureMemoryCompatError("unowned texture stage")
        active_generation = _active_generation(entries) if owned else None
        active_any = any(_lexists(active) for _pack, _cache, active in entries)
        if owned and state == _ACTIVE and active_generation is None:
            raise TextureMemoryCompatError("active owned texture generation is incomplete or unrecognized")
        if state is None and active_any:
            raise TextureMemoryCompatError("unowned active texture pack")
        if decision == "unknown":
            if state is None and not active_any:
                return {"mode": "unknown", "changed": 0}
            if state in (_ACTIVE, _STAGING) and active_generation is not None and all(
                _lexists(active)
                and not _lexists(active.with_name(active.name + _STAGE_SUFFIX))
                and not _lexists(active.with_name(active.name + _HELD_SUFFIX))
                for _pack, _cache, active in entries
            ):
                return {"mode": "preserved-software", "changed": 0}
            raise TextureMemoryCompatError("incomplete texture state on unknown renderer")
        if state in (_STAGING, _DEACTIVATING, _MIGRATING):
            _recover(entries, marker, state, arena_running)
            state = _ACTIVE if state == _MIGRATING else None
            active_generation = _active_generation(entries) if state == _ACTIVE else None
        if state == _ACTIVE and active_generation is None:
            raise TextureMemoryCompatError("recovered texture generation is not recognized")
        if decision == "software":
            if state == _ACTIVE and active_generation == tuple(row[0] for row in entries):
                return {"mode": "software", "changed": 0}
            if state == _ACTIVE:
                return _migrate(entries, marker, active_generation, arena_running)
            return _activate(entries, marker, False, arena_running)
        if state == _ACTIVE:
            return _deactivate_generation(entries, marker, True, arena_running,
                                          active_generation)
        return {"mode": "hardware", "changed": 0}
    except (OSError, UpdaterError) as exc:
        raise TextureMemoryCompatError("texture compatibility transaction failed") from exc


def _write_marker(marker: Path, value: bytes, *, initial: bool = False) -> None:
    if initial:
        with marker.open("xb") as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        return
    temp = marker.with_name(marker.name + ".transition")
    _require_unshared_regular_or_missing(temp, "texture marker transition")
    if _lexists(temp):
        raise TextureMemoryCompatError("texture marker transition needs recovery")
    with temp.open("xb") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temp, marker)


def _recover(entries, marker: Path, state: bytes, arena_running) -> None:
    if state == _MIGRATING:
        _recover_migration(entries, marker, arena_running)
        return
    for index, (pack, _cache, active) in enumerate(entries):
        _require_not_running(arena_running)
        stage = active.with_name(active.name + _STAGE_SUFFIX)
        held = active.with_name(active.name + _HELD_SUFFIX)
        if state == _STAGING:
            if _lexists(active):
                if not _matches(active, pack):
                    raise TextureMemoryCompatError("changed published texture during recovery")
                active.unlink()
            if _lexists(stage):
                _require_unshared_regular_or_missing(stage, "texture stage")
                stage.unlink()
        elif state == _DEACTIVATING:
            for path in (active, held):
                if _lexists(path):
                    if not _known_pack_match(entries, index, path):
                        raise TextureMemoryCompatError("changed held texture during recovery")
                    path.unlink()
    marker.unlink()


def _restore_migration(entries, marker: Path, previous, arena_running) -> None:
    current = tuple(row[0] for row in entries)
    for index, (current_pack, cache, active) in enumerate(entries):
        _require_not_running(arena_running)
        stage = active.with_name(active.name + _STAGE_SUFFIX)
        held = active.with_name(active.name + _HELD_SUFFIX)
        active_is_previous = _lexists(active) and _matches(active, previous[index])
        held_is_previous = _lexists(held) and _matches(held, previous[index])
        if _lexists(active):
            if active_is_previous:
                # Some generations intentionally share byte-identical packs.
                # Keep the active copy; a held duplicate is safe to discard.
                if held_is_previous:
                    held.unlink()
            elif _matches(active, current_pack):
                if not held_is_previous:
                    raise TextureMemoryCompatError("migration rollback is missing its old texture")
                active.unlink()
            else:
                raise TextureMemoryCompatError("migration rollback found an unrecognized active texture")
        if _lexists(held):
            if not held_is_previous or _lexists(active):
                raise TextureMemoryCompatError("migration rollback refused changed held texture")
            held.rename(active)
        if _lexists(stage):
            if not (_matches(stage, current_pack)
                    or _known_cache_prefix(stage, cache, current_pack)):
                raise TextureMemoryCompatError("migration rollback refused changed staged texture")
            stage.unlink()
    if _active_generation(entries) != previous:
        raise TextureMemoryCompatError("migration rollback did not restore a complete generation")
    _write_marker(marker, _ACTIVE)


def _recover_migration(entries, marker: Path, arena_running) -> None:
    current = tuple(row[0] for row in entries)
    if all(_lexists(entries[i][2]) and _matches(entries[i][2], pack)
           for i, pack in enumerate(current)):
        # The new generation was fully published. Finish its commit, cleaning
        # only exact old-generation sidecars and exact current-generation stages.
        held_generation = next((generation for generation in _known_generations(entries)
                                if generation != current and all(
                                    not _lexists(entries[i][2].with_name(
                                        entries[i][2].name + _HELD_SUFFIX))
                                    or _matches(entries[i][2].with_name(
                                        entries[i][2].name + _HELD_SUFFIX), generation[i])
                                    for i in range(len(entries)))), None)
        if held_generation is None and any(
                _lexists(active.with_name(active.name + _HELD_SUFFIX))
                for _pack, _cache, active in entries):
            raise TextureMemoryCompatError("migration recovery found a mixed held generation")
        for i, (pack, cache, active) in enumerate(entries):
            _require_not_running(arena_running)
            held = active.with_name(active.name + _HELD_SUFFIX)
            stage = active.with_name(active.name + _STAGE_SUFFIX)
            if _lexists(held):
                if held_generation is None or not _matches(held, held_generation[i]):
                    raise TextureMemoryCompatError("migration recovery found changed held texture")
                held.unlink()
            if _lexists(stage):
                if not (_matches(stage, current[i])
                        or _known_cache_prefix(stage, cache, pack)):
                    raise TextureMemoryCompatError("migration recovery found changed stage")
                stage.unlink()
        _write_marker(marker, _ACTIVE)
        return
    previous = None
    for generation in _known_generations(entries):
        if generation == current:
            continue
        coherent = True
        for i, (_pack, _cache, active) in enumerate(entries):
            held = active.with_name(active.name + _HELD_SUFFIX)
            if _lexists(held):
                if not _matches(held, generation[i]):
                    coherent = False
                    break
            elif not _lexists(active) or not _matches(active, generation[i]):
                coherent = False
                break
        if coherent:
            previous = generation
            break
    if previous is None:
        raise TextureMemoryCompatError("interrupted migration has no complete recognized rollback generation")
    _restore_migration(entries, marker, previous, arena_running)


def _activate(entries, marker: Path, owned: bool, arena_running) -> dict[str, int | str]:
    missing = [(pack, cache, active) for pack, cache, active in entries if not _lexists(active)]
    if not missing:
        if not owned:
            raise TextureMemoryCompatError("active texture packs are not owned")
        return {"mode": "software", "changed": 0}
    staged: list[tuple[TexturePack, Path]] = []
    published: list[tuple[TexturePack, Path]] = []
    created_marker = False
    try:
        if owned:
            _write_marker(marker, _STAGING)
        else:
            _write_marker(marker, _STAGING, initial=True)
            created_marker = True
        for pack, cache, active in missing:
            stage = active.with_name(active.name + _STAGE_SUFFIX)
            staged.append((pack, stage))
            _copy_exclusive(cache, stage, pack)
        _require_not_running(arena_running)
        for pack, stage in staged:
            active = stage.with_name(stage.name[:-len(_STAGE_SUFFIX)])
            _require_not_running(arena_running)
            if _lexists(active) or not _matches(stage, pack):
                raise TextureMemoryCompatError("texture publish target or stage changed")
            stage.rename(active)
            published.append((pack, active))
            if not _matches(active, pack):
                raise TextureMemoryCompatError("published texture hash mismatch")
        _write_marker(marker, _ACTIVE)
        return {"mode": "software", "changed": len(published)}
    except Exception:
        for pack, active in reversed(published):
            if not _matches(active, pack):
                raise TextureMemoryCompatError("texture activation rollback refused")
            active.unlink()
        for _pack, stage in staged:
            if _lexists(stage):
                # The sidecar was created exclusively by this transaction.
                if _is_reparse_point(stage) or not stage.is_file():
                    raise TextureMemoryCompatError("texture stage cleanup refused")
                stage.unlink()
        transition = marker.with_name(marker.name + ".transition")
        _require_unshared_regular_or_missing(transition, "texture marker transition")
        if _lexists(transition):
            if transition.read_bytes() != _ACTIVE:
                raise TextureMemoryCompatError("texture marker transition rollback refused")
            transition.unlink()
        if created_marker:
            if marker.read_bytes() != _STAGING:
                raise TextureMemoryCompatError("texture marker rollback refused")
            marker.unlink()
        elif marker.read_bytes() == _STAGING:
            _write_marker(marker, _ACTIVE)
        raise


def _deactivate(entries, marker: Path, owned: bool, arena_running) -> dict[str, int | str]:
    return _deactivate_generation(entries, marker, owned, arena_running,
                                  tuple(row[0] for row in entries))


def _deactivate_generation(entries, marker: Path, owned: bool, arena_running, generation) -> dict[str, int | str]:
    present = [(generation[index], active, index)
               for index, (_pack, _cache, active) in enumerate(entries) if _lexists(active)]
    if not present:
        if owned:
            marker.unlink()
        return {"mode": "hardware", "changed": 0}
    if not owned:
        raise TextureMemoryCompatError("active texture packs are not owned")
    _write_marker(marker, _DEACTIVATING)
    for pack, active, index in present:
        _require_not_running(arena_running)
        if not _matches(active, generation[index]):
            raise TextureMemoryCompatError("active texture changed before deactivation")
        sidecar = active.with_name(active.name + _HELD_SUFFIX)
        if _lexists(sidecar):
            raise TextureMemoryCompatError("texture held path appeared")
        active.rename(sidecar)
    _recover(entries, marker, _DEACTIVATING, arena_running)
    return {"mode": "hardware", "changed": len(present)}


def _migrate(entries, marker: Path, previous, arena_running) -> dict[str, int | str]:
    if previous is None or tuple(previous) == tuple(row[0] for row in entries):
        raise TextureMemoryCompatError("migration source generation is not recognized")
    staged: list[tuple[TexturePack, Path]] = []
    current = tuple(row[0] for row in entries)
    try:
        _write_marker(marker, _MIGRATING)
        for pack, cache, active in entries:
            _require_not_running(arena_running)
            stage = active.with_name(active.name + _STAGE_SUFFIX)
            staged.append((pack, stage))
            _copy_exclusive(cache, stage, pack)
        for index, (pack, _cache, active) in enumerate(entries):
            _require_not_running(arena_running)
            held = active.with_name(active.name + _HELD_SUFFIX)
            stage = active.with_name(active.name + _STAGE_SUFFIX)
            if not _matches(active, previous[index]) or _lexists(held):
                raise TextureMemoryCompatError("migration source changed or held target appeared")
            active.rename(held)
            if not _matches(held, previous[index]) or _lexists(active) or not _matches(stage, pack):
                raise TextureMemoryCompatError("migration staged or held texture changed")
            stage.rename(active)
            if not _matches(active, pack):
                raise TextureMemoryCompatError("migrated texture hash mismatch")
        if not all(_matches(active, pack) for pack, _cache, active in entries):
            raise TextureMemoryCompatError("migration did not publish the full new generation")
        # Keep the MIGRATING marker until old copies are removed. A restart in
        # this window recognizes the complete new set and finishes the commit.
        for index, (_pack, _cache, active) in enumerate(entries):
            _require_not_running(arena_running)
            held = active.with_name(active.name + _HELD_SUFFIX)
            if not _matches(held, previous[index]):
                raise TextureMemoryCompatError("old migration backup changed before cleanup")
            held.unlink()
        _write_marker(marker, _ACTIVE)
        return {"mode": "software", "changed": len(entries)}
    except Exception:
        # If the new set is already complete, leave the MIGRATING journal so
        # the next locked launch can finish commit without losing either set.
        if all(_lexists(active) and _matches(active, pack)
               for pack, _cache, active in entries):
            raise
        _restore_migration(entries, marker, previous, arena_running)
        raise
