"""Fail-closed maintenance and signed-update gate for distributed launches.

``development`` is an explicit no-network bypass for this source tree's
existing local/fake launch workflow. ``release`` requires a non-loopback
HTTPS control origin and a separately pinned production Ed25519 key set. It
never accepts the reproducible development key, even under a different id.

This module prepares the copied client only. It does not implement EOS login,
the native bridge lifecycle, or the rest of a distributable launch bootstrap.
Callers must keep those requirements separate and must not treat READY as
authorization to use a local fake-auth launch path.
"""
from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Callable
from urllib.parse import urlsplit

from .api_client import (
    ApiClient,
    ApiError,
    MaintenanceError,
    NetworkError,
    UpdateRequiredError,
    normalize_api_base_url,
)
from .config import Config
from .maintenance import MaintenanceStatus, status_from_error
from .manifest import ManifestError, semver_tuple
from .trusted_keys import RELEASE_TRUSTED_KEYS
from .updater import ArenaRunningError, UpdatePlan, UpdaterError
from .updater import apply as updater_apply
from .updater import check as updater_check

STARTUP_REQUEST_TIMEOUT_SECONDS = 5.0
# A terrain update can exceed 1 GB. Keep the short per-I/O timeout for
# stalled connections while allowing an active download up to 30 minutes.
STARTUP_NETWORK_BUDGET_SECONDS = 1800.0
_KEY_RE = re.compile(r"^[0-9a-fA-F]{64}$")
# Permanent deny-list by key bytes. Do not derive this from TRUSTED_KEYS: a
# future cleanup/rename of that mapping must not make the publicly reproducible
# seed eligible for release trust under a different id.
_DEVELOPMENT_PUBLIC_KEY_BYTES = frozenset({
    bytes.fromhex("a471d9e62d9c0a1cb7abd46c80a76ec3cbc26bfd5ea6c47827075e1b3c01d3bb")
})


class StartupCode(str, Enum):
    READY = "ready"
    DEVELOPMENT = "development"
    CONFIGURATION = "configuration"
    MAINTENANCE = "maintenance"
    UPDATE_REQUIRED = "update_required"
    OFFLINE = "offline"
    INVALID_RESPONSE = "invalid_response"
    UNTRUSTED_UPDATE = "untrusted_update"
    UPDATE_FAILED = "update_failed"


@dataclass(frozen=True)
class StartupResult:
    code: StartupCode
    allow_launch: bool
    message: str
    version: str | None = None
    updated: bool = False


_TEXT = {
    "EN": {
        "development": "Development startup: online maintenance/update gate was explicitly skipped.",
        "configuration": "Release startup is not configured: {detail}",
        "maintenance": "The service is under maintenance. {detail}",
        "update_required": "A verified compatible update is not available: {detail}",
        "offline": "Could not reach the update/maintenance service within the startup time limit.",
        "invalid_response": "The update/maintenance service returned an invalid health response.",
        "untrusted_update": "The release manifest could not be verified; startup was blocked.",
        "update_failed": "The verified update could not be applied safely: {detail}",
        "ready": "Startup checks passed at client version {version}.",
        "endpoint": "set a non-loopback HTTPS TWA_API_BASE_URL",
        "key_missing": "pin a real release Ed25519 public key in RELEASE_TRUSTED_KEYS",
        "key_malformed": "release public-key configuration is malformed",
        "key_hex": "release public key {key_id} is not 32-byte hex",
        "key_dev": "release public key {key_id} is the public development key",
        "server_config": "server startup control is unavailable",
        "end_time": "Scheduled end: {value}",
        "bootstrap_fake": "Release launch is blocked: authenticated EOS/Worker session and native bridge bootstrap are not integrated with this fake-auth development launcher.",
        "bootstrap_legacy": "Release launch is blocked: authenticated EOS/Worker session and native bridge bootstrap are not integrated with this legacy frontend path.",
        "bootstrap_release": "Release launch is blocked after preflight: authenticated EOS/Worker session and native bridge bootstrap are not implemented by this entry point.",
        "checking_maintenance": "Checking service and maintenance status…",
        "checking_update": "Checking the signed update manifest…",
        "verified_plan": "Verified update plan: {count} file(s), {mib:.1f} MiB.",
        "applying": "Applying the verified update…",
        "rechecking": "Rechecking service status after update verification…",
        "minimum_manifest": "required {minimum}; signed manifest offers {version}",
        "minimum_installed": "required {minimum}; verified version is {version}",
        "minimum_only": "required client version is {minimum}",
    },
    "JA": {
        "development": "開発用起動: オンラインのメンテナンス・更新チェックを明示的に省略しました。",
        "configuration": "配布版の起動設定が未完了です: {detail}",
        "maintenance": "現在メンテナンス中です。{detail}",
        "update_required": "互換性を確認できる署名済み更新がありません: {detail}",
        "offline": "起動時の制限時間内に更新・メンテナンスサービスへ接続できませんでした。",
        "invalid_response": "更新・メンテナンスサービスのヘルス応答が不正です。",
        "untrusted_update": "配布マニフェストの署名を検証できないため、起動を中止しました。",
        "update_failed": "検証済み更新を安全に適用できませんでした: {detail}",
        "ready": "クライアント {version} の起動前チェックが完了しました。",
        "endpoint": "ループバック以外の HTTPS TWA_API_BASE_URL を設定してください",
        "key_missing": "RELEASE_TRUSTED_KEYS に実運用の Ed25519 公開鍵を固定してください",
        "key_malformed": "配布用公開鍵の設定形式が不正です",
        "key_hex": "配布用公開鍵 {key_id} は32バイトの16進数ではありません",
        "key_dev": "配布用公開鍵 {key_id} は公開済みの開発鍵です",
        "server_config": "サーバーの起動制御設定を確認できません",
        "end_time": "終了予定: {value}",
        "bootstrap_fake": "配布版の起動を中止しました: このフェイク認証用開発ランチャーには EOS/Worker 認証とネイティブブリッジの起動処理が統合されていません。",
        "bootstrap_legacy": "配布版の起動を中止しました: この旧フロントエンド経路には EOS/Worker 認証とネイティブブリッジの起動処理が統合されていません。",
        "bootstrap_release": "起動前チェック後に配布版の起動を中止しました: このエントリーポイントには EOS/Worker 認証とネイティブブリッジの起動処理が未実装です。",
        "checking_maintenance": "サービスとメンテナンス状態を確認しています…",
        "checking_update": "署名済み更新マニフェストを確認しています…",
        "verified_plan": "更新内容を検証しました: {count} ファイル、{mib:.1f} MiB。",
        "applying": "検証済み更新を適用しています…",
        "rechecking": "更新確認後のサービス状態を再確認しています…",
        "minimum_manifest": "必要版 {minimum} に対し、署名済みマニフェストは {version} です",
        "minimum_installed": "必要版 {minimum} に対し、検証済みの版は {version} です",
        "minimum_only": "必要なクライアント版は {minimum} です",
    },
    "RU": {
        "development": "Запуск для разработки: онлайн-проверка обслуживания и обновлений явно пропущена.",
        "configuration": "Запуск сборки не настроен: {detail}",
        "maintenance": "Сервис находится на техническом обслуживании. {detail}",
        "update_required": "Нет проверенного совместимого обновления: {detail}",
        "offline": "Не удалось связаться с сервисом обновлений за отведённое время.",
        "invalid_response": "Сервис обновлений вернул некорректный ответ проверки состояния.",
        "untrusted_update": "Подпись манифеста не прошла проверку; запуск заблокирован.",
        "update_failed": "Не удалось безопасно применить проверенное обновление: {detail}",
        "ready": "Проверки запуска завершены для версии клиента {version}.",
        "endpoint": "задайте TWA_API_BASE_URL с HTTPS и без loopback-адреса",
        "key_missing": "закрепите настоящий открытый ключ Ed25519 в RELEASE_TRUSTED_KEYS",
        "key_malformed": "конфигурация открытого ключа выпуска некорректна",
        "key_hex": "открытый ключ выпуска {key_id} не является 32-байтовым hex-значением",
        "key_dev": "открытый ключ выпуска {key_id} совпадает с общедоступным ключом разработки",
        "server_config": "конфигурация управления запуском на сервере недоступна",
        "end_time": "Планируемое окончание: {value}",
        "bootstrap_fake": "Запуск выпуска заблокирован: вход EOS/Worker и запуск нативного моста не интегрированы с этой тестовой программой запуска с имитацией входа.",
        "bootstrap_legacy": "Запуск выпуска заблокирован: вход EOS/Worker и запуск нативного моста не интегрированы с устаревшей программой запуска.",
        "bootstrap_release": "Запуск выпуска заблокирован после проверки: вход EOS/Worker и запуск нативного моста в этой точке входа ещё не реализованы.",
        "checking_maintenance": "Проверка сервиса и режима обслуживания…",
        "checking_update": "Проверка подписанного манифеста обновления…",
        "verified_plan": "План обновления проверен: файлов — {count}, {mib:.1f} МиБ.",
        "applying": "Применение проверенного обновления…",
        "rechecking": "Повторная проверка сервиса после обновления…",
        "minimum_manifest": "требуется {minimum}, подписанный манифест предлагает {version}",
        "minimum_installed": "требуется {minimum}, проверенная версия — {version}",
        "minimum_only": "требуемая версия клиента — {minimum}",
    },
}


def _text(locale: str, key: str, **values: object) -> str:
    language = locale.upper() if isinstance(locale, str) else "EN"
    table = _TEXT.get(language, _TEXT["EN"])
    return table[key].format(**values).strip()


def _emit_progress(
    callback: Callable[[str], None] | None,
    locale: str,
    key: str,
    **values: object,
) -> None:
    if callback is None:
        return
    try:
        callback(_text(locale, key, **values))
    except Exception:
        # Display plumbing cannot weaken or alter a security decision.
        pass


def release_bootstrap_notice(locale: str, launcher: str) -> str:
    key = {
        "fake": "bootstrap_fake",
        "legacy": "bootstrap_legacy",
        "release": "bootstrap_release",
    }.get(launcher, "bootstrap_release")
    return _text(locale, key)


def _release_configuration(
    config: Config, trusted_keys: dict[str, str]
) -> tuple[str | None, dict[str, str], list[tuple[str, str | None]]]:
    issues: list[tuple[str, str | None]] = []
    normalized: str | None = None
    try:
        normalized = normalize_api_base_url(config.api_base_url)
        parsed = urlsplit(normalized)
        host = (parsed.hostname or "").rstrip(".").lower()
        loopback = host == "localhost"
        if not loopback:
            try:
                loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                pass
        if parsed.scheme != "https" or loopback:
            issues.append(("endpoint", None))
    except ValueError:
        issues.append(("endpoint", None))

    accepted: dict[str, str] = {}
    for key_id, value in trusted_keys.items():
        if not isinstance(key_id, str) or not key_id or not isinstance(value, str):
            issues.append(("key_malformed", None))
            continue
        if not _KEY_RE.fullmatch(value):
            issues.append(("key_hex", key_id))
            continue
        key_bytes = bytes.fromhex(value)
        if key_bytes in _DEVELOPMENT_PUBLIC_KEY_BYTES:
            issues.append(("key_dev", key_id))
            continue
        accepted[key_id] = value.lower()
    if not accepted:
        issues.append(("key_missing", None))
    return normalized, accepted, issues


def _strict_health(
    body: Any, *, expected_native_battles: bool = False,
    public_native: bool = False,
) -> tuple[MaintenanceStatus, str]:
    """Validate the public release-health contract without permissive defaults."""
    if not isinstance(body, dict):
        raise ValueError("health body is not an object")
    if type(public_native) is not bool or public_native and expected_native_battles:
        raise ValueError("conflicting native launch channels")
    expected_fields = {
        "ok", "service", "nativeBattles", "minClientVersion", "maintenance",
    }
    if expected_native_battles:
        expected_fields.add("nativePvpTest")
    if public_native:
        expected_fields.add("nativeProtocol")
    if set(body) != expected_fields:
        raise ValueError("health fields do not match the release contract")
    if body.get("ok") is not True or body.get("service") != "twa-private-control":
        raise ValueError("health identity is invalid")
    if body.get("nativeBattles") is not (expected_native_battles or public_native):
        raise ValueError("nativeBattles does not match the selected launch channel")
    if public_native and body.get("nativeProtocol") != "twa-relay-v1":
        raise ValueError("public native protocol is not supported")
    if expected_native_battles:
        candidate = body.get("nativePvpTest")
        if not isinstance(candidate, dict) or set(candidate) != {
            "enabled", "state", "reason", "scope", "nativeWireEnabled",
            "gameplayVerified",
        }:
            raise ValueError("nativePvpTest fields do not match the internal contract")
        if candidate.get("enabled") is not True:
            raise ValueError("nativePvpTest is not enabled")
        if candidate.get("state") not in {"candidate", "verified"}:
            raise ValueError("nativePvpTest state is invalid")
        if candidate.get("scope") not in {"health_matchmaking_only", "native_wire"}:
            raise ValueError("nativePvpTest scope is invalid")
        if not isinstance(candidate.get("reason"), str):
            raise ValueError("nativePvpTest reason is invalid")
        if type(candidate.get("nativeWireEnabled")) is not bool:
            raise ValueError("nativePvpTest nativeWireEnabled is invalid")
        if type(candidate.get("gameplayVerified")) is not bool:
            raise ValueError("nativePvpTest gameplayVerified is invalid")
        if candidate.get("state") == "verified" and not (
            candidate["nativeWireEnabled"] and candidate["gameplayVerified"]
        ):
            raise ValueError("verified nativePvpTest is incomplete")
    minimum = body.get("minClientVersion")
    if not isinstance(minimum, str):
        raise ValueError("minClientVersion is missing")
    try:
        semver_tuple(minimum)
    except ManifestError as exc:
        raise ValueError("minClientVersion is not valid semver") from exc
    maintenance = body.get("maintenance")
    if not isinstance(maintenance, dict):
        raise ValueError("maintenance is not an object")
    if set(maintenance) != {"enabled", "message", "endsAt"}:
        raise ValueError("maintenance fields do not match the release contract")
    enabled = maintenance.get("enabled")
    message = maintenance.get("message")
    ends_at = maintenance.get("endsAt")
    if (
        not isinstance(enabled, bool)
        or not isinstance(message, str)
        or len(message) > 500
        or any(ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in message)
    ):
        raise ValueError("maintenance fields have invalid types")
    if ends_at is not None and (
        not isinstance(ends_at, int)
        or isinstance(ends_at, bool)
        or not 0 <= ends_at <= 4_102_444_800
    ):
        raise ValueError("maintenance endsAt has an invalid type")
    return MaintenanceStatus(enabled=enabled, message=message, ends_at=ends_at), minimum


def _maintenance_detail(status: MaintenanceStatus, locale: str) -> str:
    details = status.message.strip()
    if status.ends_at is not None:
        try:
            rendered = datetime.fromtimestamp(status.ends_at).astimezone().strftime(
                "%Y-%m-%d %H:%M:%S %Z"
            )
        except (OSError, OverflowError, ValueError):
            rendered = str(status.ends_at)
        ending = _text(locale, "end_time", value=rendered)
        details = (details + " " if details else "") + ending
    return details


def _strict_status_from_error(exc: MaintenanceError) -> MaintenanceStatus:
    status = status_from_error(exc)
    if (
        not isinstance(status.message, str)
        or len(status.message) > 500
        or any(ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in status.message)
    ):
        raise ValueError("maintenance error message is invalid")
    if status.ends_at is not None and (
        not isinstance(status.ends_at, int)
        or isinstance(status.ends_at, bool)
        or not 0 <= status.ends_at <= 4_102_444_800
    ):
        raise ValueError("maintenance error endsAt is invalid")
    return status


def check_startup(
    config: Config,
    policy: str,
    *,
    locale: str = "EN",
    trusted_keys: dict[str, str] | None = None,
    api_factory: Callable[..., ApiClient] = ApiClient,
    check_update: Callable[..., UpdatePlan] = updater_check,
    apply_update: Callable[..., dict[str, object]] = updater_apply,
    network_budget_seconds: float = STARTUP_NETWORK_BUDGET_SECONDS,
    progress: Callable[[str], None] | None = None,
    expected_native_battles: bool = False,
    public_native: bool = False,
) -> StartupResult:
    """Run the selected startup policy; release never degrades to development."""
    if policy == "development":
        return StartupResult(
            StartupCode.DEVELOPMENT, True, _text(locale, "development"), config.client_version
        )
    if policy != "release":
        return StartupResult(
            StartupCode.CONFIGURATION,
            False,
            _text(locale, "configuration", detail=f"unknown policy {policy!r}"),
        )

    release_keys = RELEASE_TRUSTED_KEYS if trusted_keys is None else trusted_keys
    endpoint, accepted_keys, issues = _release_configuration(config, release_keys)
    if issues or endpoint is None:
        localized_issues = [
            _text(locale, code, key_id=repr(value) if value is not None else "")
            for code, value in issues
        ]
        return StartupResult(
            StartupCode.CONFIGURATION,
            False,
            _text(
                locale,
                "configuration",
                detail="; ".join(dict.fromkeys(localized_issues)),
            ),
        )

    started = time.monotonic()

    def new_api(version: str, *, update: bool = False) -> ApiClient:
        from .trusted_keys import PUBLIC_DOWNLOAD_ORIGIN
        remaining = network_budget_seconds - (time.monotonic() - started)
        if remaining <= 0:
            raise NetworkError("startup network deadline exceeded")
        return api_factory(
            PUBLIC_DOWNLOAD_ORIGIN if update and public_native else endpoint,
            version,
            timeout=STARTUP_REQUEST_TIMEOUT_SECONDS,
            strict_download_transport=True,
            total_timeout=remaining,
        )

    minimum_required: str | None = None
    try:
        api = new_api(config.client_version)
        _emit_progress(progress, locale, "checking_maintenance")
        try:
            status, minimum_required = _strict_health(
                api.health(), expected_native_battles=expected_native_battles, public_native=public_native,
            )
        except MaintenanceError as exc:
            status = _strict_status_from_error(exc)
        except UpdateRequiredError as exc:
            # Never follow the server-provided manifestUrl. updater.check below
            # uses the configured channel's fixed API route and verifies it.
            minimum_required = exc.min_version
            try:
                semver_tuple(minimum_required)
            except ManifestError as version_error:
                raise ValueError("update_required minimum is not valid semver") from version_error
            status = MaintenanceStatus(False, "", None)
        if status.enabled:
            return StartupResult(
                StartupCode.MAINTENANCE,
                False,
                _text(locale, "maintenance", detail=_maintenance_detail(status, locale)),
            )

        _emit_progress(progress, locale, "checking_update")
        update_api = new_api(config.client_version, update=True) if public_native else api
        plan = check_update(config, update_api, trusted_keys=accepted_keys)
        _emit_progress(
            progress,
            locale,
            "verified_plan",
            count=len(plan.files),
            mib=plan.total_bytes / (1024 * 1024),
        )
        if minimum_required is not None and semver_tuple(plan.version) < semver_tuple(minimum_required):
            return StartupResult(
                StartupCode.UPDATE_REQUIRED,
                False,
                _text(
                    locale,
                    "update_required",
                    detail=_text(
                        locale,
                        "minimum_manifest",
                        minimum=minimum_required,
                        version=plan.version,
                    ),
                ),
                plan.current_version,
            )

        # Always pass the verified plan through apply(), including an equal
        # version with zero changed files. updater.apply owns migration and
        # durable recording of the canonical downgrade floor.
        _emit_progress(progress, locale, "applying")
        apply_result = apply_update(config, update_api, plan)
        if (
            not isinstance(apply_result, dict)
            or apply_result.get("ok") is not True
            or apply_result.get("version") != plan.version
        ):
            raise UpdaterError("updater did not confirm the verified manifest version")

        # Always check health again after hashing/apply: maintenance and the
        # configured minimum can change while a large copied client is read.
        _emit_progress(progress, locale, "rechecking")
        post_api = new_api(plan.version)
        post_status, post_minimum = _strict_health(
            post_api.health(), expected_native_battles=expected_native_battles, public_native=public_native,
        )
        if post_status.enabled:
            return StartupResult(
                StartupCode.MAINTENANCE,
                False,
                _text(locale, "maintenance", detail=_maintenance_detail(post_status, locale)),
                plan.version,
                bool(apply_result.get("applied")),
            )
        if semver_tuple(plan.version) < semver_tuple(post_minimum):
            return StartupResult(
                StartupCode.UPDATE_REQUIRED,
                False,
                _text(
                    locale,
                    "update_required",
                    detail=_text(
                        locale,
                        "minimum_installed",
                        minimum=post_minimum,
                        version=plan.version,
                    ),
                ),
                plan.version,
                bool(apply_result.get("applied")),
            )
        return StartupResult(
            StartupCode.READY,
            True,
            _text(locale, "ready", version=plan.version),
            plan.version,
            bool(apply_result.get("applied")),
        )
    except MaintenanceError as exc:
        try:
            status = _strict_status_from_error(exc)
        except ValueError:
            return StartupResult(
                StartupCode.INVALID_RESPONSE, False, _text(locale, "invalid_response")
            )
        return StartupResult(
            StartupCode.MAINTENANCE,
            False,
            _text(locale, "maintenance", detail=_maintenance_detail(status, locale)),
        )
    except UpdateRequiredError as exc:
        return StartupResult(
            StartupCode.UPDATE_REQUIRED,
            False,
            _text(
                locale,
                "update_required",
                detail=_text(locale, "minimum_only", minimum=exc.min_version),
            ),
        )
    except (NetworkError, TimeoutError):
        return StartupResult(StartupCode.OFFLINE, False, _text(locale, "offline"))
    except (ValueError, TypeError):
        return StartupResult(
            StartupCode.INVALID_RESPONSE, False, _text(locale, "invalid_response")
        )
    except ManifestError:
        return StartupResult(
            StartupCode.UNTRUSTED_UPDATE, False, _text(locale, "untrusted_update")
        )
    except ArenaRunningError as exc:
        return StartupResult(
            StartupCode.UPDATE_FAILED,
            False,
            _text(locale, "update_failed", detail=str(exc)),
        )
    except ApiError as exc:
        if exc.code == "startup_configuration_unavailable":
            return StartupResult(
                StartupCode.CONFIGURATION,
                False,
                _text(
                    locale,
                    "configuration",
                    detail=_text(locale, "server_config"),
                ),
            )
        return StartupResult(
            StartupCode.UPDATE_FAILED,
            False,
            _text(locale, "update_failed", detail=str(exc)),
        )
    except (UpdaterError, OSError) as exc:
        return StartupResult(
            StartupCode.UPDATE_FAILED,
            False,
            _text(locale, "update_failed", detail=str(exc)),
        )


def startup_exit_code(result: StartupResult) -> int:
    return 0 if result.allow_launch else (2 if result.code == StartupCode.CONFIGURATION else 1)


__all__ = [
    "StartupCode",
    "StartupResult",
    "check_startup",
    "release_bootstrap_notice",
    "startup_exit_code",
]
