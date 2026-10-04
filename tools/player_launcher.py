"""Epic-only player launcher. The operator supplies player-release.json."""
from __future__ import annotations

import argparse
import json
import queue
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from companion.diagnostics import DiagnosticLog, open_log_folder
DIAGNOSTICS = None


def diagnostics(*, state_dir=None):
    global DIAGNOSTICS
    if state_dir is not None and DIAGNOSTICS is not None:
        expected = Path(state_dir).absolute() / "diagnostics"
        if DIAGNOSTICS.directory is None or DIAGNOSTICS.directory.parent != expected:
            DIAGNOSTICS.close()
            DIAGNOSTICS = None
    if DIAGNOSTICS is None:
        DIAGNOSTICS = DiagnosticLog("worker" if "--action" in sys.argv else "launcher",
            repo_root=ROOT, state_dir=state_dir)
        DIAGNOSTICS.install_exception_hooks()
    return DIAGNOSTICS

LANGUAGES = {"English": "EN", "日本語": "JA", "Русский": "RU"}
TEXT = {
    "JA": {
        "invalid_login_response": "ゲームサーバーからのログイン応答を確認できませんでした。再試行し、続く場合はエラーログをお知らせください。",
        "invalid_session_token_response": "ゲームサーバーからのログイン応答を確認できませんでした。再試行し、続く場合はエラーログをお知らせください。",
        "invalid_session_expiry_response": "ログインの有効期限を確認できませんでした。Windowsの日時を同期して再試行し、続く場合はエラーログをお知らせください。",
        "worker_identity_mismatch": "Epicアカウントとゲームサーバーの応答が一致しません。再ログインし、続く場合はエラーログをお知らせください。",
        "title": "Epicでログインして、戦場へ。", "name": "プレイヤーネーム（初回登録時に入力）",
        "login": "Epicでログイン", "account": "ログイン状態を確認", "rename": "名前を保存",
        "update": "更新を確認して適用", "launch": "格納庫を開く", "working": "処理しています…",
        "playing": "ゲーム実行中。終了するとこの画面に戻ります。", "finished": "ゲームが終了しました。",
        "ready": "ログイン状態を確認して、次の操作をご案内します。", "ok": "完了しました。",
        "game_launch_failed": "ゲームを起動できませんでした。「更新を確認」を実行し、もう一度ゲームを開始してください。改善しない場合は運営へお知らせください。",
        "loopback_bind_failed": "ゲームに必要なローカル通信ポートを開けません。他のアプリの使用中、またはWindowsの制限が考えられます。使用中のアプリが分かる場合は終了して再試行し、不明な場合はエラーログを運営へお送りください。",
        "configuration": "配布設定が未完了です。運営に確認してください。",
        "login_required": "ログインが必要です。Epicでログインし直してください。",
        "auth_unavailable": "ログイン状態を確認できませんでした。保存済みログインは保持しています。時間をおいて再試行してください。",
        "eos_auth_login": "Epicアカウントへのログインに失敗しました（Epic結果コード: {result}）。名前の重複によるエラーではありません。このコードを運営へお知らせください。",
        "eos_auth_token": "Epicのログイン証明を取得できませんでした（Epic結果コード: {result}）。このコードを運営へお知らせください。",
        "eos_connect_login": "Epicの認証後、ゲーム用IDへの接続に失敗しました（Epic結果コード: {result}）。名前の重複によるエラーではありません。このコードを運営へお知らせください。",
        "eos_connect_create": "Epicの認証後、初回のゲーム用IDを作成できませんでした（Epic結果コード: {result}）。名前の重複によるエラーではありません。このコードを運営へお知らせください。",
        "eos_connect_token": "ゲーム用IDのログイン証明を取得できませんでした（Epic結果コード: {result}）。このコードを運営へお知らせください。",
        "invalid_display_name": "プレイヤーネームは1～32文字で入力してください。",
        "player_name_required": "初回登録にはプレイヤーネームが必要です。名前を設定してログインを完了してください。",
        "registration_closed": "現在、新規登録の受付を停止しています。",
        "invitation_required": "この接続先では一般登録がまだ有効になっていません。",
        "account_disabled": "このアカウントではログインできません。運営にお問い合わせください。",
        "maintenance": "現在メンテナンス中です。", "offline": "サービスへ接続できませんでした。",
        "failed": "処理を完了できませんでした。時間をおいて再試行してください。",
        "busy_close": "処理中です。ゲームを終了するか、処理が完了するまでお待ちください。",
        "language_applied": "ランチャーとゲームの言語を変更しました。",
        "language_pending": "言語を保存しました。ゲームには次回起動時に反映します。",
        "language_install": "言語を保存しました。ゲーム導入後の起動時に反映します。",
        "language_failed": "ゲームの言語を変更できませんでした。言語データとゲームの終了を確認してください。",
        "language_save_failed": "言語を保存できませんでした。保存先を確認して再試行してください。",
        "restarting": "ランチャーを更新して再起動します…",
        "updated": "ランチャーを更新しました。",
        "restored": "更新を完了できなかったため、前のランチャーへ戻しました。",
        "launcher_update_failed": "ランチャーの更新を確認・適用できませんでした。時間をおいて再試行してください。",
        "launcher_update_required": "ランチャーの更新が必要です。「更新を確認して適用」を実行し、ランチャーを再起動してください。",
        "runtime_dependency_missing": "Epic認証に必要な起動部品が見つかりません。下のMicrosoft公式案内からVisual C++ v14（x64）を導入し、もう一度ログインしてください。",
        "runtime_invalid": "起動部品を読み込めませんでした。配布クライアントを展開し直してください。改善しない場合は運営に確認してください。",
        "runtime_help": "Microsoft公式の起動部品案内を開く",
        "loopback_dns_missing": "このPCではゲームのローカルサービス名（revival-*.localhost）を解決できないため、このままではArenaがエラー0xf003で停止します。下のボタンから、必要なローカル設定をWindowsのhostsファイルに追加できます（管理者の承認が必要です）。",
        "loopback_tls_failed": "ゲームのローカル通信用ファイルを修復できませんでした。保存先の書き込み権限と空き容量を確認して再試行してください。改善しない場合はログを運営に送ってください。",
        "loopback_repair": "自動で修正（管理者）",
        "loopback_repair_confirm": "{hosts} に「TWA Revival loopback names」と記した区画を作り、その中に revival-*.localhost を 127.0.0.1（このPC）へ対応付ける12行を追加します。それ以外は変更しません。\n\nWindowsが管理者の承認を求めます。この区画は後から削除すれば元に戻せます。\n\n続行しますか？",
        "loopback_repair_done": "修正しました。もう一度「ゲームを開始」を押してください。",
        "loopback_repair_cancelled": "管理者の承認がキャンセルされました。何も変更していません。",
        "loopback_repair_unresolved": "設定は追加しましたが、Windowsがまだ名前を解決できません。Windowsを再起動するか、VPNやセキュリティソフトを確認してから再試行してください。",
        "loopback_repair_failed": "Windowsで自動修正を完了できませんでした。詳細はエラーログを確認してください。ログフォルダーに loopback-hosts.txt があれば、その行を管理者として {hosts} に追加できます。",
        "loopback_repair_unsupported": "hostsファイル（{hosts}）に、自動修正では安全に編集できない内容（非常に大きな一覧、特殊な文字コード、壊れたTWAの区画など）が含まれています。追加する行をログフォルダーの loopback-hosts.txt に保存しました（下のボタンで開けます）。管理者として手動で追加してください。",
        "loopback_repair_permission": "Windowsがhostsファイルへの書き込みを拒否しました。ファイルの権限やセキュリティソフトの設定を確認してください。ログフォルダーに loopback-hosts.txt があれば、その行を管理者として {hosts} に追加できます。",
        "loopback_repair_timeout": "管理者の修正処理が時間内に終了しませんでした。Windowsの管理者確認が開いていないか確認してください。ログフォルダーに loopback-hosts.txt があれば、その行を管理者として {hosts} に追加できます。",
    },
    "EN": {
        "invalid_login_response": "Could not verify the game server sign-in response. Try again. If it still fails, please share your error logs.",
        "invalid_session_token_response": "Could not verify the game server sign-in response. Try again. If it still fails, please share your error logs.",
        "invalid_session_expiry_response": "Could not verify the sign-in expiry time. Sync the date and time in Windows Settings and try again. If it still fails, please share your error logs.",
        "worker_identity_mismatch": "The game server response does not match your Epic account. Sign in again. If it still fails, please share your error logs.",
        "title": "Sign in with Epic. Enter the battlefield.", "name": "Player name (for first registration)",
        "login": "Sign in with Epic", "account": "Check sign-in", "rename": "Save name",
        "update": "Check and install updates", "launch": "Open hangar", "working": "Working…",
        "playing": "Game running. This window will be ready when it exits.", "finished": "Game finished.",
        "ready": "Checking sign-in to show your next step.", "ok": "Completed.",
        "game_launch_failed": "Could not start the game. Check updates and try again. If this continues, contact the operator.",
        "loopback_bind_failed": "A required local port is unavailable. Another app may be using it, or Windows may have reserved it. Close the conflicting app if you recognize it, then retry. Otherwise, send your error logs to support.",
        "configuration": "The release is not configured. Please contact the operator.",
        "login_required": "Please sign in with Epic again.",
        "auth_unavailable": "Could not verify sign-in. Your saved login has been kept. Please try again shortly.",
        "eos_auth_login": "Epic account sign-in failed (Epic result: {result}). This is not a duplicate player name. Share this code with support.",
        "eos_auth_token": "Could not obtain Epic sign-in proof (Epic result: {result}). Share this code with support.",
        "eos_connect_login": "Epic authentication finished, but connecting to your game ID failed (Epic result: {result}). This is not a duplicate name. Share this code with support.",
        "eos_connect_create": "Epic authentication finished, but creating your first game ID failed (Epic result: {result}). This is not a duplicate name. Share this code with support.",
        "eos_connect_token": "Could not obtain game ID sign-in proof (Epic result: {result}). Share this code with support.",
        "invalid_display_name": "Enter a player name with 1–32 characters.",
        "player_name_required": "First registration needs a player name. Set your name to finish signing in.",
        "registration_closed": "New registrations are currently closed.",
        "invitation_required": "Open registration is not enabled on this service yet.",
        "account_disabled": "This account cannot sign in. Please contact the operator.",
        "maintenance": "The service is under maintenance.", "offline": "Could not connect to the service.",
        "failed": "Could not complete the operation. Please try again later.",
        "busy_close": "Please close the game or wait for the current operation to finish.",
        "language_applied": "Launcher and game language changed.",
        "language_pending": "Language saved. The game will use it at the next launch.",
        "language_install": "Language saved. It will apply after the game is installed.",
        "language_failed": "Could not change the game language. Check the language files and close the game.",
        "language_save_failed": "Could not save the language. Check the save location and try again.",
        "restarting": "Updating and restarting the launcher…",
        "updated": "Launcher updated.",
        "restored": "The update could not finish. The previous launcher was restored.",
        "launcher_update_failed": "Could not check or install the launcher update. Please try again later.",
        "launcher_update_required": "A launcher update is required. Check for updates, install it, then restart the launcher.",
        "runtime_dependency_missing": "A component required for Epic sign-in is missing. Use the Microsoft guide below to install Visual C++ v14 (x64), then sign in again.",
        "runtime_invalid": "Could not load the runtime. Extract a fresh copy of the client. If this continues, contact the operator.",
        "runtime_help": "Open the official Microsoft runtime guide",
        "loopback_dns_missing": "This PC cannot find the game's local service names (revival-*.localhost), so Arena would stop with error 0xf003. Use the button below to add the required local entries to the Windows hosts file (administrator approval required).",
        "loopback_tls_failed": "Could not repair the game's local connection files. Check that the installation folder is writable and the disk has free space, then try again. If this continues, send your logs to the operator.",
        "loopback_repair": "Fix automatically (administrator)",
        "loopback_repair_confirm": "This adds 12 lines that map revival-*.localhost to 127.0.0.1 (this PC), inside a block marked \"TWA Revival loopback names\" in {hosts}. Nothing else is changed.\n\nWindows will ask for administrator approval. You can undo this later by deleting that block.\n\nContinue?",
        "loopback_repair_done": "Fixed. Press Start game again.",
        "loopback_repair_cancelled": "Administrator approval was cancelled. Nothing was changed.",
        "loopback_repair_unresolved": "The entries were added, but Windows still cannot find the names. Restart Windows, or check VPN and security software, then try again.",
        "loopback_repair_failed": "Windows could not complete the automatic repair. Check the error logs for details. If loopback-hosts.txt is in the log folder, add its lines to {hosts} as administrator.",
        "loopback_repair_unsupported": "The hosts file at {hosts} contains content the automatic fix will not edit safely (for example a very large list, an unusual encoding or a damaged TWA block). The exact lines were saved as loopback-hosts.txt in the log folder (open it with the button below). Add them manually as administrator.",
        "loopback_repair_permission": "Windows denied writing to the hosts file. Check file permissions and security software settings. If loopback-hosts.txt is in the log folder, add its lines to {hosts} as administrator.",
        "loopback_repair_timeout": "The administrator repair did not finish in time. Check for an open Windows administrator prompt. If loopback-hosts.txt is in the log folder, add its lines to {hosts} as administrator.",
    },
    "RU": {
        "invalid_login_response": "Не удалось проверить ответ игрового сервера при входе. Повторите попытку. Если ошибка повторится, отправьте журналы ошибок.",
        "invalid_session_token_response": "Не удалось проверить ответ игрового сервера при входе. Повторите попытку. Если ошибка повторится, отправьте журналы ошибок.",
        "invalid_session_expiry_response": "Не удалось проверить срок действия входа. Синхронизируйте дату и время в параметрах Windows и повторите попытку. Если ошибка повторится, отправьте журналы ошибок.",
        "worker_identity_mismatch": "Ответ игрового сервера не соответствует вашей учётной записи Epic. Войдите снова. Если ошибка повторится, отправьте журналы ошибок.",
        "title": "Войдите через Epic и выходите на поле боя.", "name": "Имя игрока (для первой регистрации)",
        "login": "Войти через Epic", "account": "Проверить вход", "rename": "Сохранить имя",
        "update": "Проверить и установить обновления", "launch": "Открыть ангар", "working": "Выполняется…",
        "playing": "Игра запущена. После выхода вы вернётесь сюда.", "finished": "Игра завершена.",
        "ready": "Проверяем вход, чтобы показать следующий шаг.", "ok": "Готово.",
        "game_launch_failed": "Не удалось запустить игру. Проверьте обновления и повторите запуск. Если ошибка повторится, обратитесь к оператору.",
        "loopback_bind_failed": "Нужный локальный порт недоступен: он может использоваться другим приложением или быть зарезервирован Windows. Если вы знаете приложение, закройте его и повторите попытку. Иначе отправьте журналы ошибок оператору.",
        "configuration": "Выпуск не настроен. Обратитесь к оператору.",
        "login_required": "Войдите через Epic ещё раз.",
        "auth_unavailable": "Не удалось проверить вход. Сохранённый вход не удалён. Повторите попытку позже.",
        "eos_auth_login": "Не удалось войти в Epic (код Epic: {result}). Совпадение имени игрока не является причиной. Сообщите код поддержке.",
        "eos_auth_token": "Не удалось получить подтверждение входа Epic (код Epic: {result}). Сообщите код поддержке.",
        "eos_connect_login": "Вход в Epic выполнен, но подключение игрового ID не удалось (код Epic: {result}). Причина не в совпадении имени. Сообщите код поддержке.",
        "eos_connect_create": "Вход в Epic выполнен, но первый игровой ID не создан (код Epic: {result}). Причина не в совпадении имени. Сообщите код поддержке.",
        "eos_connect_token": "Не удалось получить подтверждение игрового ID (код Epic: {result}). Сообщите код поддержке.",
        "invalid_display_name": "Введите имя игрока длиной от 1 до 32 символов.",
        "player_name_required": "Для регистрации нужно имя игрока. Укажите его, чтобы завершить вход.",
        "registration_closed": "Регистрация новых игроков временно закрыта.",
        "invitation_required": "Открытая регистрация на этом сервисе ещё не включена.",
        "account_disabled": "Вход для этой учётной записи недоступен. Обратитесь к оператору.",
        "maintenance": "Сервис на техническом обслуживании.", "offline": "Не удалось подключиться к сервису.",
        "failed": "Не удалось завершить операцию. Повторите попытку позже.",
        "busy_close": "Закройте игру или дождитесь завершения текущей операции.",
        "language_applied": "Язык лаунчера и игры изменён.",
        "language_pending": "Язык сохранён. Он применится при следующем запуске игры.",
        "language_install": "Язык сохранён. Он применится после установки игры.",
        "language_failed": "Не удалось изменить язык игры. Проверьте языковые файлы и закройте игру.",
        "language_save_failed": "Не удалось сохранить язык. Проверьте папку сохранения и повторите попытку.",
        "restarting": "Обновление и перезапуск лаунчера…",
        "updated": "Лаунчер обновлён.",
        "restored": "Обновление не завершено. Восстановлена предыдущая версия лаунчера.",
        "launcher_update_failed": "Не удалось проверить или установить обновление лаунчера. Повторите попытку позже.",
        "launcher_update_required": "Требуется обновление лаунчера. Установите обновление и перезапустите лаунчер.",
        "runtime_dependency_missing": "Отсутствует компонент для входа через Epic. Установите Visual C++ v14 (x64) по инструкции Microsoft ниже, затем войдите снова.",
        "runtime_invalid": "Не удалось загрузить компоненты запуска. Распакуйте клиент заново. Если ошибка повторится, обратитесь к оператору.",
        "runtime_help": "Открыть официальную инструкцию Microsoft",
        "loopback_dns_missing": "Этот компьютер не находит локальные имена служб игры (revival-*.localhost), поэтому Arena остановится с ошибкой 0xf003. Кнопка ниже добавит нужные локальные записи в файл hosts Windows (требуется подтверждение администратора).",
        "loopback_tls_failed": "Не удалось восстановить файлы локального подключения игры. Проверьте доступ на запись в папку игры и свободное место на диске, затем повторите попытку. Если ошибка повторяется, отправьте журналы оператору.",
        "loopback_repair": "Исправить автоматически (администратор)",
        "loopback_repair_confirm": "В файл {hosts} будет добавлено 12 строк, связывающих revival-*.localhost с 127.0.0.1 (этот компьютер), внутри блока с пометкой «TWA Revival loopback names». Больше ничего не изменится.\n\nWindows запросит подтверждение администратора. Позже это можно отменить, удалив этот блок.\n\nПродолжить?",
        "loopback_repair_done": "Исправлено. Снова нажмите «Начать игру».",
        "loopback_repair_cancelled": "Подтверждение администратора отменено. Ничего не изменено.",
        "loopback_repair_unresolved": "Записи добавлены, но Windows по-прежнему не находит эти имена. Перезагрузите Windows или проверьте VPN и защитные программы, затем повторите попытку.",
        "loopback_repair_failed": "Windows не удалось завершить автоматическое исправление. Проверьте журналы ошибок. Если в папке журналов есть loopback-hosts.txt, добавьте его строки в {hosts} от имени администратора.",
        "loopback_repair_unsupported": "Файл hosts ({hosts}) содержит данные, которые автоматическое исправление не может безопасно изменить (например, очень большой список, необычная кодировка или повреждённый блок TWA). Нужные строки сохранены в файл loopback-hosts.txt в папке журналов (откройте её кнопкой ниже). Добавьте их вручную от имени администратора.",
        "loopback_repair_permission": "Windows отказала в записи в файл hosts. Проверьте права доступа и настройки защитных программ. Если в папке журналов есть loopback-hosts.txt, добавьте его строки в {hosts} от имени администратора.",
        "loopback_repair_timeout": "Исправление от имени администратора не завершилось вовремя. Проверьте, не открыт ли запрос Windows на повышение прав. Если в папке журналов есть loopback-hosts.txt, добавьте его строки в {hosts} от имени администратора.",
    },
}
ACTIONS = ("login", "account", "rename", "update", "launch")
WORKER_ACTIONS = (*ACTIONS, "language")
EOS_LOGIN_OPERATIONS = frozenset(('auth_login', 'auth_token', 'connect_login', 'connect_create', 'connect_token'))


def safe_eos_result(code, value):
    return (code in {'eos_' + operation for operation in EOS_LOGIN_OPERATIONS}
            and type(value) is int and 0 <= value <= 2147483647)


def safe_loopback_bind(value):
    if (not isinstance(value, dict)
            or set(value) != {'transport', 'family', 'port', 'windowsError'}
            or value.get('transport') not in ('tcp', 'udp')
            or value.get('family') not in ('ipv4', 'ipv6')
            or type(value.get('port')) is not int or not 1 <= value['port'] <= 65535):
        return None
    number = value['windowsError']
    if number is not None and (type(number) is not int or not 0 <= number <= 0xffffffff):
        return None
    return dict(value)


def loopback_failure_message(locale, value):
    message = TEXT[locale]['loopback_bind_failed']
    details = safe_loopback_bind(value)
    if details is None:
        return message
    endpoint = '{} {} ({})'.format(details['transport'].upper(), details['port'],
                                  'IPv4' if details['family'] == 'ipv4' else 'IPv6')
    if details['windowsError'] is not None:
        endpoint += ' / Windows: {}'.format(details['windowsError'])
    return endpoint + '\n' + message


def open_runtime_help():
    """Open vendor instructions only after an explicit player click."""
    import webbrowser
    return webbrowser.open('https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist')


# Notices after which the hosts repair is offered (again).
LOOPBACK_REPAIR_OFFERED = frozenset(("loopback_dns_missing", "loopback_repair_cancelled",
    "loopback_repair_unresolved", "loopback_repair_failed", "loopback_repair_unsupported",
    "loopback_repair_permission", "loopback_repair_timeout"))
# Notices whose "{hosts}" is filled with the real path when shown (the confirm dialog too).
HOSTS_PATH_NOTICES = frozenset(("loopback_repair_failed", "loopback_repair_unsupported",
    "loopback_repair_permission", "loopback_repair_timeout"))


def hosts_path_text() -> str:
    # The file the elevated helper writes; Windows is not always on C:.
    try:
        from tools.loopback_certificate import hosts_file_path
        return str(hosts_file_path())
    except Exception:
        return "%SystemRoot%\\System32\\drivers\\etc\\hosts"


def save_loopback_hosts_lines() -> Path | None:
    """Best effort: leave the exact block in the folder the log button opens."""
    try:
        from companion.diagnostics import _safe_directory
        from companion.player_language import player_state_dir
        from tools.loopback_certificate import HOSTS_BLOCK_BEGIN, HOSTS_BLOCK_END, LOOPBACK_HOSTS
        # Resolved like open_log_folder: works even when DiagnosticLog could not start.
        path = _safe_directory(player_state_dir() / "diagnostics") / "loopback-hosts.txt"
        path.unlink(missing_ok=True)  # "x" then never follows a planted link
        with path.open("x", encoding="utf-8", newline="\r\n") as stream:
            stream.write("\n".join((HOSTS_BLOCK_BEGIN, *("127.0.0.1 " + host for host in LOOPBACK_HOSTS),
                HOSTS_BLOCK_END)) + "\n")
        return path
    except Exception:
        return None


def repair_loopback_hosts(owner_hwnd: int = 0) -> str:
    """Worker-thread body, only after explicit player consent; returns a TEXT key."""
    error, outcome = None, None
    try:
        from tools.loopback_certificate import request_elevated_repair, unresolved_loopback_hosts
        # A manual repair or changed resolver may already have fixed the names.
        # Do not request UAC or rewrite a working (possibly read-only) hosts file.
        if not unresolved_loopback_hosts():
            return "loopback_repair_done"
        outcome = request_elevated_repair(ROOT, owner_hwnd=owner_hwnd)
        if outcome == "cancelled":
            code = "loopback_repair_cancelled"
        elif not unresolved_loopback_hosts():
            # Resolution is decisive even when a helper's final status was lost.
            code = "loopback_repair_done"
        else:
            code = {"ok": "loopback_repair_unresolved", "permission": "loopback_repair_permission",
                    "timeout": "loopback_repair_timeout",
                    "unsupported": "loopback_repair_unsupported"}.get(outcome, "loopback_repair_failed")
    except Exception as caught:
        error, code = caught, "loopback_repair_failed"
    if code != "loopback_repair_done":
        if code != "loopback_repair_cancelled":
            save_loopback_hosts_lines()
        diagnostics().event("operation_failed", "repair_hosts", error=error, code=code, crash=False,
            repair_stage=getattr(outcome, 'stage', None), windows_error=getattr(outcome, 'winerror', None),
            helper_exit=getattr(outcome, 'exit_code', None))
    return code


def action_timeout(action: str) -> float | None:
    if action not in WORKER_ACTIONS:
        raise ValueError("unknown action")
    return None if action == "launch" else (1800 if action == "update" else 600)


def run_player_process(action: str, name: str, language: str) -> dict:
    """Drain output to a temporary file; never expose raw native/auth logs."""
    timeout = action_timeout(action)
    python = ROOT / "runtime" / "python.exe"
    command = [str(python if python.is_file() else Path(sys.executable)),
               str(ROOT/'tools/player_launcher.py'), "--action", action, "--language", language]
    # User names travel as JSON stdin, not shell text or an option argument.
    try:
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(command, input=json.dumps({"name": name}).encode("utf-8"),
                cwd=ROOT, stdout=output, stderr=output, timeout=timeout,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            output.seek(0, 2)
            output.seek(max(0, output.tell() - 16384))
            lines = output.read().decode("utf-8", "replace").splitlines()
        for line in reversed(lines):
            if line.startswith("TWA_PLAYER_RESULT "):
                payload = json.loads(line.removeprefix("TWA_PLAYER_RESULT "))
                if (isinstance(payload, dict) and type(payload.get("ok")) is bool
                        and payload["ok"] == (result.returncode == 0)):
                    if payload["ok"] and isinstance(payload.get("data"), dict):
                        return payload
                    code = payload.get("error")
                    if not payload["ok"] and isinstance(code, str) and code in TEXT["EN"]:
                        if safe_eos_result(code, payload.get('eosResult')):
                            return {"ok": False, "error": code, "eosResult": payload['eosResult']}
                        if code.startswith('eos_'):
                            return {"ok": False, "error": "auth_unavailable"}
                        if code == 'loopback_bind_failed':
                            details = safe_loopback_bind(payload.get('loopbackBind'))
                            if details is not None:
                                return {"ok": False, "error": code, "loopbackBind": details}
                        return {"ok": False, "error": code}
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        diagnostics().event("process_failed", action, error=error, code="failed", crash=True)
        return {"ok": False, "error": "failed"}
    diagnostics().event("process_failed", action, exit_code=result.returncode, code="failed", crash=True)
    return {"ok": False, "error": "failed"}


def worker_main(action: str, language: str) -> int:
    from companion.player_release import PlayerReleaseError, PlayerService, load_player_release
    from companion.player_language import apply_player_language
    try:
        value = json.loads(sys.stdin.buffer.read(4096))
        name = value.get("name")
        if not isinstance(name, str):
            raise ValueError("invalid input")
        # Choosing a language also works before Epic/service setup is complete.
        service = None if action == "language" else PlayerService(load_player_release(ROOT))
        public_state = getattr(getattr(service, "config", None), "state_dir", None)
        if isinstance(public_state, Path):
            diagnostics(state_dir=public_state)
        if action == "language":
            data = apply_player_language(ROOT, language)
        elif action == "login":
            data = service.sign_in(name or None)
        elif action == "account":
            data = service.account()
        elif action == "rename":
            if not name.strip():
                raise PlayerReleaseError("invalid_display_name")
            data = service.account(name)
        elif action == "update":
            data = service.update()
        else:
            data = service.launch(language)
        result = {"ok": True, "data": data}
    except Exception as error:
        from companion.api_client import ApiError, NetworkError
        from tools.client_language import ClientLanguageError
        from companion.self_updater import LauncherUpdateError
        from companion.eos.session import EosLoginError, EosTimeoutError
        from companion.player_session import PlayerSessionError
        from companion.native_launch import NativeLaunchError
        code = getattr(error, "code", None)
        if isinstance(error, PlayerReleaseError):
            code = str(error)
        if isinstance(error, NetworkError):
            code = "offline"
        if isinstance(error, ClientLanguageError) or action == "language":
            code = "language_failed"
        if isinstance(error, LauncherUpdateError):
            code = "launcher_update_failed"
        # SDK/network/renewal failures do not prove the saved login expired.
        # Only a definitive rejection or changed login clears the UI identity.
        if isinstance(error, EosLoginError):
            code = "auth_unavailable"
        if isinstance(error, PlayerSessionError):
            code = "login_required" if str(error) in ("login_required", "session_changed") else "auth_unavailable"
        if isinstance(error, ApiError) and error.status == 401:
            code = "login_required"
        if isinstance(error, EosTimeoutError):
            code = "offline"
        if isinstance(error, NativeLaunchError):
            code = ('loopback_bind_failed' if getattr(error, 'code', None) == 'loopback_bind_failed'
                    else 'game_launch_failed')
        if not isinstance(code, str):
            code = "failed"
        if code in {"invalid_release_configuration", "invalid_release_origin", "local_state_unavailable"}:
            code = "configuration"
        result = {"ok": False, "error": code if code in TEXT["EN"] else "failed"}
        if action == 'login' and isinstance(error, EosLoginError):
            operation = getattr(error, 'operation', None)
            native_result = getattr(error, 'result_code', None)
            if isinstance(operation, str) and operation in EOS_LOGIN_OPERATIONS:
                detail_code = 'eos_' + operation
                if safe_eos_result(detail_code, native_result):
                    result = {"ok": False, "error": detail_code, "eosResult": native_result}
        if result['error'] == 'loopback_bind_failed':
            details = safe_loopback_bind({
                'transport': getattr(error, 'bind_transport', None),
                'family': getattr(error, 'bind_family', None),
                'port': getattr(error, 'bind_port', None),
                'windowsError': getattr(error, 'windows_error', None),
            })
            if details is not None:
                result['loopbackBind'] = details
        details = result.get('loopbackBind', {})
        diagnostics().event("operation_failed", action, error=error,
            code=result["error"], eos_result=result.get("eosResult"), crash=True,
            bind_transport=details.get('transport'), bind_family=details.get('family'),
            bind_port=details.get('port'), windows_error=details.get('windowsError'))
    print("TWA_PLAYER_RESULT " + json.dumps(result, ensure_ascii=True), flush=True)
    return 0 if result["ok"] else 1


def _main(*, app=None, locale_override=None) -> int:
    global ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=WORKER_ACTIONS)
    parser.add_argument("--language", choices=("JA", "EN", "RU"))
    parser.add_argument("--startup-probe", action="store_true")
    parser.add_argument("--update-result", choices=("updated", "restored"))
    args = parser.parse_args()
    from companion.player_language import (load_player_language, save_player_language,
        load_player_name_draft, save_player_name_draft)
    locale = locale_override or args.language or load_player_language()
    if args.action:
        return worker_main(args.action, locale)
    import tkinter as tk
    from tkinter import messagebox, ttk
    app = app if app is not None else tk.Tk()
    if not args.startup_probe and not (ROOT/'client/Arena.exe').is_file():
        from tools.player_setup import installation_view
        installed = installation_view(app, ROOT, locale=locale)
        if installed is None:
            app.destroy()
            return 0
        ROOT, selected_language = installed
        from companion.self_updater import launcher_lock
        # Continue inside the SAME Tk window. Future actions and updates use
        # the installed copy, with its own launcher lock and bundled Python.
        with launcher_lock(ROOT):
            return _main(app=app, locale_override=selected_language)
    if args.startup_probe:
        app.withdraw()
    from tools.player_ui import PlayerWindow, button
    language = tk.StringVar(value=next(k for k, v in LANGUAGES.items() if v == locale))
    name, account = tk.StringVar(value=load_player_name_draft()), tk.StringVar()
    pending = queue.Queue()
    state = {"busy": False, "language_pending": False, "locale": locale,
             "eos_result": None, "loopback_bind": None,
             "status": "ready", "kind": "notice", "update_notice": args.update_result,
             "initial_account_pending": True, "initial_account": False,
             "after_language_notice": None}
    def text(key):
        return TEXT[LANGUAGES[language.get()]][key]
    def show(key, kind="notice"):
        state["status"], state["kind"] = key, kind
        message = view.text(key[3:]) if key.startswith("ui:") else text(key)
        if key == 'loopback_bind_failed':
            message = loopback_failure_message(LANGUAGES[language.get()], state['loopback_bind'])
        elif safe_eos_result(key, state['eos_result']):
            message = message.format(result=state['eos_result'])
        elif key in HOSTS_PATH_NOTICES:
            message = message.format(hosts=hosts_path_text())
        view.message(message, kind)
        if key == 'runtime_dependency_missing':
            runtime_help.pack(anchor='w', pady=(9, 0))
        else:
            runtime_help.pack_forget()
        if key in LOOPBACK_REPAIR_OFFERED:
            loopback_fix.pack(anchor='w', pady=(9, 0), before=log_button)
        else:
            loopback_fix.pack_forget()
    def start(action):
        if state["busy"]:
            return
        state["busy"] = True
        state['eos_result'] = None
        state['loopback_bind'] = None
        view.set_busy(action)
        show('ui:' + {'login':'signing_in','launch':'running_hint','update':'updating',
                       'account':'checking_account'}.get(action,'checking'))
        player_name, selected = name.get(), LANGUAGES[language.get()]
        def work():
            try:
                result = run_player_process(action, player_name, selected)
            except Exception as error:
                diagnostics().event("operation_failed", action, error=error, code="failed", crash=True)
                result = {"ok": False, "error": "failed"}
            pending.put((action, result))
        threading.Thread(target=work, daemon=True).start()
    try:
        version=(ROOT/'companion/VERSION').read_text(encoding='ascii').strip()
    except OSError:
        version='—'
    def begin_account_switch():
        from companion.player_release import PlayerService, load_player_release
        PlayerService(load_player_release(ROOT)).begin_account_switch()
        save_player_name_draft('')
    view=PlayerWindow(app,language,name,account,locale=locale,version=version,action=start,
        load_name_draft=load_player_name_draft,save_name_draft=save_player_name_draft,
        begin_account_switch=begin_account_switch)
    def callback_error(kind, value, traceback):
        diagnostics().event("python_unhandled", "ui_callback", error=value, crash=True)
        show("failed", "error")
    app.report_callback_exception = callback_error
    if not args.startup_probe:
        from companion.player_release import PlayerReleaseError, PlayerService, load_player_release
        try:
            saved = PlayerService(load_player_release(ROOT)).remembered_account()
        except (OSError, PlayerReleaseError):
            saved = None
        if saved is not None:
            account.set(saved['displayName'])
            # A remembered display name does not authorize an expired/revoked login.
            view.authenticated = None
    runtime_help=button(view.notice,command=open_runtime_help)
    def repair_loopback():
        if state["busy"]:
            return
        # The hosts file is changed only after this consent AND the Windows UAC prompt.
        confirm = text("loopback_repair_confirm").format(hosts=hosts_path_text())
        if not messagebox.askyesno("TWA Revival", confirm, icon="warning", parent=app) or state["busy"]:
            return
        try:
            hwnd = int(app.wm_frame(), 16)  # Tk thread only; owns the UAC prompt
        except Exception:
            hwnd = 0
        state["busy"] = True
        view.set_busy("repair_hosts")
        show("ui:checking")
        def work():
            try:
                code = repair_loopback_hosts(hwnd)
            except Exception:
                code = "loopback_repair_failed"
            pending.put(("repair_hosts", {"ok": code == "loopback_repair_done", "code": code}))
        threading.Thread(target=work, daemon=True).start()
    loopback_fix=button(view.notice,command=repair_loopback)
    def open_logs():
        if not open_log_folder():
            diagnostics().event("operation_failed", "open_logs", code="failed", crash=True)
            show("failed", "error")
    log_button=button(view.notice,command=open_logs)
    log_button.pack(anchor='w',pady=(9,0))
    def localize(event=None):
        selected = LANGUAGES[language.get()]
        if event is not None:
            try:
                save_player_language(selected)
            except OSError:
                language.set(next(k for k, v in LANGUAGES.items() if v == state["locale"]))
                show("language_save_failed", "error")
                return
            state["locale"] = selected
            state["language_pending"] = True
        view.localize(selected)
        runtime_help.configure(text=text('runtime_help'))
        loopback_fix.configure(text=text('loopback_repair'))
        log_button.configure(text={"JA":"エラー・クラッシュログのフォルダーを開く",
            "EN":"Open error and crash logs folder",
            "RU":"Открыть папку журналов ошибок и сбоев"}[selected])
        show(state["status"],state["kind"])
        if state["language_pending"] and not state["busy"]:
            state["language_pending"] = False
            start("language")
    def poll():
        try:
            action, result = pending.get_nowait()
        except queue.Empty:
            pass
        else:
            if action == "restart" and result["ok"]:
                app.destroy()
                return
            if result["ok"] and result.get("data", {}).get("restartRequired"):
                state["busy"] = True
                show("restarting")
                transaction = result["data"].get("transaction")
                def restart():
                    from companion.self_updater import schedule_restart
                    try:
                        schedule_restart(ROOT, transaction)
                        notice = {"ok": True}
                    except Exception as error:
                        diagnostics().event("operation_failed", "restart", error=error,
                            code="launcher_update_failed", crash=True)
                        notice = {"ok": False, "error": "launcher_update_failed"}
                    pending.put(("restart", notice))
                threading.Thread(target=restart, daemon=True).start()
                app.after(100, poll)
                return
            state["busy"] = False
            view.set_busy()
            if action == "repair_hosts":
                # Own copy; the generic success mapping below would read "ui:notice".
                show(result["code"], "success" if result["ok"] else "error")
            elif result["ok"]:
                shown = result.get("data", {}).get("displayName")
                if isinstance(shown, str):
                    account.set(shown)
                    view.authenticated=True
                    view.refresh_state()
                if action == "language":
                    if state["after_language_notice"]:
                        key=state["after_language_notice"]
                        state["after_language_notice"]=None
                        show(key,"success")
                    elif state["initial_account_pending"]:
                        state["initial_account_pending"]=False
                        state["initial_account"]=True
                        start("account")
                    else:
                        data=result.get("data",{})
                        show("language_applied" if data.get("applied") else "language_pending","success")
                else:
                    success={"launch":"game_closed","account":"account_ok", "login":"login_ok",
                             "rename":"rename_ok","update":"updated"}.get(action,"notice")
                    show("ui:"+success,"success")
                    if action == "update":state["after_language_notice"]="ui:updated"
            else:
                error=result.get("error","failed")
                state['eos_result'] = result.get('eosResult') if safe_eos_result(error, result.get('eosResult')) else None
                state['loopback_bind'] = safe_loopback_bind(result.get('loopbackBind')) if error == 'loopback_bind_failed' else None
                if error in ("login_required","account_disabled"):
                    view.authenticated=False
                    view.refresh_state()
                show("ui:login_hint" if state["initial_account"] and error=="login_required" else error,
                     "notice" if state["initial_account"] and error=="login_required" else "error")
                if action == "login" and error == "player_name_required":
                    view.request_player_name()
            if action=="account":state["initial_account"]=False
            if (state["language_pending"] or (action=="update" and result["ok"])) and not state["busy"]:
                state["language_pending"]=False
                start("language")
        app.after(100,poll)
    def close():
        if state["busy"]:
            messagebox.showinfo("TWA Revival",text("busy_close"))
        else:
            view.flush_name_draft()
            app.destroy()
    view.selector.bind("<<ComboboxSelected>>",localize)
    app.protocol("WM_DELETE_WINDOW",close)
    localize()
    if args.startup_probe:
        app.update_idletasks()
        app.destroy()
        print("TWA_PLAYER_READY",flush=True)
        return 0
    app.after(0,lambda:start("language"))
    app.after(100,poll)
    app.mainloop()
    return 0



def main() -> int:
    # Elevated hosts helper (started only via request_elevated_repair after consent
    # and UAC): exact argv only, and no diagnostics/lock/Tk; the UI holds the lock
    # and LOCALAPPDATA may belong to the approving administrator.
    if sys.argv[1:] == ["--repair-loopback-hosts"]:
        from tools.loopback_certificate import repair_loopback_hosts_main
        return repair_loopback_hosts_main()
    diagnostics()
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--action')
    parser.add_argument('--startup-probe', action='store_true')
    args, _ = parser.parse_known_args()
    from companion.self_updater import launcher_lock
    if args.action or args.startup_probe:
        return _main()
    # The fixed bootstrap recovers a crashed update before this module loads.
    if (ROOT / '.twa-launcher-update-active.json').exists():
        return 1
    with launcher_lock(ROOT):
        return _main()


if __name__ == "__main__":
    raise SystemExit(main())
