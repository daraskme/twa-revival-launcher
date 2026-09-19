"""First-install view hosted in the player launcher's single Tk window."""
from pathlib import Path
import json
import os
import queue
import re
import sys
import threading

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TEXT = {
    'JA': ['TWA Revival の導入', '', '導入先（新しいフォルダー）',
           '選択', 'インストール', '本体も自動でダウンロードします。導入先を選んでください。',
           'ファイルを確認しています…', 'ゲームをコピーしています…', '言語データを導入しています…',
           '導入結果を確認しています…', '導入が完了しました。導入先の「Launch TWA.cmd」で起動できます。',
           '導入できませんでした。ログを開いて運営に問題をご連絡ください。',
           '導入中です。完了するまでお待ちください。', 'ゲーム本体をダウンロードしています…',
           'ダウンロードを中断しました。次回は取得済みのデータを再利用します。',
           '配信設定が未完了か、配信先に接続できません。運営の案内を確認してください。'],
    'EN': ['Install TWA Revival', '', 'Install location (new folder)',
           'Choose', 'Install', 'The game will download automatically. Choose an installation folder.',
           'Checking files…', 'Copying the game…', 'Installing language files…',
           'Verifying the installation…', 'Installed. Open Launch TWA.cmd in the installation folder.',
           'Installation failed. Open the logs and contact support.',
           'Installation is running. Please wait for it to finish.', 'Downloading the game…',
           'Download paused. Verified data will be reused next time.',
           'Download is not configured or the service is unavailable. Check the project announcements.'],
    'RU': ['Установка TWA Revival', '', 'Папка установки (новая папка)',
           'Выбрать', 'Установить', 'Игра будет загружена автоматически. Выберите папку установки.',
           'Проверка файлов…', 'Копирование игры…', 'Установка языковых файлов…',
           'Проверка установки…', 'Готово. Откройте Launch TWA.cmd в папке установки.',
           'Ошибка установки. Откройте журналы и обратитесь в поддержку.',
           'Идёт установка. Дождитесь завершения.', 'Загрузка игры…',
           'Загрузка приостановлена. Проверенные данные будут использованы при повторном запуске.',
           'Загрузка не настроена или сервис недоступен. Проверьте объявления проекта.'],
}
for _locale, _messages in {
    'JA': ['ランチャーの更新を確認しています…', 'ランチャーを更新できませんでした。接続を確認して再試行してください。'],
    'EN': ['Checking launcher updates…', 'Could not update the launcher. Check your connection and try again.'],
    'RU': ['Проверка обновлений лаунчера…', 'Не удалось обновить лаунчер. Проверьте соединение и повторите попытку.'],
}.items():
    TEXT[_locale].extend(_messages)


def prepare_installer(root):
    """Update before downloading game content, without Epic or machine state."""
    from companion import self_updater as update
    from companion.api_client import ApiClient
    from companion.trusted_keys import PUBLIC_DOWNLOAD_ORIGIN
    from tools.install_player import core_rows
    api = ApiClient(PUBLIC_DOWNLOAD_ORIGIN, update.installed_version(root),
                    strict_download_transport=True, total_timeout=1200)
    result = update.stage(root, PUBLIC_DOWNLOAD_ORIGIN, api=api)
    if result['restartRequired']:
        return result, None
    signed = update.verify_manifest(api.launcher_update_manifest('stable'), PUBLIC_DOWNLOAD_ORIGIN, 'stable')
    core_rows(root, launcher_manifest=signed)
    return result, signed


def _install_request_path():
    from companion.player_language import player_state_dir
    from companion.self_updater import _safe
    return _safe(player_state_dir()/'installer-request.json',missing=True)


def load_install_request(root):
    """Local selected location, scoped to this unpacked launcher; not auth."""
    from companion.self_updater import LauncherUpdateError
    try:
        path=_install_request_path()
        with path.open('rb') as stream: raw=stream.read(16385)
        value=json.loads(raw)
        if (len(raw)>16384 or not isinstance(value,dict)
                or set(value)!={'schemaVersion','root','destination','language','transaction'}
                or type(value['schemaVersion']) is not int or value['schemaVersion']!=1
                or value['root']!=str(root.resolve(strict=True))
                or value['language'] not in ('JA','EN','RU')
                or not isinstance(value['destination'],str) or not value['destination']
                or len(value['destination'])>4096 or not Path(value['destination']).is_absolute()
                or any(ord(char)<32 for char in value['destination'])
                or (value['transaction'] is not None and
                    (not isinstance(value['transaction'],str) or
                     re.fullmatch('[0-9a-f]{32}',value['transaction']) is None))):
            return None
        return value
    except (OSError,UnicodeError,TypeError,ValueError,LauncherUpdateError):
        return None


def save_install_request(root,destination,language,*,transaction=None):
    from companion.config import _write_json_private
    value={'schemaVersion':1,'root':str(root.resolve(strict=True)),
        'destination':str(destination),'language':language,'transaction':transaction}
    if (language not in ('JA','EN','RU') or not destination.is_absolute()
            or len(str(destination))>4096 or any(ord(char)<32 for char in str(destination))
            or (transaction is not None and
                re.fullmatch('[0-9a-f]{32}',transaction) is None)):
        raise ValueError('invalid installation request')
    _write_json_private(_install_request_path(),value)


def completed_install_handoff(root,request):
    """Auto-continue only a prior approved location after its signed update."""
    if (request is None or request['transaction'] is None
            or '--update-result' not in sys.argv):
        return False
    index=sys.argv.index('--update-result')
    if len(sys.argv)<=index+1 or sys.argv[index+1]!='updated':return False
    from companion import self_updater as update
    try:
        folder,plan=update.load_plan(root,request['transaction'])
        return (update._journal(folder,plan)['phase']=='complete'
            and plan['channel']=='stable'
            and update.installed_version(root)==plan['manifest']['version']
            and not Path(request['destination']).exists())
    except (OSError,ValueError,update.LauncherUpdateError):
        return False


INSTALL_ERROR_MESSAGES = {
    'install_failed':'install_failed', 'install_space':'install_space',
    'install_permission':'install_permission', 'install_busy':'install_busy',
    'install_destination':'destination_exists', 'install_files':'install_files',
    'install_download':'install_download', 'install_launcher':'install_launcher',
}


def installer_error_code(error):
    """Only fixed classifications cross into UI/logs; never exception text."""
    import errno
    from companion.base_download import DownloadError
    from companion.client_lock import ClientOperationLockBusy
    from companion.self_updater import LauncherUpdateError
    from tools.install_player import PlayerInstallError
    from tools.player_native_payload import NativePayloadError
    from tools.player_package import PackageError
    from tools.stage_client import StageError
    if isinstance(error,OSError) and (error.errno==errno.ENOSPC or getattr(error,'winerror',None)==112):
        return 'install_space'
    if isinstance(error,PermissionError):return 'install_permission'
    if isinstance(error,ClientOperationLockBusy):return 'install_busy'
    if isinstance(error,DownloadError):
        return 'install_space' if error.args==('insufficient download space',) else 'install_download'
    if isinstance(error,LauncherUpdateError):return 'install_launcher'
    if isinstance(error,StageError) and error.args and isinstance(error.args[0],str) and error.args[0].startswith('insufficient free space for Revival client:'):
        return 'install_space'
    if isinstance(error,PlayerInstallError) and error.args==('installation destination must be new',):
        return 'install_destination'
    if isinstance(error,(NativePayloadError,PackageError)):return 'install_files'
    return 'install_failed'


def report_installer_failure(error,phase):
    code=installer_error_code(error)
    try:
        from tools.player_launcher import diagnostics
        diagnostics().event('operation_failed','install',error=error,code=code,
                            installer_phase=phase,crash=True)
    except Exception:
        pass # A local log failure must never replace the installation result.
    return code


def installation_view(app, root, *, locale='EN', probe=False):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    from companion.player_language import save_player_language
    from tools.install_player import install
    from tools.player_launcher import LANGUAGES
    from tools import player_ui as ui
    ui.configure(app)
    panel=tk.Frame(app,bg=ui.BG,padx=30,pady=24)
    panel.pack(fill='both',expand=True)
    request=load_install_request(root)
    resume=completed_install_handoff(root,request) if not probe else False
    if resume:locale=request['language']
    language=tk.StringVar(value=next(k for k,v in LANGUAGES.items() if v==locale))
    languages=ui.header(panel,language,(root/'companion/VERSION').read_text().strip())
    def copy(key):return ui.COPY[LANGUAGES[language.get()]][key]
    labels=[]
    def bind(widget,key):
        labels.append((widget,key))
        return widget
    steps=tk.Frame(panel,bg=ui.BG)
    steps.pack(fill='x',pady=(0,16))
    for key in ('step_install','step_login','step_play'):
        bind(ui.label(steps,size=10,color=ui.GOLD if key=='step_install' else ui.MUTED),key).pack(side='left',padx=(0,34))
    content=ui.card(panel,padx=24,pady=22)
    content.pack(fill='both',expand=True)
    bind(ui.label(content,size=23,bold=True),'setup_title').pack(anchor='w')
    bind(ui.label(content,color=ui.MUTED,wraplength=810),'setup_intro').pack(anchor='w',pady=(8,22))
    bind(ui.label(content,bold=True),'destination').pack(anchor='w')
    destination=tk.StringVar(value=request['destination'] if request is not None else
        str(Path(os.environ.get('LOCALAPPDATA',Path.home()))/'TWARevival/Game'))
    row=tk.Frame(content,bg=ui.CARD)
    row.pack(fill='x',pady=(7,4))
    entry=ttk.Entry(row,textvariable=destination)
    entry.pack(side='left',fill='x',expand=True)
    def choose_destination():
        selected=filedialog.askdirectory(parent=app)
        if selected:destination.set(str(Path(selected)/'TWA Revival'))
    browse=bind(ui.button(row,command=choose_destination),'browse')
    browse.pack(side='right',padx=(10,0))
    bind(ui.label(content,size=9,color=ui.MUTED),'destination_hint').pack(anchor='w')
    tk.Frame(content,bg=ui.LINE,height=1).pack(fill='x',pady=20)
    status=ui.label(content,size=12,bold=True,wraplength=810,justify='left')
    status.pack(anchor='w')
    bar=ttk.Progressbar(content,mode='determinate')
    bar.pack(fill='x',pady=(12,7))
    detail=ui.label(content,color=ui.MUTED,size=10)
    detail.pack(anchor='w')
    buttons=tk.Frame(panel,bg=ui.BG)
    buttons.pack(fill='x',pady=(18,0))
    controls=[languages,entry,browse]
    events=queue.Queue()
    state={'busy':False,'message':'restart_hint' if '--update-result' in sys.argv else 'download_hint',
           'result':None,'poll':None,'downloading':False,'close_pending':False,'download_progress':'',
           'phase':None,'failure_code':None}
    cancel=threading.Event()
    finished=tk.BooleanVar(app,False)
    def localize(event=None):
        for widget,key in labels:widget.configure(text=copy(key))
        message=state['message']
        status.configure(text=copy(message) if isinstance(message,str) else TEXT[LANGUAGES[language.get()]][message],
                         fg=ui.RED if message in (11,15,17,'destination_exists') or message in INSTALL_ERROR_MESSAGES.values() else ui.TEXT)
        detail.configure(text=state['download_progress'])
        submit.configure(text=copy('resume' if message==14 else 'continue_install' if message=='restart_hint' else 'download'))
        pause.configure(text=copy('pause'),state='normal' if state['busy'] and state['downloading'] else 'disabled')
    def begin():
        if state['busy']:
            return
        if not destination.get():
            state['message'] = 5
            localize()
            return
        selected = LANGUAGES[language.get()]
        source = None
        target = Path(destination.get()).expanduser().absolute()
        if target.exists():
            state['message']='destination_exists'
            localize()
            return
        state['busy'] = True
        state['downloading'] = source is None
        cancel.clear()
        for control in controls:
            control.configure(state='disabled')
        def download_progress(done,total):
            events.put(('progress',done,total))
            if done==total:events.put('unpacking')
        def work():
            from companion.base_download import download_public, download_native, DownloadPaused, DownloadError
            from companion.self_updater import LauncherUpdateError
            phase='prepare'
            def install_progress(message):
                nonlocal phase
                phase=message
                events.put(message)
            try:
                save_player_language(selected)
                save_install_request(root,target,selected)
                events.put('launcher_checking')
                phase='launcher_check'
                update, launcher_manifest = prepare_installer(root)
                if update['restartRequired']:
                    if not cancel.is_set():
                        save_install_request(root,target,selected,transaction=update['transaction'])
                    events.put(('restart', update['transaction']))
                    return
                original = source
                if original is None:
                    events.put('downloading_base')
                    phase='base_download'
                    original = download_public(target.parent/'Downloads',
                        cancel=cancel, progress=download_progress)
                from tools.player_native_payload import MANIFEST
                content = root
                if not (root / MANIFEST).is_file():
                    state['downloading'] = True
                    events.put('downloading_native')
                    phase='native_download'
                    content = download_native(target.parent/'Downloads', cancel=cancel,
                        progress=download_progress)
                state['downloading'] = False
                phase='checking'
                install(root, original, target, selected, native_source=content,
                        launcher_manifest=launcher_manifest, progress=install_progress)
                events.put(('installed', target, selected))
            except LauncherUpdateError as error:
                events.put(('installer_failed',report_installer_failure(error,phase)))
            except DownloadPaused:
                events.put('paused')
            except DownloadError as error:
                events.put(('installer_failed',report_installer_failure(error,phase)))
            except Exception as error:
                events.put(('installer_failed',report_installer_failure(error,phase)))
        threading.Thread(target=work, daemon=True).start()
    submit=ui.button(buttons,command=begin,primary=True)
    submit.pack(side='left',fill='x',expand=True)
    pause=ui.button(buttons,command=cancel.set)
    pause.pack(side='right',padx=(12,0))
    controls.append(submit)
    from companion.diagnostics import open_log_folder
    logs=bind(ui.button(buttons,command=open_log_folder),'install_logs')
    logs.pack(side='right',padx=(12,0))
    def poll():
        try:
            while True:
                phase = events.get_nowait()
                if isinstance(phase,tuple) and phase[0] == 'progress':
                    unit,scale=('GB',1e9) if phase[2]>=1e9 else ('MB',1e6)
                    state['download_progress']=f'{phase[1]/phase[2]:.0%}   ·   {phase[1]/scale:.2f} / {phase[2]/scale:.2f} {unit}'
                    bar.stop()
                    bar.configure(mode='determinate',maximum=phase[2],value=phase[1])
                    localize()
                    continue
                if isinstance(phase, tuple) and phase[0] == 'restart':
                    from companion.self_updater import schedule_restart
                    try:
                        if cancel.is_set():
                            save_install_request(root,Path(destination.get()).expanduser().absolute(),
                                LANGUAGES[language.get()])
                        schedule_restart(root, phase[1])
                    except Exception:
                        phase = 'launcher_failed'
                    else:
                        state['busy'] = False
                        finished.set(True)
                        return
                if isinstance(phase, tuple) and phase[0] == 'installed':
                    state['result'] = (phase[1], phase[2])
                    state['busy'] = False
                    finished.set(True)
                    return
                if isinstance(phase,tuple) and phase[0]=='installer_failed':
                    code=phase[1] if phase[1] in INSTALL_ERROR_MESSAGES else 'install_failed'
                    state['failure_code']=code
                    state['message']=INSTALL_ERROR_MESSAGES[code]
                    phase='failed'
                else:
                    state['failure_code']=None
                state['phase']=phase
                bar.stop()
                if phase not in ('failed','paused','download_failed','launcher_failed'):
                    bar.configure(mode='indeterminate')
                    bar.start(14)
                message = {'checking': 6, 'copying': 7, 'applying': 8,
                                    'verifying': 9, 'complete': 10, 'failed': 11,
                                    'downloading_base':'base_download','downloading_native':'native_download',
                                    'unpacking':'unpacking', 'paused':14, 'download_failed':15,
                                    'launcher_checking':16, 'launcher_failed':17}[phase]
                if state['failure_code'] is None:state['message']=message
                if phase in ('failed','paused','download_failed','launcher_failed'):
                    state['busy'] = False
                    if state['close_pending']:
                        finished.set(True)
                        return
                    for control in controls:
                        control.configure(state='normal')
                    languages.configure(state='readonly')
                localize()
        except queue.Empty:
            pass
        state['poll'] = app.after(100, poll)
    def close():
        if state['busy'] and state['downloading']:
            state['close_pending'] = True
            cancel.set()
        elif state['busy']:
            messagebox.showinfo('TWA Revival', TEXT[LANGUAGES[language.get()]][12])
        else:
            finished.set(True)
    app.protocol('WM_DELETE_WINDOW', close)
    languages.bind('<<ComboboxSelected>>', localize)
    localize()
    if probe:
        app.withdraw()
        for selected in LANGUAGES:
            language.set(selected)
            localize()
            app.update_idletasks()
    else:
        state['poll'] = app.after(100, poll)
        if resume:app.after(0,begin)
        app.wait_variable(finished)
    if state['poll'] is not None:
        app.after_cancel(state['poll'])
    bar.stop()
    panel.destroy()
    return state['result']


def main():
    if '--startup-probe' in sys.argv:
        import tkinter as tk
        app = tk.Tk()
        installation_view(app, ROOT, probe=True)
        app.destroy()
        print('TWA_SETUP_READY')
    else:
        # Compatibility for an earlier candidate; one launcher remains the entry.
        from tools.player_launcher import main as launch
        return launch()


if __name__ == '__main__':
    main()
