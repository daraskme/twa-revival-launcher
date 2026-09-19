"""Shared visual components for the player launcher; no network or account I/O."""
import tkinter as tk
from tkinter import ttk

BG = '#0e151e'
CARD = '#172330'
LINE = '#2c3c4d'
TEXT = '#edf2f7'
MUTED = '#a8b7c7'
GOLD = '#e7be7a'
GREEN = '#8dd6b1'
RED = '#ffb3a7'
FONT = 'Yu Gothic UI'

COPY = {
    'JA': {
        'install_failed':'導入できませんでした。ログを開いて運営に問題をご連絡ください。',
        'install_space':'空き容量が不足しています。容量を確保して再試行してください。取得済みのデータは保持されます。',
        'install_permission':'書き込みが許可されていないか、ファイルが使用中です。利用可能な新しい導入先を選んで再試行してください。',
        'install_busy':'別の導入処理が動いています。完了してから再試行してください。',
        'install_files':'導入ファイルの確認に失敗しました。ログを開いて運営に問題をご連絡ください。',
        'install_download':'データを取得できませんでした。接続を確認して再試行してください。取得済みのデータは保持されます。',
        'install_launcher':'ランチャーの更新を確認できませんでした。接続を確認して再試行してください。',
        'install_logs':'導入ログを開く',

        'edition':'WINDOWS ランチャー', 'welcome':'戦場へ向かう準備を。',
        'intro':'Epicアカウントでログインして、ゲームを開始します。\n更新は起動時にも自動で確認します。',
        'play':'ゲームを開始', 'login':'Epicでログイン', 'account':'アカウント',
        'signed_out':'ログインしていません', 'signed_in':'ログイン済み',
        'checking_account':'ログイン状態を確認中', 'account_hint':'Epicの画面で本人認証を行います。',
        'refresh':'ログイン状態を確認', 'switch':'別のアカウントでログイン',
        'settings':'プレイヤーネームを変更', 'name':'プレイヤーネーム',
        'change_name':'変更', 'set_name':'名前を指定', 'save_name':'保存', 'cancel':'キャンセル',
        'rename_hint':'ゲーム内に表示する名前を1～32文字で入力してください。',
        'name_hint':'初めて遊ぶ方は、ゲーム内で使う名前を1～32文字で入力してください。\n次にEpicの画面でログインします。',
        'name_login':'名前を設定してログイン', 'name_continue':'この名前でEpicログイン',
        'existing_login':'登録済みのアカウントでログイン',
        'name_invalid':'1～32文字で入力してください。改行・制御文字・\\・"・; は使えません。',
        'name_required':'初回登録のため、プレイヤーネームを入力してください。',
        'rename':'名前を変更', 'update':'更新を確認', 'files':'ゲームファイル',
        'installed':'導入済み', 'update_hint':'ゲーム開始時に最新版を確認',
        'next':'次の操作', 'login_hint':'初めての方はプレイヤーネームを設定して、Epicでログインしてください。',
        'play_hint':'準備できました。「ゲームを開始」で格納庫へ進みます。',
        'checking':'確認しています', 'updating':'更新を確認しています',
        'signing_in':'Epicの認証を待っています', 'starting':'ゲームを起動しています',
        'running_hint':'起動までお待ちください。ゲーム終了後はこの画面に戻ります。',
        'notice':'お知らせ', 'error':'操作を完了できませんでした', 'success':'準備できました',
        'game_closed':'ゲームが終了しました。もう一度開始できます。',
        'updated':'更新の確認が完了しました。ゲームを開始できます。',
        'account_ok':'ログイン状態を確認しました。', 'login_ok':'Epicにログインしました。',
        'rename_ok':'プレイヤーネームを変更しました。',
        'setup_title':'ゲームをインストール',
        'setup_intro':'ランチャーが必要なゲームファイルをすべてダウンロードします。',
        'step_install':'1  インストール', 'step_login':'2  Epicログイン', 'step_play':'3  ゲーム開始',
        'destination':'インストール先', 'destination_hint':'まだ使っていない、新しいフォルダーを選んでください。',
        'browse':'変更',
        'download':'ダウンロードしてインストール', 'resume':'ダウンロードを再開',
        'pause':'ダウンロードを中断', 'download_hint':'本体のダウンロードは約8.1 GB。中断後は続きから再開できます。',
        'base_download':'ゲーム本体をダウンロード中', 'native_download':'追加・言語データをダウンロード中',
        'setup_wait':'ゲームの準備中です。完了するまでお待ちください。',
        'unpacking':'取得したデータを展開・確認しています',
        'restart_hint':'ランチャーの更新が完了しました。インストールを続けられます。',
        'continue_install':'続けてインストール', 'destination_exists':'このフォルダーはすでに存在します。新しい導入先を選んでください。',
    },
    'EN': {
        'install_failed':'Installation failed. Open the logs and contact support.',
        'install_space':'Not enough free space. Free up space and retry. Verified downloads are retained.',
        'install_permission':'Writing is not permitted or a file is in use. Choose a new writable destination and retry.',
        'install_busy':'Another installation is running. Wait for it to finish, then retry.',
        'install_files':'Installation files could not be verified. Open the logs and contact support.',
        'install_download':'Could not download the data. Check your connection and retry. Verified downloads are retained.',
        'install_launcher':'Could not check launcher updates. Check your connection and retry.',
        'install_logs':'Open installation logs',

        'edition':'WINDOWS LAUNCHER', 'welcome':'Ready for the battlefield.',
        'intro':'Sign in with Epic, then start the game.\nUpdates are also checked automatically when you play.',
        'play':'Start game', 'login':'Sign in with Epic', 'account':'ACCOUNT',
        'signed_out':'Not signed in', 'signed_in':'Signed in', 'checking_account':'Checking sign-in',
        'account_hint':'Complete authentication in the Epic window.', 'refresh':'Check sign-in',
        'switch':'Sign in with another account', 'settings':'Change player name', 'name':'Player name',
        'change_name':'Change', 'set_name':'Set name', 'save_name':'Save', 'cancel':'Cancel',
        'rename_hint':'Enter the name shown in the game, using 1–32 characters.',
        'name_hint':'New players: enter the name shown in the game, using 1–32 characters.\nThen sign in on the Epic screen.',
        'name_login':'Set name and sign in', 'name_continue':'Sign in with this name',
        'existing_login':'Sign in to an existing account',
        'name_invalid':'Use 1–32 characters. Line breaks, control characters, \\, " and ; are not allowed.',
        'name_required':'Enter a player name to create your game account.',
        'rename':'Change name', 'update':'Check updates', 'files':'GAME FILES', 'installed':'Installed',
        'update_hint':'Latest version checked when you play', 'next':'NEXT STEP',
        'login_hint':'First time here? Set your player name, then sign in with Epic.', 'play_hint':'Ready. Start the game to open the hangar.',
        'checking':'Checking', 'updating':'Checking updates', 'signing_in':'Waiting for Epic sign-in',
        'starting':'Starting the game', 'running_hint':'Please wait for the game. Return here after you exit.',
        'notice':'Notice', 'error':'Could not complete this step', 'success':'Ready',
        'game_closed':'The game has closed. You can start it again.',
        'updated':'Update check complete. You can start the game.', 'account_ok':'Sign-in confirmed.',
        'login_ok':'Signed in with Epic.', 'rename_ok':'Player name changed.',
        'setup_title':'Install the game', 'setup_intro':'The launcher downloads all the game files you need.',
        'step_install':'1  Install', 'step_login':'2  Epic sign-in', 'step_play':'3  Play',
        'destination':'Install location', 'destination_hint':'Choose a new folder that is not already in use.',
        'browse':'Change',
        'download':'Download and install', 'resume':'Resume download', 'pause':'Pause download',
        'download_hint':'About 8.1 GB to download. You can pause and resume later.',
        'base_download':'Downloading the base game', 'native_download':'Downloading additional and language files',
        'setup_wait':'Preparing your game. Please wait until this finishes.',
        'unpacking':'Unpacking and verifying downloaded files',
        'restart_hint':'Launcher updated. Ready to continue the installation.',
        'continue_install':'Continue installation', 'destination_exists':'This folder already exists. Choose a new install location.',
    },
    'RU': {
        'install_failed':'Ошибка установки. Откройте журналы и обратитесь в поддержку.',
        'install_space':'Недостаточно свободного места. Освободите место и повторите. Проверенные загрузки сохранены.',
        'install_permission':'Запись запрещена или файл используется. Выберите новую доступную папку и повторите.',
        'install_busy':'Другая установка ещё выполняется. Дождитесь её завершения и повторите.',
        'install_files':'Не удалось проверить файлы установки. Откройте журналы и обратитесь в поддержку.',
        'install_download':'Не удалось загрузить данные. Проверьте соединение и повторите. Проверенные загрузки сохранены.',
        'install_launcher':'Не удалось проверить обновления. Проверьте соединение и повторите.',
        'install_logs':'Открыть журналы установки',

        'edition':'ЛАУНЧЕР ДЛЯ WINDOWS', 'welcome':'Подготовка к сражению.',
        'intro':'Войдите через Epic и запустите игру.\nОбновления также проверяются при запуске.',
        'play':'Начать игру', 'login':'Войти через Epic', 'account':'УЧЁТНАЯ ЗАПИСЬ',
        'signed_out':'Вход не выполнен', 'signed_in':'Вход выполнен', 'checking_account':'Проверка входа',
        'account_hint':'Пройдите проверку в окне Epic.', 'refresh':'Проверить вход',
        'switch':'Войти в другую учётную запись', 'settings':'Изменить имя игрока', 'name':'Имя игрока',
        'change_name':'Изменить', 'set_name':'Указать имя', 'save_name':'Сохранить', 'cancel':'Отмена',
        'rename_hint':'Введите имя для отображения в игре: от 1 до 32 символов.',
        'name_hint':'Новый игрок? Введите имя для игры: от 1 до 32 символов.\nЗатем войдите на экране Epic.',
        'name_login':'Указать имя и войти', 'name_continue':'Войти с этим именем',
        'existing_login':'Войти в существующую запись',
        'name_invalid':'Введите от 1 до 32 символов без переноса строк, управляющих символов, \\, " и ;.',
        'name_required':'Укажите имя игрока для регистрации в игре.',
        'rename':'Изменить имя', 'update':'Проверить обновления', 'files':'ФАЙЛЫ ИГРЫ',
        'installed':'Установлены', 'update_hint':'Проверка обновлений при запуске', 'next':'СЛЕДУЮЩИЙ ШАГ',
        'login_hint':'Играете впервые? Укажите имя игрока, затем войдите через Epic.',
        'play_hint':'Всё готово. Начните игру, чтобы открыть ангар.',
        'checking':'Проверка', 'updating':'Проверка обновлений', 'signing_in':'Ожидание входа через Epic',
        'starting':'Запуск игры', 'running_hint':'Дождитесь запуска. После выхода вы вернётесь сюда.',
        'notice':'Информация', 'error':'Не удалось завершить действие', 'success':'Всё готово',
        'game_closed':'Игра закрыта. Можно запустить её снова.',
        'updated':'Обновления проверены. Можно начать игру.', 'account_ok':'Вход подтверждён.',
        'login_ok':'Вход через Epic выполнен.', 'rename_ok':'Имя игрока изменено.',
        'setup_title':'Установка игры', 'setup_intro':'Лаунчер загрузит все необходимые файлы игры.',
        'step_install':'1  Установка', 'step_login':'2  Вход через Epic', 'step_play':'3  Игра',
        'destination':'Папка установки', 'destination_hint':'Выберите новую, ещё не используемую папку.',
        'browse':'Изменить',
        'download':'Скачать и установить', 'resume':'Продолжить загрузку', 'pause':'Приостановить',
        'download_hint':'Объём загрузки — около 8,1 ГБ. Загрузку можно возобновить.',
        'base_download':'Загрузка основной игры', 'native_download':'Загрузка дополнений и языковых файлов',
        'setup_wait':'Подготовка игры. Дождитесь завершения.',
        'unpacking':'Распаковка и проверка загруженных файлов',
        'restart_hint':'Лаунчер обновлён. Можно продолжить установку.',
        'continue_install':'Продолжить установку', 'destination_exists':'Эта папка уже существует. Выберите новую папку.',
    },
}


def configure(app):
    app.title('TWA Revival')
    app.geometry('960x760')
    app.minsize(900, 720)
    app.configure(bg=BG)
    app.option_add('*Font', (FONT, 10))
    style = ttk.Style(app)
    style.theme_use('clam')
    style.configure('TCombobox', fieldbackground=CARD, background=LINE, foreground=TEXT,
                    arrowcolor=GOLD, bordercolor=LINE, padding=6)
    style.map('TCombobox', fieldbackground=[('readonly', CARD)], foreground=[('readonly', TEXT)])
    style.configure('TEntry', fieldbackground=BG, foreground=TEXT, bordercolor=LINE, padding=8)
    style.configure('TProgressbar', background=GOLD, troughcolor=BG, borderwidth=0)


def label(parent, text='', *, size=10, color=TEXT, bold=False, **kwargs):
    return tk.Label(parent, text=text, bg=parent.cget('bg'), fg=color,
                    font=(FONT, size, 'bold' if bold else 'normal'), anchor='w', **kwargs)


def button(parent, text='', command=None, *, primary=False):
    return tk.Button(parent, text=text, command=command, relief='flat', bd=0,
        bg=GOLD if primary else LINE, fg=BG if primary else TEXT,
        activebackground='#f4cf93' if primary else '#3c5065',
        activeforeground=BG if primary else TEXT, disabledforeground='#748395',
        font=(FONT, 12 if primary else 10, 'bold' if primary else 'normal'),
        padx=18, pady=13 if primary else 8, cursor='hand2',
        highlightthickness=1, highlightbackground=GOLD if primary else LINE,
        highlightcolor=TEXT, takefocus=True)


def card(parent, **kwargs):
    return tk.Frame(parent, bg=CARD, highlightbackground=LINE, highlightthickness=1, **kwargs)


def header(parent, language, version):
    bar=tk.Frame(parent,bg=BG)
    bar.pack(fill='x',pady=(0,22))
    brand=tk.Frame(bar,bg=BG)
    brand.pack(side='left')
    label(brand,'TWA',size=27,color=GOLD,bold=True).pack(side='left')
    label(brand,'REVIVAL',size=14,bold=True).pack(side='left',padx=(12,0))
    selector=ttk.Combobox(bar,textvariable=language,values=('English','日本語','Русский'),
                          state='readonly',width=12)
    selector.pack(side='right')
    label(bar,'v'+version,size=9,color=MUTED).pack(side='right',padx=16)
    return selector


class PlayerWindow:
    """One primary next action, separate account controls, persistent status."""
    def __init__(self, app, language, name, account, *, locale, version, action,
                 load_name_draft=None, save_name_draft=None, begin_account_switch=None):
        configure(app)
        # None means not checked yet, not logged out. A failed initial account
        # request must offer a retry instead of sending the user to Epic again.
        self.locale, self.authenticated, self.busy = locale, None, False
        self.app = app
        self.name_action, self.registration_required, self.name_error_key = 'login', False, None
        self.name, self.account, self.action = name, account, action
        self.load_name_draft = load_name_draft or (lambda: '')
        self.save_name_draft = save_name_draft or (lambda value: None)
        self.begin_account_switch = begin_account_switch or (lambda: None)
        self.draft_save_job = None
        self.name.trace_add('write', self.schedule_name_draft)
        self.bound=[]
        self.controls=[]
        self.panel=tk.Frame(app,bg=BG,padx=30,pady=24)
        self.panel.pack(fill='both',expand=True)
        self.selector=header(self.panel,language,version)
        self.controls.append(self.selector)
        body=tk.Frame(self.panel,bg=BG)
        body.pack(fill='both',expand=True)
        body.grid_columnconfigure(0,weight=3,uniform='body')
        body.grid_columnconfigure(1,weight=2,uniform='body')
        self.main=card(body,padx=26,pady=23)
        self.main.grid(row=0,column=0,sticky='nsew',padx=(0,16))
        self.bind(label(self.main,size=9,color=GOLD),'edition').pack(anchor='w')
        self.bind(label(self.main,size=22,bold=True),'welcome').pack(anchor='w',pady=(16,10))
        self.bind(label(self.main,color=MUTED,justify='left',wraplength=440),'intro').pack(anchor='w')
        tk.Frame(self.main,bg=LINE,height=1).pack(fill='x',pady=22)
        self.bind(label(self.main,size=9,color=GOLD),'next').pack(anchor='w')
        self.next_hint=label(self.main,wraplength=440,justify='left')
        self.next_hint.pack(fill='x',pady=(8,16))
        self.primary=button(self.main,primary=True,command=self.primary_action)
        self.primary.pack(fill='x')
        self.controls.append(self.primary)
        self.progress=ttk.Progressbar(self.main,mode='indeterminate')
        self.progress.pack(fill='x',pady=(14,0))
        side=card(body,padx=20,pady=21)
        side.grid(row=0,column=1,sticky='nsew')
        self.bind(label(side,size=9,color=GOLD),'account').pack(anchor='w')
        self.account_badge=label(side,size=10,color=MUTED)
        self.account_badge.pack(anchor='w',pady=(14,3))
        self.bind(label(side,size=9,color=MUTED),'name').pack(anchor='w',pady=(10,3))
        name_row=tk.Frame(side,bg=CARD)
        name_row.pack(fill='x',pady=(0,14))
        name_row.grid_columnconfigure(0,weight=1)
        self.account_label=label(name_row,textvariable=account,size=15,bold=True,justify='left',wraplength=180)
        self.account_label.grid(row=0,column=0,sticky='w')
        self.settings_button=button(name_row,command=self.toggle_settings)
        self.settings_button.grid(row=0,column=1,sticky='ne',padx=(10,0))
        def wrap_name(event):
            self.account_label.configure(wraplength=max(80,event.width-self.settings_button.winfo_reqwidth()-10))
        name_row.bind('<Configure>',wrap_name)
        self.controls.append(self.settings_button)
        self.refresh=self.bind(button(side,command=lambda:action('account')),'refresh')
        self.refresh.pack(fill='x')
        self.switch=self.bind(button(side,command=self.switch_account),'switch')
        self.switch.pack(fill='x',pady=(7,0))
        self.controls.extend((self.refresh,self.switch))
        tk.Frame(side,bg=LINE,height=1).pack(fill='x',pady=18)
        self.bind(label(side,size=9,color=GOLD),'files').pack(anchor='w')
        self.bind(label(side,color=GREEN),'installed').pack(anchor='w',pady=(7,2))
        self.bind(label(side,color=MUTED,size=9,wraplength=290),'update_hint').pack(anchor='w')
        self.update=self.bind(button(side,command=lambda:action('update')),'update')
        self.update.pack(fill='x',pady=(10,0))
        self.controls.append(self.update)
        self.settings_window=tk.Toplevel(app)
        self.settings_window.withdraw()
        self.settings_window.configure(bg=BG)
        self.settings_window.geometry('660x390')
        self.settings_window.minsize(660,390)
        self.settings_window.protocol('WM_DELETE_WINDOW',self.close_settings)
        self.settings=card(self.settings_window,padx=20,pady=20)
        self.settings.pack(fill='both',expand=True,padx=16,pady=16)
        self.bind(label(self.settings,size=15,bold=True),'name').pack(anchor='w',pady=(0,10))
        self.name_hint=label(self.settings,color=MUTED,justify='left',wraplength=540)
        self.name_hint.pack(anchor='w',pady=(0,12))
        self.entry=ttk.Entry(self.settings,textvariable=name)
        self.entry.pack(fill='x')
        self.name_error=label(self.settings,color=RED,justify='left',wraplength=580)
        self.name_error.pack(fill='x',pady=(6,0))
        row=tk.Frame(self.settings,bg=CARD)
        row.pack(fill='x',pady=(16,0))
        self.rename=button(row,command=self.submit_name,primary=True)
        self.rename.pack(side='right')
        self.cancel=self.bind(button(row,command=self.close_settings),'cancel')
        self.cancel.pack(side='right',padx=(0,10))
        self.existing=self.bind(button(self.settings,command=self.login_existing),'existing_login')
        self.controls.extend((self.entry,self.rename,self.cancel,self.existing))
        self.settings_window.bind('<Escape>',lambda event:self.close_settings())
        self.entry.bind('<Return>',lambda event:self.submit_name())
        self.notice=card(self.panel,padx=17,pady=13)
        self.notice.pack(fill='x',pady=(16,0))
        self.notice_title=label(self.notice,size=10,color=GOLD,bold=True)
        self.notice_title.pack(anchor='w')
        self.notice_body=label(self.notice,color=MUTED,wraplength=830,justify='left')
        self.notice_body.pack(anchor='w',pady=(5,0))
        self.runtime_help=None
        self.localize(locale)

    def bind(self,widget,key):
        self.bound.append((widget,key))
        return widget

    def text(self,key):return COPY[self.locale][key]

    def localize(self,locale):
        self.locale=locale
        for widget,key in self.bound:widget.configure(text=self.text(key))
        self.refresh_state()

    def toggle_settings(self):
        self.open_name_dialog('rename' if self.authenticated else 'login')

    def primary_action(self):
        if self.authenticated is None:self.action('account')
        elif self.authenticated:self.action('launch')
        else:self.open_login()

    def open_login(self):
        self.open_name_dialog('login')

    def switch_account(self):
        if self.busy:return
        self.begin_account_switch()
        self.open_name_dialog('login')

    def request_player_name(self):
        self.open_name_dialog('login',required=True)

    def open_name_dialog(self,action,*,required=False):
        if self.busy:return
        self.name_action, self.registration_required = action, required
        self.name_error_key='name_required' if required else None
        self.name.set(self.account.get() if action=='rename' else self.load_name_draft())
        self.refresh_state()
        # Associate the dialog only after the owner is mapped. In particular,
        # never grab input on a withdrawn/unmapped transient window: Windows
        # can leave the launcher visible but unable to receive button clicks.
        self.app.update_idletasks()
        if self.app.winfo_viewable():
            self.settings_window.transient(self.app)
        width, height = 660, 390
        x = max(0, self.app.winfo_rootx() + (self.app.winfo_width() - width) // 2)
        y = max(0, self.app.winfo_rooty() + (self.app.winfo_height() - height) // 2)
        self.settings_window.geometry(f'{width}x{height}+{x}+{y}')
        self.settings_window.deiconify()
        self.settings_window.update_idletasks()
        self.settings_window.lift()
        self.entry.focus_force()
        self.entry.selection_range(0,'end')

    def close_settings(self):
        self.flush_name_draft()
        self.settings_window.withdraw()

    def schedule_name_draft(self, *_):
        if self.draft_save_job is not None:
            self.app.after_cancel(self.draft_save_job)
        self.draft_save_job = self.app.after(250, self.flush_name_draft)

    def flush_name_draft(self):
        if self.draft_save_job is not None:
            self.app.after_cancel(self.draft_save_job)
            self.draft_save_job = None
        if self.name_action == 'login':
            try:
                self.save_name_draft(self.name.get())
            except (OSError, ValueError):
                pass  # Keep the last valid draft; typing must continue on disk errors.

    def submit_name(self):
        if self.busy:return
        from companion.player_name import validate_display_name
        try:
            draft=validate_display_name(self.name.get()).strip()
        except ValueError:
            self.name_error_key='name_invalid'
            self.refresh_state()
            self.entry.focus_set()
            return
        self.close_settings()
        self.name.set(draft)
        self.action(self.name_action)

    def login_existing(self):
        if self.busy or self.registration_required:return
        self.close_settings()
        draft = self.name.get()
        self.name.set('')
        try:
            self.action('login')  # Existing-account login sends no registration name.
        finally:
            self.name.set(draft)

    def refresh_state(self):
        unknown = self.authenticated is None
        self.account_badge.configure(text=self.text('checking_account' if unknown else 'signed_in' if self.authenticated else 'signed_out'),
                                     fg=GREEN if self.authenticated else MUTED)
        self.primary.configure(text=self.text('refresh' if unknown else 'play' if self.authenticated else 'name_login'))
        self.next_hint.configure(text=self.text('checking_account' if unknown else 'play_hint' if self.authenticated else 'login_hint'))
        self.switch.configure(state='normal' if self.authenticated and not self.busy else 'disabled')
        self.settings_button.configure(text=self.text('change_name' if self.authenticated else 'set_name'),
                                       state='disabled' if unknown or self.busy else 'normal')
        self.settings_window.title(self.text('settings' if self.name_action=='rename' else 'set_name'))
        self.name_hint.configure(text=self.text('rename_hint' if self.name_action=='rename' else 'name_hint'))
        self.name_error.configure(text=self.text(self.name_error_key) if self.name_error_key else '')
        self.rename.configure(text=self.text('save_name' if self.name_action=='rename' else 'name_continue'),
                              state='normal' if not self.busy else 'disabled')
        if self.name_action=='login' and not self.registration_required:
            self.existing.pack(fill='x',pady=(12,0))
        else:self.existing.pack_forget()

    def set_busy(self,action=None):
        self.busy=action is not None
        for control in self.controls:control.configure(state='disabled' if self.busy else 'normal')
        if not self.busy:self.selector.configure(state='readonly')
        self.refresh_state()
        if self.busy:
            key={'login':'signing_in','launch':'starting','update':'updating','account':'checking_account'}.get(action,'checking')
            self.primary.configure(text=self.text(key))
            self.progress.start(14)
        else:self.progress.stop()

    def message(self,text,kind='notice'):
        self.notice_title.configure(text=self.text(kind),fg=RED if kind=='error' else GREEN if kind=='success' else GOLD)
        self.notice_body.configure(text=text,fg=RED if kind=='error' else MUTED)
