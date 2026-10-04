# TWA Revival launcher — 0.2.48 QA source

This branch contains **120 reviewed source/configuration files** from the
0.2.48 launcher candidate. The source is available for review while Windows VM
QA continues. **0.2.48 has not been released to production.** The published
production snapshot and its signed verification are on
[`main` (0.2.43)](https://github.com/daraskme/twa-revival-launcher/tree/main).

This is a source subset, not a complete game or standalone build. Game assets,
extracted catalogs, four held files containing game instruction/data material,
third-party binaries, private configuration and diagnostics are excluded.
See [PUBLISHING.md](PUBLISHING.md) for the exact boundary and release workflow.

TWA Revival is a free, non-commercial fan project. It is not affiliated with,
endorsed by or supported by Creative Assembly, SEGA or Epic Games. Publishing
this source does not grant rights to the original game or third-party materials.

## Changes under validation

- Stop requesting local TCP port 80, avoiding that startup conflict.
- Report validated protocol, address family and port details when a required
  local TCP or UDP socket cannot be opened.
- Preserve supported resolution, display mode and graphics changes during normal
  shutdown, including native position/advice rewrites made by graphics Apply.
- Notify the native game when an unbound matchmaking queue expires or is aborted.

The candidate retains game payload 0.2.5 and native payload 0.2.4. Actual QA048
Apply / normal exit / restart retained 1280x900 resolution and render scale 0.5
on an RTX 5060 Ti Windows VM. Fresh-install and two-player battle checks remain
open. The black terrain/vegetation report is not claimed fixed.

## Source and release verification

The 16 changed files and one added file (`companion/loopback_ports.py`) preserve
the exact bytes of the prepared 0.2.48 candidate; the remaining published source
is unchanged from 0.2.43. Only reviewed source is added to this branch.

`manifests/` and `verify_release.py` are still the original **0.2.43 release
reference**, not a signature for this candidate. Its source-hash check is
expected to fail against changed QA source. To verify the production download,
use the instructions and verifier on `main`. Before merging this branch, replace
release metadata only with the actual production signed manifest, update the
verifier, and pass its source/ZIP and tamper/exclusion checks.

| Path | Purpose |
|---|---|
| `companion/` | Launcher orchestration, identity, updates, diagnostics and local game preparation |
| `server/` | Client-side compatibility services shipped with the launcher; not the hosted backend |
| `tools/` | Launcher UI, installation, bootstrap and runtime integration |
| `Launch TWA.cmd`, `config/preferences.template.txt` | Release entry point and preference defaults |
| `NOTICE.txt` | Third-party runtime notices; the binaries themselves are excluded |

Bugs and review feedback belong in
[Issues](https://github.com/daraskme/twa-revival-launcher/issues). Include the
launcher version, Windows/GPU details and reproduction steps. Do not post
credentials, tokens, signing keys, game assets or unredacted logs publicly.

## What the launcher does

`Launch TWA.cmd` runs the bundled `runtime\python.exe` on `tools/player_bootstrap.py`, which
starts the launcher window (`tools/player_launcher.py`). Everything runs as the normal
Windows user; the only thing that asks for administrator rights is the optional hosts file
fix described below. The launcher does its work in hidden `runtime\python.exe` child
processes: a worker for each button, the local-services bridge, the Frida helper
(`tools/unit_drag_bridge.py`) and the update helper. Before updating or launching, it runs
`tasklist` (hidden) to check that `Arena.exe` is not already running; the process list is
not stored or sent.

### 1. Installation

- Installs into `%LOCALAPPDATA%\TWARevival\Game` by default (or a folder you choose), and
  keeps a download cache next to it (`...\TWARevival\Downloads`), which is not cleaned up
  automatically.
- **Downloads the Total War: Arena client files from the project's download server**, plus a
  set of replacement files: a modified `game.dll`, replacement data and language `.pack`
  files, and two "NPL stub" DLLs (`npl-base.dll`, `npl-sdk.dll`) that replace the original
  publisher's login library (`tools/player_native_payload.py`, `tools/stage_client.py`).
  The installed `Arena.exe` is the original, unmodified file. Every download is checked
  against Ed25519-signed manifests and SHA-256 values before use
  (`companion/base_download.py`).
- Creates a self-signed TLS certificate for the local services, using a hidden PowerShell
  process (`tools/loopback_certificate.py`). It is saved as files in the install folder and
  is **not** added to the Windows certificate store.

### 2. Sign-in (Epic Online Services)

- Sign-in uses Epic's own EOS SDK and Epic's account portal (`companion/eos/session.py`).
  **The launcher never asks for or sees your Epic password.** The only text boxes in the
  launcher are the player name and the install folder. The requested scope is
  `BasicProfile`.
- After sign-in, Epic's SDK gives the launcher an Epic Connect ID token, which the launcher
  sends to the project API to get a project session token that is valid for about one hour
  (`companion/auth.py`, `companion/api_client.py`). The launcher gets a fresh Connect ID
  token from Epic's SDK and sends it again each time you start the game, when an expired
  session is resumed at launcher start, and about once an hour while you play
  (`companion/player_session.py`). The launcher never writes Epic tokens to disk itself.
- After your first sign-in, Epic's SDK keeps its own saved login on this PC, which the
  launcher uses to renew your session without showing Epic's page again. The launcher has
  no sign-out that deletes this saved login ("Sign in with another account" only stops it
  from being used automatically). You can revoke TWA Revival's access in your Epic Games
  account settings.
- The project session token, your player ID and display name are stored in plain JSON under
  `%LOCALAPPDATA%\TWARevival\Player` (`companion/config.py`).
- Other players in a match can see your display name and your EOS product user ID.

### 3. Starting the game

- Starts local stand-in services for the original game servers. **They listen only on
  loopback** (127.0.0.1 and ::1) and cannot be reached from other machines:
  TCP 18765 and 443 (HTTP/HTTPS), TCP 5222 and 5223 (XMPP), UDP 19063 and TCP 19000.
- For the duration of the game session it writes:
  - `%APPDATA%\The Creative Assembly\Arena\scripts\User.script.txt` and
    `preferences.script.txt` (window settings, `ONLINE_PLATFORM fake`, the project session
    token and your display name), and
  - `HKCU\Software\The Creative Assembly\Arena\machine_fingerprint`: the MAC address of one
    of your network adapters as 12 hex digits (Python's `uuid.getnode()`, or a random
    number if none is found), only if the value does not exist yet. The game reads it from
    the registry and the local services also return it to the game. The launcher never
    sends it to the project API.

  These are the same per-user locations the official game used. When the game exits, the
  launcher restores session-only bindings, merges supported graphics changes, and removes
  the registry value it created; the registry key itself is left in place
  (`companion/launch_preparation.py`). If cleanup fails or the launcher is killed during
  play, the files and the value can remain. This candidate also validates native
  window-position changes and preserves the original advice setting when the game
  rewrites it during graphics Apply, so those rewrites do not discard valid choices.
- Starts `Arena.exe +auth <project session token>`: created suspended, placed in a Windows
  Job object (so it closes with the launcher) and then resumed. While the game runs, the
  session token is visible on Arena's command line to other programs running as the same
  user.
- **Injects Frida (a dynamic instrumentation toolkit) into that Arena.exe process**
  (`tools/unit_drag_bridge.py`). It only attaches after checking that the process is the
  `client\Arena.exe` in the install folder and that its `game.dll` has an expected hash.
  Frida hooks and patches the running game in memory, and one script allocates executable
  memory in the game and writes new machine code into it. The patches: hand the project
  session token to the stub login library, route the game's settings storage to the local
  services, drag-and-drop loadout editing, party and game-mode handling, a raised squad
  tier-spread limit (squads can mix unit tiers), moving the game's region-ping port from
  UDP 55563 to 19063, career screen columns and a retreat-destination gameplay feature
  (`tools/native_*.py`). These scripts do not write the game's files on disk and are removed
  when the game exits. Antivirus software often flags Frida because it is also used for
  debugging and reverse engineering.
- While the game runs, the helper checks the left mouse button (`GetAsyncKeyState` for the
  left button only) and the cursor position every 10 ms to detect unit-card drags. Button
  presses/releases with their coordinates are written to a local log at
  `%LOCALAPPDATA%\TWARevival\Player\bridge-runs\<run>\unit-drag.jsonl`, including clicks
  made while the game window is not in front (they are marked as such). It never reads the
  keyboard. There is one run folder per game session; they are not deleted automatically
  (they also hold local battle data used by the career screen) and are not uploaded.

### 4. Network use

| Destination | Why |
|---|---|
| `https://downloads.darask.me` | Signed launcher updates, game client updates and install downloads. No account data is sent. |
| `https://staging-api.darask.me` | The project API (the live service, despite its name): sign-in and session renewal, profile, loadout, matchmaking, rooms, battle results, friends and parties. While you play, the launcher refreshes friends/party state every 5 s and sends your online status (online, matchmaking, in battle, offline) every 15 s. |
| Relay address returned by the API | Outbound WebSocket for multiplayer battle traffic. |
| Epic Online Services | Contacted by Epic's EOS SDK for sign-in and session renewal (at game start and about hourly while you play). |
| `learn.microsoft.com` | Opened in your browser only if you click the Visual C++ help button. |

The launcher contains no analytics, advertising or crash-reporting code. Error and crash
logs stay on your PC in `%LOCALAPPDATA%\TWARevival\Player\diagnostics`; the "Open error and
crash logs folder" button only opens that folder. Like any online service, the API and the
relay see your IP address.

### 5. Hosts file fix

Arena looks up 12 names such as `revival-casag.localhost` through Windows. Windows does not
answer `*.localhost` names by itself, so on many PCs the game stopped with error 0xf003.
Before starting the game, the launcher now checks these names. If they do not resolve to
this PC, it shows a **Fix automatically (administrator)** button. Only if you click it,
confirm the dialog **and** approve the Windows administrator (UAC) prompt, it adds a block
like this to your hosts file, flushes the DNS cache and checks again:

```
# BEGIN TWA Revival loopback names
# Added with the player's consent so Arena can reach its local services; delete this block to remove.
127.0.0.1 revival-casag.localhost
... (12 lines, all 127.0.0.1)
# END TWA Revival loopback names
```

The UAC prompt names Python (publisher: Python Software Foundation), because the fix runs
the bundled `runtime\python.exe -B -E -s tools\player_launcher.py --repair-loopback-hosts`
as administrator. Nothing else in the hosts file is changed. Delete the block to undo it
(`tools/loopback_certificate.py`, `tools/player_launcher.py`).

### 6. Automatic updates

The launcher checks for and installs updates automatically, without asking: during
installation, when you press "Check updates", and every time you start the game;
it then restarts itself. Updates must be signed with the release key above, which only
darask holds, and are checked by SHA-256; unsigned, altered or older files are refused
(`companion/self_updater.py`, `companion/updater.py`).

- A launcher update can add or replace any `.py` file under `companion/`, `server/` and
  `tools/`, plus `catalog/*.json`, `companion/VERSION` and `NOTICE.txt`. That covers all of
  the launcher's logic. It cannot replace the bundled runtime, `tools/player_bootstrap.py`
  or `player-release.json`.
- A game client update can replace the client files listed in `COPY_NAMES` in
  `tools/stage_client.py` (including `Arena.exe`, `game.dll`, the NPL DLLs and the Chromium
  (CEF) files), plus `data/wad.pack` and 14 terrain packs.

In practice, whoever holds the release key can change anything described on this page,
and the new code runs with your Windows user rights. This branch shows candidate
0.2.48 source; it does not prove the contents of a future signed release.

### What it does not do

- It installs no services, scheduled tasks, startup entries, firewall rules or certificates.
- It writes nothing under `HKEY_LOCAL_MACHINE`.
- It does not modify an existing official Total War: Arena installation folder (it only
  uses the same per-user settings locations described in step 3).
- It asks for administrator rights only for the optional hosts file fix.

## Notes for reviewers

- `server/local_stack.py` contains an older launch routine (`launch_mode`: DLL swapping,
  WMI process creation, closing leftover Arena processes) that is not reachable from the
  player launcher. `server/xmpp_stub.py` defaults to listening on all interfaces, but the
  launcher never uses it that way.
- The released launcher depends on `catalog/*.json` game data. Those files are intentionally
  excluded here; see [PUBLISHING.md](PUBLISHING.md). This checkout cannot run the game by itself.
- Version 0.2.43 detects the rendering adapter and manages signed low-memory texture
  overlays for a confirmed software renderer (`companion/renderer_probe.py`,
  `companion/texture_memory_compat.py`). The actual texture data is not published here.

## Licence

No licence is granted for this code: it is published so people can read and verify it.
`NOTICE.txt` contains the licences of the third-party components in the ZIP's runtime.
