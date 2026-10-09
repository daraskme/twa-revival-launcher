# Running TWA Revival on Linux (Proton)

> **Community add-on, not part of the signed Windows release.** The files in `linux/` are
> not in `TWA-Launcher.zip`, are not covered by the release key or the hashes in
> `manifests/`, and are not delivered by launcher updates. `verify_release.py` only checks
> that they are the three expected extra files here, not their content. They change no
> launcher file; they add one file to the launcher's bundled runtime (see below). Linux
> support is not tested by the project's release QA.

The launcher and the game are Windows programs. On Linux, all of them run inside one
Proton prefix through [umu-launcher](https://github.com/Open-Wine-Components/umu-launcher):
the bundled `runtime\python.exe`, Epic's EOS SDK, the local stand-in services,
`Arena.exe` and the Frida helper that attaches to it. Frida, Job objects, suspended process
creation, the registry and `tasklist` all work under Proton, so the launcher's own launch
sequence is used unchanged.

A few steps behave differently under Proton. `linux/sitecustomize.py` works around them:

| Windows step | Problem under Proton | What the compatibility layer does |
|---|---|---|
| TLS key for the local services is made with PowerShell (`tools/loopback_certificate.py`) | Proton has no PowerShell, so installation always failed at "applying" | Generates the same self-signed certificate (CN=localhost, same SAN names, 5 years) in pure Python |
| Hosts-file fix writes `C:\Windows\System32\drivers\etc\hosts` | Wine ignores that file; names are resolved by Linux | The fix is reported as unavailable; add the lines to `/etc/hosts` yourself (usually not needed, see below) |
| The launcher waits for Arena with `WaitForInputIdle` (30 s) before attaching the Frida helper | Arena runs, but under Wine it never signals input-idle, so the launcher closed the game | A visible Arena window also counts as ready; up to 120 s for the first DXVK start |
| `os.startfile` on the log folder | Opens Wine's explorer | Opens your Linux file manager |
| Launchers before 0.2.48 reset the game to windowed, at most 1600x900, on every launch | Applies on all platforms; on Linux there is no other way to keep fullscreen | Keeps a valid saved resolution and fullscreen choice, without clamping to the desktop size (the same rule 0.2.48 uses). Turned off automatically from launcher 0.2.48, which does this itself |

It also copies itself into a freshly installed game folder, and does nothing on real Windows.

The file is copied into the launcher's `runtime/Lib/site-packages/`. The bundled Python loads
it at startup through `import site` in `python311._pth`. None of the launcher's `.py` files are
modified. Signed launcher updates replace everything under `companion/`, `server/` and `tools/`
(and refuse to update locally modified files), but they never touch `runtime/`, so the
layer keeps working across updates.

## Requirements

- `umu-launcher` (Arch/CachyOS: `sudo pacman -S umu-launcher`). By default the latest
  GE-Proton is used, and umu downloads it if needed. Set `PROTONPATH` to choose another build.
- **Privileged ports.** Launcher 0.2.43 listens on TCP 18765, 80 and 443, and needs all
  three (they are not alternatives). Launcher 0.2.48 (in QA) no longer uses port 80. By
  default, Linux lets only root listen on ports below 1024. Run this once:

  ```sh
  linux/twa-proton.sh allow-ports
  ```

  This writes `/etc/sysctl.d/60-twa-revival.conf` with
  `net.ipv4.ip_unprivileged_port_start = 80` (or `443` when the launcher in the prefix is
  0.2.48 or newer), which lets programs of every user listen on ports from that number up to
  1023. Delete the file and reboot to undo it. `check` and `run` read the launcher's
  `companion/VERSION`, so after an update to 0.2.48 you can run `allow-ports` again to
  narrow it to 443.
- **`revival-*.localhost` must resolve to 127.0.0.1.** With systemd-resolved or
  nss-myhostname (the default on most desktops) this already works. `linux/twa-proton.sh check`
  tests it and prints the `/etc/hosts` lines to add if it does not.

## Install and play

Download the launcher ZIP from the [project page](https://darask.me/twa/) and verify it
**before** `setup`, with the verifier from this repository at the matching version (this
`main` snapshot is 0.2.43):

```sh
python3 -I verify_release.py --zip ~/Downloads/TWA-Launcher-0.2.43.zip
```

Continue only if it prints `All checks passed.` Then:

```sh
linux/twa-proton.sh check                                   # prerequisites
linux/twa-proton.sh setup ~/Downloads/TWA-Launcher.zip      # first time only
linux/twa-proton.sh                                         # every time after that
linux/twa-proton.sh desktop                                 # optional: application menu entry
```

`setup` creates the prefix (default `~/Games/twa-revival`, change with `TWA_PREFIX`),
unpacks the launcher into a temporary folder next to `C:\TWARevival-Launcher`, checks it,
moves it into place, and opens it. If the input is wrong or unpacking fails, the temporary
folder is removed and nothing blocks a retry. Keep the suggested
install location. The game is downloaded into
`C:\users\steamuser\AppData\Local\TWARevival\Game` and the launcher continues from there.
Later runs start that installed copy. Epic sign-in opens in your normal Linux browser.

### Lutris, Bottles, Heroic

Use any Proton/Wine prefix you like, but run the launcher's `runtime\python.exe` with
`-B tools\player_bootstrap.py` (what `Launch TWA.cmd` does). Copy the compatibility
layer into each launcher folder first: the unpacked ZIP, and after installation the game
folder (a new installation copies it automatically):

```sh
linux/twa-proton.sh patch /path/to/prefix/drive_c/.../TWA-Launcher
```

Do not unpack the ZIP into the folder you then install to. The installer needs a new, empty
destination.

## Known issues

- Private games currently fail when the battle starts (the launcher reports `private_coordinator_failed`). 
