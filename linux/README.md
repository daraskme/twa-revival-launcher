# Running TWA Revival on Linux (Proton)

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

It also copies itself into a freshly installed game folder, and does nothing on real Windows.

The file is copied into the launcher's `runtime/Lib/site-packages/`. The bundled Python loads
it at startup through `import site` in `python311._pth`. None of the launcher's `.py` files are
modified. Signed launcher updates replace everything under `companion/`, `server/` and `tools/`
(and refuse to update locally modified files), but they never touch `runtime/`, so the
layer keeps working across updates.

## Requirements

- `umu-launcher` (Arch/CachyOS: `sudo pacman -S umu-launcher`). By default the latest
  GE-Proton is used, and umu downloads it if needed. Set `PROTONPATH` to choose another build.
- **Ports 80 and 443.** Arena talks to the local services on these ports. By default, Linux
  lets only root listen on ports below 1024. Run this once:

  ```sh
  linux/twa-proton.sh allow-ports
  ```

  This writes `/etc/sysctl.d/60-twa-revival.conf` with
  `net.ipv4.ip_unprivileged_port_start = 80`, which lets programs of every user listen on
  ports 80–1023. Delete the file and reboot to undo it.
- **`revival-*.localhost` must resolve to 127.0.0.1.** With systemd-resolved or
  nss-myhostname (the default on most desktops) this already works. `linux/twa-proton.sh check`
  tests it and prints the `/etc/hosts` lines to add if it does not.

## Install and play

```sh
linux/twa-proton.sh check                                   # prerequisites
linux/twa-proton.sh setup ~/Downloads/TWA-Launcher.zip      # first time only
linux/twa-proton.sh                                         # every time after that
linux/twa-proton.sh desktop                                 # optional: application menu entry
```

`setup` creates the prefix (default `~/Games/twa-revival`, change with `TWA_PREFIX`),
unpacks the launcher to `C:\TWARevival-Launcher` in it, and opens it. Keep the suggested
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
