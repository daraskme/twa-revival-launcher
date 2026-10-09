#!/usr/bin/env bash
# Run the TWA Revival launcher and the game on Linux through Proton (umu-launcher).
#
# The whole Windows launcher runs inside one Proton prefix: its bundled
# runtime\python.exe, Epic's EOS SDK, the local services, Arena.exe and the
# Frida helper that attaches to Arena. Nothing Windows-specific is emulated on
# the Linux side; linux/sitecustomize.py (copied into the launcher's runtime)
# only replaces the steps that need PowerShell or the Windows hosts file.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")" && pwd)"
COMPAT_SOURCE="$SCRIPT_DIR/sitecustomize.py"

TWA_PREFIX="${TWA_PREFIX:-$HOME/Games/twa-revival}"
export PROTONPATH="${PROTONPATH:-GE-Proton}"   # umu downloads the latest GE-Proton
export GAMEID="${GAMEID:-umu-0}"
SETUP_DIR_NAME="TWARevival-Launcher"           # C:\TWARevival-Launcher
LOOPBACK_SERVICES=(casag camm causer caprofile carpg calb casa xmpp capromo cacugs casteampayment camuc)

usage() {
    cat <<EOF
Usage: ${0##*/} [command]

  setup <TWA-Launcher.zip|folder>  Put the Windows launcher into the Proton prefix and
                                   open it to install the game (first time only).
  run                              Start the launcher (default). Uses the installed game
                                   if there is one, otherwise continues the setup.
  check                            Check the Linux prerequisites.
  allow-ports                      One-time system change (sudo) so the local services
                                   can listen on TCP 80 and 443 (0.2.48+: only 443).
  patch <launcher folder>          Only copy the Wine compatibility layer into an existing
                                   launcher folder (for Lutris, Bottles, Heroic, ...).
  desktop                          Add a "TWA Revival" entry to the application menu.
  wine <program> [args...]         Run a program in the prefix (e.g. winecfg).

Environment:
  TWA_PREFIX    Wine prefix to use (default: ~/Games/twa-revival; now: $TWA_PREFIX)
  PROTONPATH    Proton build for umu-run (default: GE-Proton, the latest GE-Proton)
  TWA_GAME_DIR  Installed game folder, if you installed outside the default location
EOF
}

die() {
    echo "TWA Revival: $*" >&2
    if [[ ! -t 2 ]] && command -v notify-send >/dev/null 2>&1; then
        notify-send -a "TWA Revival" "TWA Revival" "$*" || true
    fi
    exit 1
}

warn() { echo "TWA Revival: warning: $*" >&2; }

require_umu() {
    command -v umu-run >/dev/null 2>&1 \
        || die "umu-run is not installed. Install umu-launcher (Arch/CachyOS: 'sudo pacman -S umu-launcher')."
}

umu() {
    require_umu
    mkdir -p "$TWA_PREFIX"
    WINEPREFIX="$TWA_PREFIX" umu-run "$@"
}

drive_c() { realpath -m "$TWA_PREFIX/drive_c"; }

# Linux path -> Windows path as the launcher sees it (C: for the prefix, Z: otherwise).
to_windows() {
    local path c
    path="$(realpath -m "$1")"
    c="$(drive_c)"
    if [[ "$path" == "$c" || "$path" == "$c"/* ]]; then
        path="C:${path#"$c"}"
    else
        path="Z:$path"
    fi
    printf '%s' "${path//\//\\}"
}

# Windows path (C:\... or Z:\...) -> Linux path.
to_linux() {
    local path="${1//\\//}"
    case "${path:0:2}" in
        [Cc]:) printf '%s' "$(drive_c)${path:2}" ;;
        [Zz]:) printf '%s' "${path:2}" ;;
        *) return 1 ;;
    esac
}

is_launcher() { [[ -f "$1/tools/player_bootstrap.py" && -f "$1/runtime/python.exe" ]]; }

state_dirs() {
    local dir
    for dir in "$(drive_c)"/users/*/AppData/Local/TWARevival; do
        [[ -d "$dir" ]] && printf '%s\n' "$dir"
    done
}

# The installed game: TWA_GAME_DIR, the folder chosen in the installer, or the default.
find_installed() {
    local candidates=() state destination dir
    [[ -n "${TWA_GAME_DIR:-}" ]] && candidates+=("$TWA_GAME_DIR")
    while IFS= read -r state; do
        if [[ -f "$state/Player/installer-request.json" ]] && command -v python3 >/dev/null 2>&1; then
            destination="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["destination"])' \
                "$state/Player/installer-request.json" 2>/dev/null || true)"
            [[ -n "$destination" ]] && candidates+=("$(to_linux "$destination" || true)")
        fi
        candidates+=("$state/Game")
    done < <(state_dirs)
    for dir in "${candidates[@]}"; do
        if [[ -n "$dir" ]] && is_launcher "$dir" && [[ -f "$dir/client/Arena.exe" ]]; then
            printf '%s' "$dir"
            return 0
        fi
    done
    return 1
}

install_compat() {
    local root="$1" target
    [[ -f "$COMPAT_SOURCE" ]] || die "missing $COMPAT_SOURCE"
    is_launcher "$root" || die "$root is not a TWA Revival launcher folder"
    target="$root/runtime/Lib/site-packages/sitecustomize.py"
    if ! cmp -s "$COMPAT_SOURCE" "$target"; then
        cp -- "$COMPAT_SOURCE" "$target"
        echo "TWA Revival: installed the Wine compatibility layer into $root/runtime"
    fi
}

# Lowest privileged port the launcher in $1 listens on: launchers before 0.2.48
# need TCP 80 and 443, 0.2.48 and later only 443. Unknown launcher: 80.
lowest_port() {
    local version
    version="$(tr -d '[:space:]' 2>/dev/null <"${1:-}/companion/VERSION" || true)"
    if [[ -n "$version" ]] && [[ "$(printf '%s\n' 0.2.48 "$version" | sort -V | head -n1)" == 0.2.48 ]]; then
        echo 443
    else
        echo 80
    fi
}

ports_text() { [[ "$(lowest_port "${1:-}")" == 80 ]] && echo "80 and 443" || echo "443"; }

check_ports() {
    local start
    start="$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start 2>/dev/null || echo 1024)"
    (( start <= $(lowest_port "${1:-}") ))
}

# The installed game, otherwise the setup copy in the prefix.
current_launcher() {
    find_installed || { is_launcher "$(drive_c)/$SETUP_DIR_NAME" && printf '%s' "$(drive_c)/$SETUP_DIR_NAME"; }
}

check_names() {
    local service missing=()
    for service in "${LOOPBACK_SERVICES[@]}"; do
        getent ahostsv4 "revival-$service.localhost" 2>/dev/null | grep -q '^127\.' \
            || missing+=("revival-$service.localhost")
    done
    if (( ${#missing[@]} )); then
        printf '%s\n' "${missing[@]}"
        return 1
    fi
}

cmd_check() {
    local ok=0 missing root
    root="$(current_launcher || true)"
    if command -v umu-run >/dev/null 2>&1; then
        echo "ok    umu-run: $(command -v umu-run)"
    else
        echo "FAIL  umu-run is not installed (Arch/CachyOS: sudo pacman -S umu-launcher)"; ok=1
    fi
    if check_ports "$root"; then
        echo "ok    ports $(ports_text "$root") can be opened by normal users"
    else
        echo "FAIL  ports $(ports_text "$root") need root. Run: ${0##*/} allow-ports"; ok=1
    fi
    if missing="$(check_names)"; then
        echo "ok    revival-*.localhost resolves to 127.0.0.1"
    else
        echo "FAIL  these names do not resolve to 127.0.0.1; add to /etc/hosts:"
        echo "# BEGIN TWA Revival loopback names"
        sed 's/^/127.0.0.1 /' <<<"$missing"
        echo "# END TWA Revival loopback names"
        ok=1
    fi
    echo "      prefix: $TWA_PREFIX"
    local installed
    if installed="$(find_installed)"; then
        echo "      installed game: $installed"
    elif is_launcher "$(drive_c)/$SETUP_DIR_NAME"; then
        echo "      setup launcher: $(drive_c)/$SETUP_DIR_NAME (game not installed yet)"
    else
        echo "      nothing set up yet: ${0##*/} setup <TWA-Launcher.zip>"
    fi
    return $ok
}

cmd_allow_ports() {
    local conf=/etc/sysctl.d/60-twa-revival.conf root port
    root="${1:-$(current_launcher || true)}"
    port="$(lowest_port "$root")"
    echo "This lets programs of every user on this PC listen on ports $port-1023"
    echo "(needed because the launcher's local services listen on TCP $(ports_text "$root"))."
    echo "It writes $conf and applies it now. Delete that file to undo."
    echo "net.ipv4.ip_unprivileged_port_start = $port" | sudo tee "$conf" >/dev/null
    sudo sysctl -q -w "net.ipv4.ip_unprivileged_port_start=$port"
    echo "Done."
}

launch() {
    local root="$1"
    install_compat "$root"
    cd -- "$root"
    exec env WINEPREFIX="$TWA_PREFIX" umu-run \
        "$(to_windows "$root/runtime/python.exe")" -B "$(to_windows "$root/tools/player_bootstrap.py")"
}

cmd_setup() {
    local source="${1:-}" target staging
    [[ -n "$source" ]] || die "usage: ${0##*/} setup <TWA-Launcher.zip|folder>"
    require_umu
    target="$(drive_c)/$SETUP_DIR_NAME"
    if [[ -e "$target" ]]; then
        is_launcher "$target" || die "$target exists and is not a launcher folder; move it away first"
        echo "TWA Revival: the launcher is already in the prefix ($target); starting it."
    else
        if [[ -d "$source" ]]; then
            is_launcher "$source" || die "$source is not an unpacked TWA-Launcher ZIP"
        elif [[ ! -f "$source" ]]; then
            die "$source does not exist"
        fi
        if [[ ! -d "$TWA_PREFIX/drive_c" ]]; then
            echo "TWA Revival: creating the Proton prefix in $TWA_PREFIX ..."
            umu wineboot -u >/dev/null 2>&1 || true
            [[ -d "$TWA_PREFIX/drive_c" ]] || die "could not create the prefix in $TWA_PREFIX"
        fi
        # Unpack next to the target and move it into place only when complete, so a
        # failed or wrong input leaves nothing behind that blocks the next attempt.
        staging="$(mktemp -d "$(drive_c)/.$SETUP_DIR_NAME.XXXXXX")"
        trap 'rm -rf -- "$staging"' EXIT
        if [[ -d "$source" ]]; then
            cp -a -- "$source"/. "$staging"/
        elif command -v python3 >/dev/null 2>&1; then
            python3 -m zipfile -e "$source" "$staging" || die "could not unpack $source"
        elif command -v unzip >/dev/null 2>&1; then
            unzip -q "$source" -d "$staging" || die "could not unpack $source"
        else
            die "need python3 or unzip to unpack $source"
        fi
        is_launcher "$staging" || die "$source does not contain the TWA Revival launcher"
        mv -T -- "$staging" "$target"
        trap - EXIT
        echo "TWA Revival: launcher unpacked to $target"
    fi
    if ! check_ports "$target"; then
        local answer=n
        if [[ -t 0 ]]; then
            echo "TWA Revival: the launcher's local services need TCP $(ports_text "$target"), which Linux reserves for root."
            read -r -p "Allow them now (runs sudo, see '${0##*/} allow-ports')? [Y/n] " answer || answer=n
            [[ -z "$answer" ]] && answer=y
        fi
        if [[ "$answer" == [Yy]* ]]; then
            cmd_allow_ports "$target"
        else
            warn "ports $(ports_text "$target") are not allowed; installing works, but starting the game fails until you run '${0##*/} allow-ports'."
            if command -v notify-send >/dev/null 2>&1; then
                notify-send -a "TWA Revival" "TWA Revival" "Run '${0##*/} allow-ports' once before starting the game." || true
            fi
        fi
    fi
    echo "TWA Revival: keep the suggested install location; the game is downloaded into the prefix."
    launch "$target"
}

cmd_run() {
    local root
    if root="$(find_installed)"; then
        if [[ -z "${TWA_SKIP_CHECKS:-}" ]]; then
            check_ports "$root" || die "the launcher's local services need TCP $(ports_text "$root"). Run '${0##*/} allow-ports' once (or set TWA_SKIP_CHECKS=1)."
            check_names >/dev/null || warn "some revival-*.localhost names do not resolve to 127.0.0.1; see '${0##*/} check'."
        fi
        launch "$root"
    elif is_launcher "$(drive_c)/$SETUP_DIR_NAME"; then
        launch "$(drive_c)/$SETUP_DIR_NAME"
    else
        die "nothing is set up in $TWA_PREFIX yet. Run: ${0##*/} setup <TWA-Launcher.zip>"
    fi
}

cmd_desktop() {
    local file="${XDG_DATA_HOME:-$HOME/.local/share}/applications/twa-revival.desktop"
    mkdir -p -- "$(dirname -- "$file")"
    cat >"$file" <<EOF
[Desktop Entry]
Type=Application
Name=TWA Revival
Comment=Total War: Arena fan revival (Proton)
Exec=env TWA_PREFIX="$TWA_PREFIX" "$SCRIPT_DIR/twa-proton.sh" run
Icon=applications-games
Categories=Game;
Terminal=false
EOF
    echo "TWA Revival: created $file"
}

case "${1:-run}" in
    setup) shift; cmd_setup "$@" ;;
    run) cmd_run ;;
    check) cmd_check ;;
    allow-ports) cmd_allow_ports ;;
    patch) shift; [[ -n "${1:-}" ]] || die "usage: ${0##*/} patch <launcher folder>"; install_compat "$1" ;;
    desktop) cmd_desktop ;;
    wine) shift; umu "$@" ;;
    -h|--help|help) usage ;;
    *) usage >&2; exit 2 ;;
esac
