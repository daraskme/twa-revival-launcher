"""Small fixed entry point. Recover interrupted updates before importing the GUI.

The launcher update manifest cannot replace this bootstrap or the interpreter.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    arguments = sys.argv[1:]
    active = ROOT / '.twa-launcher-update-active.json'
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    if active.exists():
        if active.stat().st_size > 1024:
            raise RuntimeError('Invalid launcher recovery record')
        value = json.loads(active.read_bytes())
        if (not isinstance(value, dict) or set(value) != {'transaction'}
                or not isinstance(value['transaction'], str) or not re.fullmatch('[0-9a-f]{32}', value['transaction'])):
            raise RuntimeError('Invalid launcher recovery record')
        helper = ROOT / '.launcher-updates' / value['transaction'] / 'runner/tools/apply_launcher_update.py'
        result = subprocess.run([sys.executable, '-B', str(helper), '--root', str(ROOT),
            '--transaction', value['transaction'], '--recover'], cwd=ROOT,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=60, creationflags=flags)
        if result.returncode != 0 or active.exists():
            raise RuntimeError('Launcher recovery could not finish. Close the game and try again.')
        journal = json.loads((helper.parents[2] / 'journal.json').read_bytes())
        if '--update-result' not in arguments:
            arguments = ['--update-result', 'updated' if journal['phase'] == 'complete' else 'restored', *arguments]
    return subprocess.run([sys.executable, '-B', str(ROOT / 'tools/player_launcher.py'), *arguments],
        cwd=ROOT, creationflags=flags).returncode


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        # No mutable launcher imports are safe when recovery has failed.
        if os.name == 'nt':
            import ctypes
            ctypes.windll.user32.MessageBoxW(None,
                'Launcher recovery could not finish. Close TWA and try again.\n'
                'ランチャーの復元を完了できません。ゲームを終了して再試行してください。\n'
                'Не удалось восстановить лаунчер. Закройте игру и повторите попытку.',
                'TWA Revival', 0x10)
        raise SystemExit(1) from None
