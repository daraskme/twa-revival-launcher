"""Signed, resumable base-game delivery; no account credentials are sent.

Only complete SHA-256 verified compressed chunks enter the cache. Completed
base trees are immutable read-only sources for install_player, never live game
targets. A canceled transfer retains verified chunks for the next invocation.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
import uuid
import zlib

from .client_lock import client_operation_lock
from .manifest import verify_signature, ManifestError
from .trusted_keys import RELEASE_TRUSTED_KEYS
from .self_updater import _safe, version_key
from tools.player_package import _relative
from tools.stage_client import COPY_NAMES, _remove_staging_tree

CHUNK_SIZE = 16 * 1024 * 1024
MAX_WIRE_CHUNK = CHUNK_SIZE + 65536
MAX_MANIFEST = 4 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024 * 1024
MAX_FILES = 8192
HASH = re.compile(r'[0-9a-f]{64}\Z')
DEV_KEY = 'a471d9e62d9c0a1cb7abd46c80a76ec3cbc26bfd5ea6c47827075e1b3c01d3bb'
from .trusted_keys import PUBLIC_DOWNLOAD_ORIGIN


class DownloadError(RuntimeError):
    pass


class DownloadPaused(DownloadError):
    pass


def origin(value):
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment
            or parsed.hostname.rstrip('.').lower() == 'localhost'):
        raise DownloadError('invalid download origin')
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return value.rstrip('/')
    raise DownloadError('invalid download origin')


def base_path(name):
    parts = _relative(name)
    if (len(parts) == 1 and (name in COPY_NAMES or re.fullmatch(r'api-ms-win-[A-Za-z0-9_-]+\.dll', name))
            or len(parts) >= 2 and parts[0] in ('data', 'cef')):
        return name
    raise DownloadError('invalid base game path')


def validate(value, channel='stable', *, kind='base-game'):
    if kind not in ('base-game', 'native-payload'):
        raise DownloadError('invalid content kind')
    expected = {'schemaVersion','kind','channel','version','createdAt','publicKeyId','signature','files','assetOrigin'}
    if (not isinstance(value, dict) or set(value) != expected or type(value['schemaVersion']) is not int
            or value['schemaVersion'] != 1 or value['kind'] != kind
            or channel not in ('stable','beta') or value['channel'] != channel
            or type(value['createdAt']) is not int or not 0 < value['createdAt'] <= time.time()*1000+300000):
        raise DownloadError('invalid base manifest')
    if version_key(value['version']) < ((1,0,0) if kind == 'base-game' else (0,2,1)):
        raise DownloadError('base game is too old')
    if value['assetOrigin'] is not None:
        origin(value['assetOrigin'])
    rows = value['files']
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_FILES:
        raise DownloadError('invalid base files')
    seen, chunks, total = set(), {}, 0
    for row in rows:
        if not isinstance(row,dict) or set(row) != {'path','size','sha256','chunks'}:
            raise DownloadError('invalid base file')
        if kind == 'native-payload':
            from tools.player_native_payload import DOWNLOAD_HASHES
            _relative(row['path'])
            if row['path'] not in DOWNLOAD_HASHES or row['sha256'] != DOWNLOAD_HASHES[row['path']]:
                raise DownloadError('unreviewed native payload')
            name = row['path'].casefold()
        else:
            name = base_path(row['path']).casefold()
        if (name in seen or type(row['size']) is not int or not 0 <= row['size'] <= MAX_TOTAL
                or not isinstance(row['sha256'],str) or not HASH.fullmatch(row['sha256'])):
            raise DownloadError('invalid base file')
        # No file may double as another file's directory (case-insensitive).
        if any(name.startswith(p+'/') or p.startswith(name+'/') for p in seen):
            raise DownloadError('base path collision')
        seen.add(name)
        if (not isinstance(row['chunks'],list)
                or len(row['chunks']) != (row['size']+CHUNK_SIZE-1)//CHUNK_SIZE):
            raise DownloadError('invalid chunk count')
        remaining = row['size']
        for chunk in row['chunks']:
            if (not isinstance(chunk,dict) or set(chunk) != {'sha256','size','rawSize'}
                    or not isinstance(chunk['sha256'],str) or not HASH.fullmatch(chunk['sha256'])
                    or type(chunk['size']) is not int or not 1 <= chunk['size'] <= MAX_WIRE_CHUNK
                    or type(chunk['rawSize']) is not int or chunk['rawSize'] != min(CHUNK_SIZE,remaining)):
                raise DownloadError('invalid chunk')
            previous = chunks.setdefault(chunk['sha256'], chunk)
            if previous != chunk:
                raise DownloadError('inconsistent chunk')
            remaining -= chunk['rawSize']
        total += row['size']
    if kind == 'native-payload':
        if seen != {name.casefold() for name in DOWNLOAD_HASHES}:
            raise DownloadError('incomplete native payload')
    elif not {name.casefold() for name in COPY_NAMES} <= seen or not any(p.startswith('data/') for p in seen):
        raise DownloadError('incomplete base game')
    if total > MAX_TOTAL:
        raise DownloadError('base game too large')
    return value


def verified(value, channel='stable', *, trusted_keys=None, kind='base-game'):
    validate(value, channel, kind=kind)
    keys = RELEASE_TRUSTED_KEYS if trusted_keys is None else trusted_keys
    if (not isinstance(keys,dict) or not keys or any(not isinstance(key,str)
            or not re.fullmatch(r'[a-fA-F0-9]{64}',key) or key.lower() == DEV_KEY for key in keys.values())):
        raise DownloadError('download signing keys not configured')
    try:
        verify_signature(value, keys)
    except ManifestError:
        raise DownloadError('base manifest signature failed') from None
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise DownloadError('download redirect refused')


def fetch(url, limit, cancel):
    request = urllib.request.Request(url, headers={
        'Accept-Encoding':'identity', 'User-Agent':'TWA-Revival-Launcher/1.0',
    }, method='GET')
    for attempt in range(3):
        if cancel.is_set():
            raise DownloadPaused('download paused')
        try:
            with urllib.request.build_opener(_NoRedirect()).open(request, timeout=30) as response:
                if response.status != 200 or response.headers.get('Content-Encoding','identity') != 'identity':
                    raise DownloadError('unexpected download response')
                result = bytearray()
                while True:
                    if cancel.is_set():
                        raise DownloadPaused('download paused')
                    data = response.read(min(1024*1024, limit+1-len(result)))
                    if not data:
                        return bytes(result)
                    result.extend(data)
                    if len(result) > limit:
                        raise DownloadError('download exceeds expected size')
        except urllib.error.HTTPError as exc:
            if attempt == 2 or exc.code not in (429,500,502,503,504):
                raise DownloadError('download service unavailable') from None
            delay = min(60, max(1, int(exc.headers.get('Retry-After','5')))) if exc.headers.get('Retry-After','5').isdigit() else 5
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt == 2:
                raise DownloadError('download connection failed') from None
            delay = 2**attempt
        if cancel.wait(delay):
            raise DownloadPaused('download paused')
    raise DownloadError('download failed')


def _unique(pairs):
    value = {}
    for key,item in pairs:
        if key in value:
            raise DownloadError('duplicate manifest field')
        value[key] = item
    return value


def _hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda:handle.read(1024*1024),b''):
            digest.update(chunk)
    return digest.hexdigest()


def _matches(path, row):
    if not path.exists():
        return False
    _safe(path)
    return path.stat().st_size == row['size'] and _hash(path) == row['sha256']


def download_public(cache, **kwargs):
    """Initial content delivery does not require Epic or control-API settings."""
    return download(PUBLIC_DOWNLOAD_ORIGIN, cache, static_manifest=True, **kwargs)


def download_native(cache, **kwargs):
    """Fetch every reviewed native/language asset outside the launcher ZIP."""
    target = download(PUBLIC_DOWNLOAD_ORIGIN, cache, static_manifest=True,
                      kind='native-payload', **kwargs)
    from tools.player_native_payload import rows
    rows(target)
    return target


def download(service, cache, *, channel='stable', cancel=None, progress=lambda done,total:None,
             fetcher=fetch, trusted_keys=None, static_manifest=False, kind='base-game'):
    service = origin(service)
    if channel not in ('stable', 'beta'):
        raise DownloadError('invalid download channel')
    if kind not in ('base-game', 'native-payload') or (kind == 'native-payload' and not static_manifest):
        raise DownloadError('invalid content kind')
    cancel = cancel if cancel is not None else threading.Event()
    prefix = 'base-game-manifests' if kind == 'base-game' else 'native-manifests'
    manifest_url = (service+'/'+prefix+'/'+channel+'.json' if static_manifest else
                    service+'/v1/update/base-game-manifest?channel='+channel)
    raw = fetcher(manifest_url, MAX_MANIFEST, cancel)
    if len(raw) > MAX_MANIFEST:
        raise DownloadError('base manifest too large')
    value = verified(json.loads(raw, object_pairs_hook=_unique), channel, trusted_keys=trusted_keys, kind=kind)
    manifest_id = hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    cache = _safe(Path(cache), directory=True, missing=True)
    cache.mkdir(parents=True, exist_ok=True)
    with client_operation_lock(cache/'download-operation'):
        objects = _safe(cache/'objects', directory=True, missing=True)
        objects.mkdir(exist_ok=True)
        target = _safe(cache/(('base-' if kind == 'base-game' else 'native-')+manifest_id), directory=True, missing=True)
        if target.exists():
            if all(_matches(target/row['path'], row) for row in value['files']):
                return target
            raise DownloadError('completed base cache was modified')
        unique = {c['sha256']:c for row in value['files'] for c in row['chunks']}
        total = sum(c['size'] for c in unique.values())
        required = sum(row['size'] for row in value['files']) + sum(
            c['size'] for c in unique.values() if not _matches(objects/c['sha256'], c))
        if shutil.disk_usage(cache).free < required + 512*1024*1024:
            raise DownloadError('insufficient download space')
        done = 0
        for key, chunk in unique.items():
            if cancel.is_set():
                raise DownloadPaused('download paused')
            path = _safe(objects/key, missing=True)
            if not _matches(path,chunk):
                # The CDN origin is signed with the file list. No session,
                # cookies, API key or Authorization header travels to it.
                object_url = ((origin(value['assetOrigin'])+'/objects/'+kind+'/'+key)
                    if value['assetOrigin'] else service+'/v1/update/object/base-game/'+key)
                content = fetcher(object_url, chunk['size'], cancel)
                if len(content) != chunk['size'] or hashlib.sha256(content).hexdigest() != key:
                    raise DownloadError('download chunk integrity failed')
                descriptor, temporary = tempfile.mkstemp(prefix='.chunk-', dir=objects)
                try:
                    with os.fdopen(descriptor,'wb') as handle:
                        handle.write(content)
                        handle.flush()
                        os.fsync(handle.fileno())
                    _safe(path,missing=True)
                    os.replace(temporary,path)
                finally:
                    Path(temporary).unlink(missing_ok=True)
            done += chunk['size']
            progress(done,total)
        staging = cache/('.assemble-'+uuid.uuid4().hex)
        staging.mkdir()
        try:
            if kind == 'base-game':
                (staging/'data').mkdir()
                (staging/'cef').mkdir()
            for row in value['files']:
                path = staging/row['path']
                path.parent.mkdir(parents=True,exist_ok=True)
                digest = hashlib.sha256()
                with path.open('xb') as handle:
                    for chunk in row['chunks']:
                        if cancel.is_set():
                            raise DownloadPaused('download paused')
                        compressed = _safe(objects/chunk['sha256']).read_bytes()
                        if len(compressed) != chunk['size'] or hashlib.sha256(compressed).hexdigest() != chunk['sha256']:
                            raise DownloadError('cached chunk changed')
                        decoder = zlib.decompressobj()
                        data = decoder.decompress(compressed,chunk['rawSize']+1)
                        if (len(data) != chunk['rawSize'] or not decoder.eof
                                or decoder.unused_data or decoder.unconsumed_tail):
                            raise DownloadError('invalid compressed chunk')
                        handle.write(data)
                        digest.update(data)
                if path.stat().st_size != row['size'] or digest.hexdigest() != row['sha256']:
                    raise DownloadError('assembled base integrity failed')
            os.rename(staging,target)
        finally:
            if staging.exists():
                if staging.parent != cache or staging.is_symlink():
                    raise DownloadError('unsafe assembly cleanup')
                _remove_staging_tree(staging)
        return target
