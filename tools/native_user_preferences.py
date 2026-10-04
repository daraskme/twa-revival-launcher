"""Route only the owned native preference object to its loopback bridge.

Arena's S3 client ignores aws_s3_host and constructs s3.local.amazonaws.com
from the diagnostic region. No Amazon endpoint is needed for local UI state.
The exact DLL, curl entry point, bucket and authenticated user are bound here.
"""
import hashlib
import json
from pathlib import Path
import re
from tools.player_native_payload import GAME_HASH

GAME_SHA256='4fc11b6e734042ee0c7d0df54bc5c7f689f2d7842c450e4df541e22310804013'
GAME_SHA256S=frozenset({GAME_SHA256, '4e622f6934e0ba552b93ef546bec5dacdb0d7ae47d28b0c823959b52fdd08f15', 'f760ece7869a3e254376f927ee610675cab8112fafb502c6c18e90c30664fc0c', '884e30f841d6a1268b7cc918fa2d14b972f007ce593b957fd3d1ee93c75cbf0a', 'b5d1547b720fd03f1e55e76e2d41b531d2d72e0b4a6270c73223018b8cd45e06', GAME_HASH})

def local_storage_url(url: str, user_id: str, *, local_lab: bool = False) -> str | None:
    if not (re.fullmatch(r'[0-9a-f]{32}',user_id)
            or (local_lab is True and user_id == 'player')):
        raise ValueError('invalid_native_preference_identity')
    expected=f'https://s3.local.amazonaws.com/revival-user-storage.localhost/{user_id}/blob'
    return f'http://127.0.0.1:18765/{user_id}/blob' if url==expected else None

SOURCE=r'''
(() => {
 if(Process.arch!=='ia32')throw Error('native_preferences_arch_mismatch');
 const game=Process.getModuleByName('game.dll');
 const normalize=p=>p.replaceAll('/','\\').toLowerCase();
 if(normalize(game.path)!==normalize(__GAME_PATH__))throw Error('native_preferences_path_mismatch');
 const setopt=game.base.add(0x1abbd0);
 const anchor='558bec8b450885c07507b82b0000005dc3';
 const actual=Array.from(new Uint8Array(setopt.readByteArray(anchor.length/2)),b=>b.toString(16).padStart(2,'0')).join('');
 if(actual!==anchor)throw Error('native_preferences_curl_anchor_mismatch');
 const expected=__EXPECTED__;
 const target=__TARGET__;
 Interceptor.attach(setopt,{
  onEnter(args){
   this.url=null;
   if(args[1].toInt32()!==10002)return;
   if(args[2].isNull())return;
   const supplied=args[2].readUtf8String();
   if(supplied!==expected)return;
   this.url=Memory.allocUtf8String(target);args[2]=this.url;
   send({kind:'native_preferences_routed'});
  },
  onLeave(){this.url=null;}
 });
 send({kind:'native_preferences_ready'});
})();
'''

def build_source(root:Path,user_id:str, *, local_lab: bool = False)->str:
    expected=f'https://s3.local.amazonaws.com/revival-user-storage.localhost/{user_id}/blob'
    target=local_storage_url(expected,user_id,local_lab=local_lab)
    path=root/'client/game.dll'
    if not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() not in GAME_SHA256S:
        raise RuntimeError('native_preferences_game_mismatch')
    return SOURCE.replace('__GAME_PATH__',json.dumps(str(path.resolve()))).replace('__EXPECTED__',json.dumps(expected)).replace('__TARGET__',json.dumps(target))
