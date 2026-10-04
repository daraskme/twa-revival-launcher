"""Native retreat destination chooser for the exact reviewed x86 client.

All frame work stays in native instructions. The UI state is process-local;
the selected point still travels through the normal SET_LOCATION command.
The simulation redirect must be installed on every client before multiplayer.
"""

BUILD_JS = r'''
function buildRetreatCode(game, state, caves, processLifetime=false) {
  class Block {
    constructor(base) { this.base=base; this.bytes=[]; this.labels={}; this.fixups=[]; }
    hex(s) { this.bytes.push(...s.match(/../g).map(x=>parseInt(x,16))); return this; }
    u32(n) { for(let i=0;i<4;i++)this.bytes.push((n>>>(i*8))&255); return this; }
    label(n) { if(n in this.labels)throw Error('duplicate label');this.labels[n]=this.bytes.length; }
    branch(op,target) { this.hex(op);this.fixups.push([this.bytes.length,target]);this.u32(0); }
    done() {
      for(const [at,target] of this.fixups) {
        const address=typeof target==='number'?target:this.base+this.labels[target];
        if(!Number.isSafeInteger(address))throw Error('missing label');
        const relative=(address-(this.base+at+4))>>>0;
        for(let i=0;i<4;i++)this.bytes[at+i]=(relative>>>(8*i))&255;
      }
      return this.bytes;
    }
  }
  // state: main, player, clicked point, active, frame budget, setup, army,
  // approved test setup, or process-lifetime enabled flag. Zero disables.
  const f=new Block(caves.frame);
  f.hex('5051528b978c020000'); // save eax/ecx/edx; player = main+28C
  f.hex('833d').u32(state+12).hex('00');f.branch('0f84','idle');
  f.hex('393d').u32(state);f.branch('0f85','cancel');
  f.hex('3915').u32(state+4);f.branch('0f85','cancel');
  f.hex('85d2');f.branch('0f84','cancel');
  f.hex('8b82540100003b05').u32(state+24);f.branch('0f85','cancel');
  f.hex('8b879001000085c0');f.branch('0f84','cancel');
  f.hex('8b40503b05').u32(state+20);f.branch('0f85','cancel');
  f.hex('80ba6801000000');f.branch('0f84','cancel');
  f.hex('80ba6901000000');f.branch('0f85','cancel');
  f.hex('83ba6001000000');f.branch('0f85','cancel');
  f.hex('80bfb60d000000');f.branch('0f85','cancel'); // second retreat cancels
  f.hex('ff0d').u32(state+16);f.branch('0f84','cancel');
  f.hex('a1').u32(state+8).hex('85c0');f.branch('0f84','finish');
  f.hex('3987b80d0000');f.branch('0f85','finish');
  f.hex('39825c010000');f.branch('0f85','finish'); // wait for normal command echo
  f.hex('c687b60d000001');f.branch('e9','clear');
  f.label('idle');
  f.hex('80bfb60d000000');f.branch('0f84','finish');
  f.hex('8b879001000085c0');f.branch('0f84','finish');
  f.hex('8b405085c0');f.branch('0f84','finish');
  if(processLifetime) {f.hex('833d').u32(state+28).hex('00');f.branch('0f84','finish');}
  else {f.hex('3b05').u32(state+28);f.branch('0f85','finish');}
  f.hex('85d2');f.branch('0f84','finish');
  f.hex('83ba6001000000');f.branch('0f85','finish');
  f.hex('80ba6801000000');f.branch('0f84','finish');
  f.hex('80ba6901000000');f.branch('0f85','finish');
  f.hex('893d').u32(state).hex('8915').u32(state+4);
  f.hex('8b8254010000a3').u32(state+24);
  f.hex('8b87900100008b4050a3').u32(state+20);
  f.hex('c705').u32(state+8).u32(0).hex('c705').u32(state+12).u32(1);
  f.hex('c705').u32(state+16).u32(3600);
  f.hex('c687b60d000000c787b80d000000000000');
  f.branch('e9','finish');
  f.label('cancel');f.hex('c687b60d000000');
  f.label('clear');f.hex('c705').u32(state+12).u32(0).hex('c705').u32(state+8).u32(0);
  f.label('finish');f.hex('5a595880bfb60d000000');f.branch('e9',game+0xe44551);

  const p=new Block(caves.panel);
  // Preserve the native dead-unit comparison, or expose the same map while choosing.
  p.hex('833d').u32(state+12).hex('00');p.branch('0f84','original');
  p.hex('3935').u32(state+4);p.branch('0f85','original');
  p.hex('391d').u32(state);p.branch('0f85','original');
  p.hex('80be6801000000');p.branch('e9',game+0xdbf7ed);
  p.label('original');p.hex('83be6001000000');p.branch('e9',game+0xdbf7ed);

  const c=new Block(caves.click);
  c.hex('8988b80d00009c'); // original store; preserve caller flags
  c.hex('833d').u32(state+12).hex('00');c.branch('0f84','done');
  c.hex('3905').u32(state);c.branch('0f85','done');
  c.hex('890d').u32(state+8);
  c.label('done');c.hex('9d');c.branch('e9',game+0xe3bbca);

  const e=new Block(caves.engine);
  if(processLifetime) {e.hex('833d').u32(state+28).hex('00');e.branch('0f84','base');}
  else {e.hex('8b47048b40503b05').u32(state+28);e.branch('0f85','base');}
  e.hex('8b932c04000085d2');e.branch('0f84','base');
  // Accept only a point in the live manager's bounded catalog. Keep team check below.
  e.hex('518b4f1883f910');e.branch('0f87','invalid');
  e.hex('85c9');e.branch('0f84','invalid');e.hex('8b471c');
  e.label('scan');e.hex('39c2');e.branch('0f84','valid');
  e.hex('83c04849');e.branch('0f85','scan');
  e.label('invalid');e.hex('59');e.branch('e9','base');
  e.label('valid');e.hex('59');e.branch('e9',game+0x87ad93);
  e.label('base');e.hex('8b47108b1488');e.branch('e9',game+0x87ad93);
  return {frame:f.done(),panel:p.done(),click:c.done(),engine:e.done()};
}
'''



import hashlib
import json
from pathlib import Path
from tools.player_native_payload import GAME_HASH as GAME_SHA256


INSTALL_JS = r'''
(() => {
 if(Process.arch!=='ia32')throw Error('retreat_arch');
 const game=Process.getModuleByName('game.dll');
 const normal=s=>s.replaceAll('/',String.fromCharCode(92)).toLowerCase();
 if(normal(game.path)!==normal(__GAME_PATH__))throw Error('retreat_path');
 const sites={frame:[0xe4454a,'80bfb60d000000'],panel:[0xdbf7e6,'83be6001000000'],
              click:[0xe3bbc4,'8988b80d0000'],engine:[0x87ad8d,'8b47108b1488']};
 const read=(p,n)=>Array.from(new Uint8Array(p.readByteArray(n)));
 const hex=a=>a.map(x=>x.toString(16).padStart(2,'0')).join('');
 for(const [rva,bytes]of Object.values(sites))if(hex(read(game.base.add(rva),bytes.length/2))!==bytes)throw Error('retreat_anchor');
 if(hex(read(game.base.add(0x87ad93),20))!=='89550885d20f84020100003b4a040f85f9000000')throw Error('retreat_team_anchor');
 const allocate=new NativeFunction(Process.getModuleByName('kernel32.dll').getExportByName('VirtualAlloc'),
   'pointer',['pointer','uint32','uint32','uint32'],'stdcall');
 const block=allocate(ptr(0),0x5000,0x3000,4);if(block.isNull())throw Error('retreat_allocate');
 const state=block,caves={frame:block.add(0x1000),panel:block.add(0x2000),click:block.add(0x3000),engine:block.add(0x4000)};
 const code=buildRetreatCode(game.base.toUInt32(),state.toUInt32(),Object.fromEntries(Object.entries(caves).map(([k,v])=>[k,v.toUInt32()])),true);
 for(const [name,bytes]of Object.entries(code)){
   if(bytes.length>4096)throw Error('retreat_code_bounds');
   caves[name].writeByteArray(bytes);
   if(!Memory.protect(caves[name],4096,'r-x'))throw Error('retreat_code_protect');
 }
 const changed=[];
 try {
   for(const [name,[rva,bytes]]of Object.entries(sites)){
     const at=game.base.add(rva),relative=caves[name].sub(at.add(5)).toUInt32();
     const patch=[0xe9,relative&255,(relative>>>8)&255,(relative>>>16)&255,(relative>>>24)&255];
     while(patch.length<bytes.length/2)patch.push(0x90);
     changed.push([at,bytes]);Memory.patchCode(at,patch.length,w=>w.writeByteArray(patch));
     if(hex(read(at,patch.length))!==hex(patch))throw Error('retreat_patch_verify');
   }
   state.add(28).writeU32(1);
 } catch(error) {
   state.add(28).writeU32(0);
   for(const [at,bytes]of changed.reverse())Memory.patchCode(at,bytes.length/2,w=>w.writeByteArray(bytes.match(/../g).map(x=>parseInt(x,16))));
   throw error;
 }
 send({kind:'retreat_destination_ready',native_callbacks:0,process_lifetime:true});
})();
'''


def build_source(root: Path) -> str:
    path=root/'client/game.dll'
    if not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=GAME_SHA256:
        raise RuntimeError('retreat_game_mismatch')
    return BUILD_JS+'\n'+INSTALL_JS.replace('__GAME_PATH__',json.dumps(str(path.resolve())))
