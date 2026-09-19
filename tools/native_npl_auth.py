"""Forward the owned launch's bearer to the two reviewed NPL interop stubs.

Only the copied, hash-pinned stub getters are instrumented, in memory. The
server remains responsible for token validation. No token enters this source
or the diagnostic messages; it is read inside the already-owned game process.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from companion.launch_preparation import _NPL_STUB_SHA256


SOURCE = r"""
(() => {
  if (Process.arch !== 'ia32') throw new Error('npl_auth_arch_mismatch');
  const paths = __NPL_PATHS__;
  const commandLine = new NativeFunction(
    Process.getModuleByName('kernel32.dll').getExportByName('GetCommandLineW'),
    'pointer', [], 'stdcall')().readUtf16String();
  const matches = Array.from(commandLine.matchAll(/(?:^|\s)\+auth\s+([a-f0-9]{64})(?=\s|$)/g));
  const authOptions = Array.from(commandLine.matchAll(/(?:^|\s)\+auth(?:\s|$)/g));
  if (matches.length !== 1 || authOptions.length !== 1)
    throw new Error('npl_auth_launch_token_missing');
  const token = Memory.allocUtf8String(matches[0][1]);
  const bindings = [
    {name:'npl-base.dll', entry:0x1090, mov:0x1090, value:0x11230},
    {name:'npl-sdk.dll', entry:0x1040, mov:0x104d, value:0x112e4},
  ];
  const normalize = value => value.replaceAll('/', '\\').toLowerCase();
  // Validate both modules before changing either one.
  for (const binding of bindings) {
    const module = Process.getModuleByName(binding.name);
    if (normalize(module.path) !== normalize(paths[binding.name]))
      throw new Error('npl_auth_module_path_mismatch');
    const mov = module.base.add(binding.mov);
    if (mov.readU8() !== 0xb8 || mov.add(5).readU8() !== 0xc3 ||
        !mov.add(1).readPointer().equals(module.base.add(binding.value)) ||
        module.base.add(binding.value).readUtf8String() !== 'revival-token')
      throw new Error('npl_auth_getter_anchor_mismatch');
    if (binding.name === 'npl-sdk.dll' &&
        (module.base.add(binding.entry).readU8() !== 0x68 ||
         !module.base.add(binding.entry + 1).readPointer().equals(module.base.add(0x112d4)) ||
         module.base.add(0x1045).readU8() !== 0xe8 ||
         module.base.add(0x1046).readS32() !== 0x166 ||
         module.base.add(0x104a).readU8() !== 0x83 ||
         module.base.add(0x104b).readU16() !== 0x04c4))
      throw new Error('npl_auth_getter_anchor_mismatch');
    binding.module = module;
  }
  for (const binding of bindings) {
    let reported = false;
    Interceptor.attach(binding.module.base.add(binding.entry), {
      onLeave(retval) {
        retval.replace(token);
        if (!reported) {
          reported = true;
          send({kind:'npl_auth_forwarded', module:binding.name});
        }
      }
    });
  }
  send({kind:'npl_auth_ready'});
})();
"""


def build_source(root: Path) -> str:
    paths = {}
    for name, expected in _NPL_STUB_SHA256.items():
        path = root / 'client' / name
        if path.is_symlink() or not path.is_file():
            raise RuntimeError('npl_auth_stub_missing')
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeError('npl_auth_stub_hash_mismatch')
        paths[name] = str(path.resolve())
    return SOURCE.replace('__NPL_PATHS__', json.dumps(paths))
