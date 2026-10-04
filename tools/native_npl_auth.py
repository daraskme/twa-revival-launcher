"""Verify owned NPL stubs and support the exact legacy in-memory forwarding.

New reviewed stubs read the owned launch command line themselves. The legacy
hook remains restricted to the two original hashes and getter anchors. Neither
branch publishes a bearer in diagnostics; the server validates it separately.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from companion.launch_preparation import _NPL_STUB_SHA256


_LEGACY_NPL_STUB_SHA256 = {
    'npl-base.dll': '57e21f4bb30309799ff00ce386b82ec2f5fbf6507f381803f5ae56877c5335f8',
    'npl-sdk.dll': 'e27de46954077a979f4b56568fa13a2f49cd5061026c5868f6262fb68aba3e45',
}


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


DIRECT_SOURCE = r"""
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
  const normalize = value => value.replaceAll('/', '\\').toLowerCase();
  for (const name of ['npl-base.dll', 'npl-sdk.dll']) {
    const module = Process.getModuleByName(name);
    if (normalize(module.path) !== normalize(paths[name]))
      throw new Error('npl_auth_module_path_mismatch');
  }
  // The exact built DLL hashes were checked on the host. No return value or
  // game memory is changed in this branch, including before helper readiness.
  send({kind:'npl_auth_ready', mode:'owned_stub_direct'});
})();
"""


def build_source(root: Path) -> str:
    paths = {}
    actual = {}
    for name in _LEGACY_NPL_STUB_SHA256:
        path = root / 'client' / name
        if path.is_symlink() or not path.is_file():
            raise RuntimeError('npl_auth_stub_missing')
        actual[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        paths[name] = str(path.resolve())
    if actual == _LEGACY_NPL_STUB_SHA256:
        source = SOURCE
    elif (_NPL_STUB_SHA256 != _LEGACY_NPL_STUB_SHA256
          and actual == _NPL_STUB_SHA256):
        source = DIRECT_SOURCE
    else:
        raise RuntimeError('npl_auth_stub_hash_mismatch')
    return source.replace('__NPL_PATHS__', json.dumps(paths))
