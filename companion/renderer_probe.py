"""Bounded, read-only D3D11 default-adapter versus WARP probe.

The helper runs in 32-bit Windows PowerShell so its D3D11 result is not
constrained by the launcher's Python bitness. It creates no Arena process and
does not change preferences, files, or network state.
"""
from __future__ import annotations

import base64
import json
import os
import platform
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping


_TIMEOUT_SECONDS = 20
_MAX_COMMAND_LINE = 32767
_MAX_STDOUT_BYTES = 8192
_HR_RE = re.compile(r"0x[0-9A-Fa-f]{8}\Z")
_FEATURE_LEVEL_RE = re.compile(r"0x[0-9A-Fa-f]{1,8}\Z")
_DESCRIPTION_RE = re.compile(r"[^\x00-\x1f\x7f]{0,128}\Z")
_SYSTEM_ENV_KEYS = ("SystemRoot", "WINDIR", "PATH", "TEMP", "TMP")


@dataclass(frozen=True)
class RendererProbeResult:
    """Strict three-state result with only allow-listed evidence fields."""

    decision: str
    reason: str
    evidence: dict[str, Any]


_POWERSHELL_SCRIPT = r'''$ErrorActionPreference = 'Stop'
if ([IntPtr]::Size -ne 4) { throw 'PROCESS_BITS_NOT_X86' }
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) {
    throw 'WINDOWS_POWERSHELL_5_1_REQUIRED'
}
$code = @'
using System;
using System.Runtime.InteropServices;

public static class TwaRendererProbe {
    public const uint D3D_DRIVER_TYPE_HARDWARE = 1;
    public const uint D3D_DRIVER_TYPE_WARP = 5;
    public const uint D3D11_SDK_VERSION = 7;
    public const uint DXGI_ADAPTER_FLAG_SOFTWARE = 2;

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct AdapterDesc1 {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=128)] public string Description;
        public uint VendorId, DeviceId, SubSysId, Revision;
        public uint DedicatedVideoMemory, DedicatedSystemMemory, SharedSystemMemory;
        public int LuidLowPart, LuidHighPart;
        public uint Flags;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int QueryInterfaceDelegate(IntPtr self, ref Guid iid, out IntPtr obj);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int GetAdapterDelegate(IntPtr self, out IntPtr adapter);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int GetDesc1Delegate(IntPtr self, out AdapterDesc1 desc);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate uint ReleaseDelegate(IntPtr self);

    [DllImport("d3d11.dll", CallingConvention=CallingConvention.StdCall)]
    static extern int D3D11CreateDevice(IntPtr adapter, uint driverType,
        IntPtr software, uint flags, IntPtr featureLevels, uint featureLevelCount,
        uint sdkVersion, out IntPtr device, out uint featureLevel, out IntPtr context);

    static readonly Guid IID_IDXGIDevice = new Guid("54EC77FA-1377-44E6-8C32-88FD5F44C84C");
    static readonly Guid IID_IDXGIAdapter1 = new Guid("29038F61-3839-4626-91FD-086879011A05");

    static IntPtr Method(IntPtr obj, int slot) {
        return Marshal.ReadIntPtr(Marshal.ReadIntPtr(obj), slot * IntPtr.Size);
    }
    static void Release(ref IntPtr obj) {
        if (obj != IntPtr.Zero) {
            Marshal.GetDelegateForFunctionPointer<ReleaseDelegate>(Method(obj, 2))(obj);
            obj = IntPtr.Zero;
        }
    }
    static string HResult(int hr) { return "0x" + unchecked((uint)hr).ToString("X8"); }

    static object Probe(uint driverType, string request) {
        IntPtr device=IntPtr.Zero, context=IntPtr.Zero, dxgiDevice=IntPtr.Zero;
        IntPtr adapter=IntPtr.Zero, adapter1=IntPtr.Zero;
        uint featureLevel=0;
        try {
            int deviceHr = D3D11CreateDevice(IntPtr.Zero, driverType, IntPtr.Zero,
                0, IntPtr.Zero, 0, D3D11_SDK_VERSION,
                out device, out featureLevel, out context);
            if (deviceHr < 0 || device == IntPtr.Zero) {
                return new { request=request, deviceHr=HResult(deviceHr),
                    deviceCreated=false, featureLevel="0x"+featureLevel.ToString("X"),
                    adapterDescription=(string)null, adapterFlags=(uint?)null,
                    softwareFlag=(bool?)null, classification="device_creation_failed" };
            }

            Guid iidDevice = IID_IDXGIDevice;
            int qi = Marshal.GetDelegateForFunctionPointer<QueryInterfaceDelegate>(
                Method(device, 0))(device, ref iidDevice, out dxgiDevice);
            if (qi < 0 || dxgiDevice == IntPtr.Zero) {
                return new { request=request, deviceHr=HResult(deviceHr),
                    deviceCreated=true, featureLevel="0x"+featureLevel.ToString("X"),
                    adapterDescription=(string)null, adapterFlags=(uint?)null,
                    softwareFlag=(bool?)null, classification="dxgi_device_query_failed" };
            }
            int getAdapterHr = Marshal.GetDelegateForFunctionPointer<GetAdapterDelegate>(
                Method(dxgiDevice, 7))(dxgiDevice, out adapter);
            if (getAdapterHr < 0 || adapter == IntPtr.Zero) {
                return new { request=request, deviceHr=HResult(deviceHr),
                    deviceCreated=true, featureLevel="0x"+featureLevel.ToString("X"),
                    adapterHr=HResult(getAdapterHr), adapterDescription=(string)null,
                    adapterFlags=(uint?)null, softwareFlag=(bool?)null,
                    classification="selected_adapter_unavailable" };
            }
            Guid iidAdapter1 = IID_IDXGIAdapter1;
            int adapterQi = Marshal.GetDelegateForFunctionPointer<QueryInterfaceDelegate>(
                Method(adapter, 0))(adapter, ref iidAdapter1, out adapter1);
            if (adapterQi < 0 || adapter1 == IntPtr.Zero) {
                return new { request=request, deviceHr=HResult(deviceHr),
                    deviceCreated=true, featureLevel="0x"+featureLevel.ToString("X"),
                    adapterHr=HResult(getAdapterHr), descHr=HResult(adapterQi),
                    adapterDescription=(string)null, adapterFlags=(uint?)null,
                    softwareFlag=(bool?)null, classification="adapter1_query_failed" };
            }
            AdapterDesc1 desc;
            int descHr = Marshal.GetDelegateForFunctionPointer<GetDesc1Delegate>(
                Method(adapter1, 10))(adapter1, out desc);
            if (descHr < 0) {
                return new { request=request, deviceHr=HResult(deviceHr),
                    deviceCreated=true, featureLevel="0x"+featureLevel.ToString("X"),
                    adapterHr=HResult(getAdapterHr), descHr=HResult(descHr),
                    adapterDescription=(string)null, adapterFlags=(uint?)null,
                    softwareFlag=(bool?)null, classification="adapter_description_failed" };
            }
            bool software = (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) != 0;
            string classification = request == "warp_explicit"
                ? "explicit_warp_device"
                : (software ? "hardware_request_selected_software_adapter"
                            : "hardware_request_selected_nonsoftware_dxgi_adapter");
            return new { request=request, deviceHr=HResult(deviceHr), deviceCreated=true,
                featureLevel="0x"+featureLevel.ToString("X"), adapterHr=HResult(getAdapterHr),
                descHr=HResult(descHr), adapterDescription=(desc.Description ?? "").TrimEnd('\0'),
                vendorId=desc.VendorId, deviceId=desc.DeviceId, adapterFlags=desc.Flags,
                softwareFlag=software, classification=classification };
        } finally {
            Release(ref adapter1); Release(ref adapter); Release(ref dxgiDevice);
            Release(ref context); Release(ref device);
        }
    }

    public static object Run() {
        int descSize = Marshal.SizeOf(typeof(AdapterDesc1));
        int flagsOffset = Marshal.OffsetOf(typeof(AdapterDesc1), "Flags").ToInt32();
        if (descSize != 296 || flagsOffset != 292)
            throw new InvalidOperationException("DXGI_DESC1_LAYOUT_MISMATCH");
        return new { schema=1, probe="d3d11_default_hardware_vs_explicit_warp",
            processBits=IntPtr.Size*8, descSize=descSize, flagsOffset=flagsOffset,
            hardwareDefault=Probe(D3D_DRIVER_TYPE_HARDWARE, "hardware_default"),
            explicitWarp=Probe(D3D_DRIVER_TYPE_WARP, "warp_explicit") };
    }
}
'@
Add-Type -TypeDefinition $code -Language CSharp
$result = [TwaRendererProbe]::Run()
$json = $result | ConvertTo-Json -Depth 5 -Compress
[Console]::Out.WriteLine($json)
'''


def _unknown(reason: str) -> RendererProbeResult:
    return RendererProbeResult("unknown", reason, {})


def _powershell_executable(system_root: str | None) -> Path | None:
    if not system_root:
        return None
    path = (Path(system_root) / "SysWOW64" / "WindowsPowerShell" / "v1.0"
            / "powershell.exe")
    return path if path.is_file() else None


def _environment(source: Mapping[str, str]) -> dict[str, str]:
    result = {key: source[key] for key in _SYSTEM_ENV_KEYS if source.get(key)}
    root = source.get("SystemRoot") or source.get("WINDIR")
    if root:
        result.setdefault("SystemRoot", root)
        result.setdefault("WINDIR", root)
    return result


def _safe_adapter(row: Any) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    request = row.get("request")
    created = row.get("deviceCreated")
    device_hr = row.get("deviceHr")
    if request not in ("hardware_default", "warp_explicit") or not isinstance(created, bool):
        return None
    if not isinstance(device_hr, str) or not _HR_RE.fullmatch(device_hr):
        return None
    hr_failed = bool(int(device_hr[2:], 16) & 0x80000000)
    if created and hr_failed:
        return None
    safe: dict[str, Any] = {"request": request, "deviceCreated": created,
                            "deviceHr": device_hr, "deviceHrFailed": hr_failed}
    feature_level = row.get("featureLevel")
    if isinstance(feature_level, str) and _FEATURE_LEVEL_RE.fullmatch(feature_level):
        safe["featureLevel"] = feature_level.lower()
    adapter_hr = row.get("adapterHr")
    if isinstance(adapter_hr, str) and _HR_RE.fullmatch(adapter_hr):
        safe["adapterHr"] = adapter_hr
    desc_hr = row.get("descHr")
    if isinstance(desc_hr, str) and _HR_RE.fullmatch(desc_hr):
        safe["descHr"] = desc_hr
    description = row.get("adapterDescription")
    if isinstance(description, str) and _DESCRIPTION_RE.fullmatch(description):
        safe["adapterDescription"] = description.strip()
    flags = row.get("adapterFlags")
    if isinstance(flags, int) and not isinstance(flags, bool) and 0 <= flags <= 0xFFFFFFFF:
        safe["adapterFlags"] = flags
    software = row.get("softwareFlag")
    if isinstance(software, bool):
        safe["softwareFlag"] = software
    for key in ("vendorId", "deviceId"):
        value = row.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFFFFFFFF:
            safe[key] = value
    return safe


def _classify(payload: Any) -> RendererProbeResult:
    if not isinstance(payload, dict) or type(payload.get("schema")) is not int or payload["schema"] != 1:
        return _unknown("invalid_probe_result")
    if (type(payload.get("processBits")) is not int or payload["processBits"] != 32
            or type(payload.get("descSize")) is not int or payload["descSize"] != 296
            or type(payload.get("flagsOffset")) is not int or payload["flagsOffset"] != 292):
        return _unknown("probe_layout_or_bitness_mismatch")
    hardware = _safe_adapter(payload.get("hardwareDefault"))
    warp = _safe_adapter(payload.get("explicitWarp"))
    if hardware is None or warp is None:
        return _unknown("invalid_adapter_result")
    if hardware["request"] != "hardware_default" or warp["request"] != "warp_explicit":
        return _unknown("adapter_request_mismatch")
    evidence = {"hardwareDefault": hardware, "explicitWarp": warp}
    if hardware["deviceCreated"]:
        if "softwareFlag" not in hardware or "adapterFlags" not in hardware:
            return _unknown("hardware_adapter_flag_unavailable")
        if hardware["softwareFlag"]:
            return RendererProbeResult("software", "hardware_request_selected_software_adapter", evidence)
        # QA's real WARP adapter exposed the same Microsoft Basic Render
        # Driver identity in both D3D11CreateDevice calls, but flags differed:
        # the default request returned flags=0 while the explicit WARP request
        # returned DXGI_ADAPTER_FLAG_SOFTWARE. Require the known vendor/device,
        # exact description, same identity, and the explicit WARP software bit.
        basic_render_identity = (
            hardware.get("vendorId") == 0x1414
            and hardware.get("deviceId") == 0x008C
            and hardware.get("adapterDescription") == "Microsoft Basic Render Driver"
        )
        warp_confirms_same_identity = (
            warp["deviceCreated"] and not warp["deviceHrFailed"]
            and warp.get("softwareFlag") is True
            and isinstance(warp.get("adapterFlags"), int)
            and bool(warp["adapterFlags"] & 2)
            and warp.get("vendorId") == hardware.get("vendorId")
            and warp.get("deviceId") == hardware.get("deviceId")
            and warp.get("adapterDescription") == hardware.get("adapterDescription")
        )
        if basic_render_identity and warp_confirms_same_identity:
            return RendererProbeResult(
                "software", "default_adapter_matches_verified_warp_identity", evidence)
        return RendererProbeResult("hardware", "hardware_request_selected_nonsoftware_dxgi_adapter", evidence)
    if not hardware["deviceHrFailed"]:
        return _unknown("hardware_creation_result_inconsistent")
    if warp["deviceCreated"] and not warp["deviceHrFailed"]:
        return RendererProbeResult("software", "hardware_creation_failed_warp_succeeded", evidence)
    return _unknown("both_device_creation_paths_failed")


def probe_renderer(
    *,
    runner: Callable[..., Any] = subprocess.run,
    system_root: str | None = None,
    environ: Mapping[str, str] | None = None,
    platform_name: str | None = None,
) -> RendererProbeResult:
    """Probe the default D3D11 adapter and explicit WARP without persistent writes.

    `hardware` means only that D3D11's default hardware request selected a
    non-software DXGI adapter; it does not assert physical hardware. Any
    unsupported platform, timeout, malformed result, or ambiguous adapter
    status produces `unknown`.
    """
    platform_name = platform_name or platform.system()
    if platform_name != "Windows":
        return _unknown("unsupported_platform")
    source_env = os.environ if environ is None else environ
    root = system_root or source_env.get("SystemRoot") or source_env.get("WINDIR")
    powershell = _powershell_executable(root)
    if powershell is None:
        return _unknown("x86_powershell_unavailable")
    encoded = base64.b64encode(_POWERSHELL_SCRIPT.encode("utf-16le")).decode("ascii")
    command = [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive",
               "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded]
    if sum(len(item) + 1 for item in command) > _MAX_COMMAND_LINE:
        return _unknown("probe_command_too_long")
    try:
        completed = runner(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_TIMEOUT_SECONDS,
            check=False,
            env=_environment(source_env),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        return _unknown("probe_timeout")
    except OSError:
        return _unknown("probe_process_unavailable")
    stdout = completed.stdout
    if isinstance(stdout, str):
        output_bytes = stdout.encode("utf-8", errors="replace")
        output_text = stdout
    elif isinstance(stdout, bytes):
        output_bytes = stdout
        try:
            output_text = stdout.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return _unknown("probe_output_invalid_encoding")
    else:
        return _unknown("probe_output_missing")
    if len(output_bytes) > _MAX_STDOUT_BYTES:
        return _unknown("probe_output_too_large")
    if completed.returncode != 0:
        return _unknown("probe_process_failed")
    lines = [line for line in output_text.splitlines() if line.strip()]
    if len(lines) != 1:
        return _unknown("probe_output_not_single_json")
    try:
        payload = json.loads(lines[0])
    except (TypeError, ValueError):
        return _unknown("probe_output_invalid_json")
    return _classify(payload)
