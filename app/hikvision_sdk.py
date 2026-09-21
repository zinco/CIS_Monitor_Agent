"""Read analog channel signal through the optional Hikvision HCNetSDK."""
import ctypes as C
import os
import time
from pathlib import Path


class IPAddress(C.Structure):
    _fields_ = [("ipv4", C.c_char * 16), ("ipv6", C.c_ubyte * 128)]


class DiskState(C.Structure):
    _fields_ = [("volume", C.c_uint32), ("free", C.c_uint32), ("state", C.c_uint32)]


class ChannelState(C.Structure):
    _fields_ = [
        ("record", C.c_ubyte), ("signal", C.c_ubyte),
        ("hardware", C.c_ubyte), ("reserved", C.c_ubyte),
        ("bitrate", C.c_uint32), ("links", C.c_uint32),
        ("clients", IPAddress * 6), ("ip_links", C.c_uint32),
        ("exceeded", C.c_ubyte), ("reserved2", C.c_ubyte * 3),
        ("all_bitrate", C.c_uint32), ("channel", C.c_uint32),
    ]


class WorkState(C.Structure):
    _fields_ = [
        ("device", C.c_uint32), ("disks", DiskState * 33),
        ("channels", ChannelState * 64),
        ("alarm_in", C.c_ubyte * 160),
        ("alarm_out", C.c_ubyte * 96),
        ("display", C.c_uint32), ("audio", C.c_ubyte * 2),
        ("reserved", C.c_ubyte * 10),
    ]


class WorkStateV40(C.Structure):
    _fields_ = [
        ("size", C.c_uint32), ("device", C.c_uint32),
        ("disks", DiskState * 33), ("channels", ChannelState * 512),
        ("alarm_in", C.c_uint32 * 4128),
        ("alarm_out", C.c_uint32 * 4128),
        ("display", C.c_uint32), ("audio", C.c_ubyte * 2),
        ("reserved1", C.c_ubyte * 2), ("humidity", C.c_float),
        ("temperature", C.c_float), ("reserved", C.c_ubyte * 116),
    ]


class WorkStateCondition(C.Structure):
    _fields_ = [
        ("size", C.c_uint32), ("find_disks", C.c_ubyte),
        ("find_channels", C.c_ubyte), ("reserved1", C.c_ubyte * 2),
        ("disk_numbers", C.c_uint32 * 33),
        ("channel_numbers", C.c_uint32 * 512),
        ("reserved", C.c_ubyte * 64),
    ]


class LegacyChannelState(C.Structure):
    _fields_ = [
        ("record", C.c_ubyte), ("signal", C.c_ubyte),
        ("hardware", C.c_ubyte), ("reserved", C.c_ubyte),
        ("bitrate", C.c_uint32), ("links", C.c_uint32),
        ("client_ips", C.c_uint32 * 6),
    ]


class LegacyWorkState(C.Structure):
    _fields_ = [
        ("device", C.c_uint32), ("disks", DiskState * 16),
        ("channels", LegacyChannelState * 16),
        ("alarm_in", C.c_ubyte * 16),
        ("alarm_out", C.c_ubyte * 4), ("display", C.c_uint32),
    ]


def _read_legacy(sdk, user_id, analog_start, analog_count):
    """Read the original 16-channel DVR work-state structure."""
    try:
        query = sdk.NET_DVR_GetDVRWorkState
    except AttributeError:
        return []
    query.argtypes = [C.c_int32, C.POINTER(LegacyWorkState)]
    query.restype = C.c_int
    state = LegacyWorkState()
    if not query(user_id, C.byref(state)):
        return []
    count = min(analog_count, 16)
    relevant = state.channels[:count]
    # An all-zero response could be an unpopulated structure. Do not
    # interpret it as sixteen channels with healthy video.
    if not any(item.record or item.bitrate or item.links for item in relevant):
        return []
    # On firmware that leaves the legacy signal bytes zeroed, a recording
    # flag alone must not turn every channel into "video present".
    if not any(item.signal == 1 for item in relevant) and not all(
        item.bitrate > 0 for item in relevant
    ):
        return []
    return [
        {"channel": analog_start + index, "signal_present": item.signal == 0}
        for index, item in enumerate(relevant)
        if item.signal in (0, 1)
    ]


def _analog_signals(state, analog_range):
    channels = []
    reported = []
    for item in state.channels:
        if item.channel == 0xffffffff:
            break
        if 1 <= item.channel <= 512 and item.signal in (0, 1):
            reported.append(item.channel)
        if item.channel in analog_range and item.signal in (0, 1):
            channels.append({"channel": item.channel,
                             "signal_present": item.signal == 0})
    return channels, reported


def _read_v40(sdk, user_id):
    """Optional read-only work-state API; older firmware may reject it."""
    try:
        query = sdk.NET_DVR_GetDeviceConfig
    except AttributeError:
        return None
    query.argtypes = [
        C.c_int32, C.c_uint32, C.c_uint32, C.c_void_p,
        C.c_uint32, C.c_void_p, C.c_void_p, C.c_uint32,
    ]
    query.restype = C.c_int
    condition = WorkStateCondition()
    condition.size = C.sizeof(condition)
    state = WorkStateV40()
    state.size = C.sizeof(state)
    status = C.c_uint32()
    success = query(
        user_id, 6189, 0, C.byref(condition), C.sizeof(condition),
        C.byref(status), C.byref(state), C.sizeof(state),
    )
    return state if success and status.value in (0, 1) else None


def read_channel_signals(ip_address, username, password, port=8000):
    """Only SDK init, login, work-state read, logout and cleanup are used."""
    started = time.perf_counter()
    path = os.getenv("HIKVISION_SDK_PATH", "")
    result = {"supported": False, "resolved": False, "identified": False,
              "source": "HCNetSDK",
              "channels": [], "message": "SDK Hikvision não configurado"}
    if not path or not Path(path).is_file():
        return result
    try:
        sdk = C.WinDLL(path) if os.name == "nt" else C.CDLL(path)
        sdk.NET_DVR_Init.restype = C.c_int
        sdk.NET_DVR_Login_V30.argtypes = [C.c_char_p, C.c_ushort, C.c_char_p,
                                          C.c_char_p, C.c_void_p]
        sdk.NET_DVR_Login_V30.restype = C.c_int32
        sdk.NET_DVR_GetDVRWorkState_V30.argtypes = [C.c_int32, C.POINTER(WorkState)]
        sdk.NET_DVR_GetDVRWorkState_V30.restype = C.c_int
        sdk.NET_DVR_Logout.argtypes = [C.c_int32]
        sdk.NET_DVR_GetLastError.restype = C.c_uint32
        if not sdk.NET_DVR_Init():
            raise RuntimeError("Falha ao inicializar SDK")
        try:
            # V30 starts with a 48-byte serial, four status bytes, then
            # byChanNum and byStartChan (HCNetSDK.h). Keep ample output space.
            device_info = C.create_string_buffer(1024)
            user_id = sdk.NET_DVR_Login_V30(ip_address.encode("ascii"), port,
                                             username.encode(), password.encode(),
                                             device_info)
            if user_id < 0:
                raise RuntimeError(f"Falha no login SDK (código {sdk.NET_DVR_GetLastError()})")
            try:
                state = WorkState()
                if not sdk.NET_DVR_GetDVRWorkState_V30(user_id, C.byref(state)):
                    raise RuntimeError(f"Falha na leitura SDK (código {sdk.NET_DVR_GetLastError()})")
                analog_count = device_info.raw[52]
                analog_start = device_info.raw[53]
                analog_range = (
                    range(analog_start, analog_start + analog_count)
                    if 1 <= analog_start <= 64 and 1 <= analog_count <= 64
                    else range(0)
                )
                channels, reported_channels = _analog_signals(state, analog_range)
                work_state_api = "V30"
                if not channels:
                    newer_state = _read_v40(sdk, user_id)
                    if newer_state is not None:
                        channels, reported_channels = _analog_signals(
                            newer_state, analog_range
                        )
                        work_state_api = "V40"
                if not channels and analog_count and analog_start:
                    channels = _read_legacy(
                        sdk, user_id, analog_start, analog_count
                    )
                    if channels:
                        work_state_api = "legacy"
                result.update(supported=True, identified=True,
                              resolved=bool(channels), channels=channels,
                              work_state_api=work_state_api,
                              analog_channel_count=analog_count,
                              analog_start_channel=analog_start,
                              reported_channel_numbers=reported_channels,
                              message="Estado de sinal consultado" if channels else
                                      "Estado SDK lido, mas canais analógicos não identificados")
            finally:
                sdk.NET_DVR_Logout(user_id)
        finally:
            sdk.NET_DVR_Cleanup()
    except (OSError, RuntimeError, UnicodeError, AttributeError) as error:
        result.update(supported=True, message=str(error))
    result["duration_ms"] = int((time.perf_counter() - started) * 1000)
    return result
