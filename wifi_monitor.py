"""
WiFi Monitor — Lightweight Windows System Tray Network Monitor.

Two-tier background scanning using native Win32 APIs (zero subprocesses):
- Fast check every 5s: live SendARP on known devices + OS ARP table (~0% CPU)
- Full /24 discovery every 30s: native IcmpSendEcho + SendARP verification
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import socket
import struct
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from PIL import Image, ImageDraw

APP_NAME = "WiFi Monitor"
FAST_CHECK_INTERVAL_SECONDS = 5    # Quick liveness check for known devices
FULL_SCAN_INTERVAL_SECONDS = 30    # Full /24 sweep to discover newly joined devices
LEAVE_GRACE_SCANS = 2              # 2 consecutive misses (~10-15s) before reporting "Left"
PING_TIMEOUT_MS = 250
PING_WORKERS = 64                  # I/O-bound kernel waits; completes /24 in ~1.5s with ~0% CPU
DNS_WORKERS = 8
MIB_IPNET_TYPE_DYNAMIC = 3
MUTEX_NAME = "Global\\WiFiMonitorTrayApp_SingleInstance_Mutex"

# ---------------------------------------------------------------------------
# Win32 network API bindings (iphlpapi.dll — zero subprocesses)
# ---------------------------------------------------------------------------
_iphlpapi = ctypes.windll.iphlpapi
_iphlpapi.IcmpCreateFile.restype = ctypes.c_void_p
_iphlpapi.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
_iphlpapi.IcmpCloseHandle.restype = ctypes.c_bool
_iphlpapi.IcmpSendEcho.argtypes = [
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.c_void_p,
    ctypes.c_uint16,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.c_uint32,
]
_iphlpapi.IcmpSendEcho.restype = ctypes.c_uint32
_iphlpapi.GetIpNetTable.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_ulong),
    ctypes.c_bool,
]
_iphlpapi.GetIpNetTable.restype = ctypes.c_uint32
_iphlpapi.SendARP.argtypes = [
    ctypes.c_uint32,
    ctypes.c_uint32,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_ulong),
]
_iphlpapi.SendARP.restype = ctypes.c_uint32


class _MIB_IPNETROW(ctypes.Structure):
    _fields_ = [
        ("dwIndex", ctypes.c_uint32),
        ("dwPhysAddrLen", ctypes.c_uint32),
        ("bPhysAddr", ctypes.c_ubyte * 8),
        ("dwAddr", ctypes.c_uint32),
        ("dwType", ctypes.c_uint32),
    ]


# ---------------------------------------------------------------------------
# Win32 UI bindings (user32, gdi32, shell32, dwmapi, uxtheme)
# ---------------------------------------------------------------------------
_user32 = ctypes.windll.user32
_gdi32 = ctypes.windll.gdi32
_kernel32 = ctypes.windll.kernel32
_shell32 = ctypes.windll.shell32

try:
    _uxtheme = ctypes.windll.uxtheme
except OSError:
    _uxtheme = None

try:
    _dwmapi = ctypes.windll.dwmapi
except OSError:
    _dwmapi = None

_WS_POPUP = 0x80000000
_WS_EX_TOPMOST = 0x00000008
_WS_EX_TOOLWINDOW = 0x00000080
_WS_EX_NOACTIVATE = 0x08000000

_SW_HIDE = 0
_SW_SHOWNOACTIVATE = 4
_SWP_NOACTIVATE = 0x0010
_SWP_SHOWWINDOW = 0x0040
_HWND_TOPMOST = -1

_WM_DESTROY = 0x0002
_WM_PAINT = 0x000F
_WM_SETCURSOR = 0x0020
_WM_DRAWITEM = 0x002B
_WM_MEASUREITEM = 0x002C
_WM_TIMER = 0x0113
_WM_LBUTTONUP = 0x0202
_WM_RBUTTONUP = 0x0205
_WM_TRAYICON = 0x8001
_WM_APP_UPDATE_TRAY = 0x8002
_WM_APP_QUIT_TRAY = 0x8003
_WM_APP_SHOW_TOAST = 0x8010
_WM_APP_QUIT_TOAST = 0x8011

_IDC_ARROW = 32512
_ODT_MENU = 1
_COLOR_WINDOW = 5
_COLOR_MENUTEXT = 7
_TRANSPARENT = 1
_DT_LEFT = 0x00000000
_DT_RIGHT = 0x00000002
_DT_VCENTER = 0x00000004
_DT_SINGLELINE = 0x00000020
_DT_NOPREFIX = 0x00000800
_DT_END_ELLIPSIS = 0x00008000
_SPI_GETNONCLIENTMETRICS = 0x0029
_SPI_GETWORKAREA = 0x0030
_MENU_POPUPBACKGROUND = 9
_DWMWA_WINDOW_CORNER_PREFERENCE = 33
_DWMWCP_ROUND = 2
_FW_NORMAL = 400
_FW_SEMIBOLD = 600
_DEFAULT_CHARSET = 1
_CLEARTYPE_QUALITY = 5
_DIB_RGB_COLORS = 0

_NIM_ADD = 0x00000000
_NIM_MODIFY = 0x00000001
_NIM_DELETE = 0x00000002
_NIF_MESSAGE = 0x00000001
_NIF_ICON = 0x00000002
_NIF_TIP = 0x00000004

_MIIM_STATE = 0x00000001
_MIIM_ID = 0x00000002
_MIIM_DATA = 0x00000020
_MIIM_STRING = 0x00000040
_MIIM_FTYPE = 0x00000100
_MFT_STRING = 0x00000000
_MFT_OWNERDRAW = 0x00000100
_MFT_SEPARATOR = 0x00000800
_MFS_DISABLED = 0x00000003
_MFS_CHECKED = 0x00000008

_TPM_RIGHTALIGN = 0x0008
_TPM_BOTTOMALIGN = 0x0020
_TPM_RETURNCMD = 0x0100

_MENU_ID_NOTIFICATIONS = 1001
_MENU_ID_QUIT = 1002
_TOAST_TIMER_ID = 1
_TOAST_DURATION_MS = 6000


def _rgb(r: int, g: int, b: int) -> int:
    return r | (g << 8) | (b << 16)


_WNDPROC = ctypes.WINFUNCTYPE(
    ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
)


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]


class _NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HICON),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("uVersion", wintypes.UINT),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
        ("guidItem", _GUID),
        ("hBalloonIcon", wintypes.HICON),
    ]


class _MENUITEMINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.UINT),
        ("fMask", wintypes.UINT),
        ("fType", wintypes.UINT),
        ("fState", wintypes.UINT),
        ("wID", wintypes.UINT),
        ("hSubMenu", wintypes.HMENU),
        ("hbmpChecked", wintypes.HBITMAP),
        ("hbmpUnchecked", wintypes.HBITMAP),
        ("dwItemData", ctypes.c_size_t),
        ("dwTypeData", wintypes.LPWSTR),
        ("cch", wintypes.UINT),
        ("hbmpItem", wintypes.HBITMAP),
    ]


class _WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.UINT),
        ("style", wintypes.UINT),
        ("lpfnWndProc", _WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
        ("hIconSm", wintypes.HICON),
    ]


class _PAINTSTRUCT(ctypes.Structure):
    _fields_ = [
        ("hdc", wintypes.HDC),
        ("fErase", wintypes.BOOL),
        ("rcPaint", wintypes.RECT),
        ("fRestore", wintypes.BOOL),
        ("fIncUpdate", wintypes.BOOL),
        ("rgbReserved", ctypes.c_byte * 32),
    ]


class _LOGFONTW(ctypes.Structure):
    _fields_ = [
        ("lfHeight", wintypes.LONG),
        ("lfWidth", wintypes.LONG),
        ("lfEscapement", wintypes.LONG),
        ("lfOrientation", wintypes.LONG),
        ("lfWeight", wintypes.LONG),
        ("lfItalic", wintypes.BYTE),
        ("lfUnderline", wintypes.BYTE),
        ("lfStrikeOut", wintypes.BYTE),
        ("lfCharSet", wintypes.BYTE),
        ("lfOutPrecision", wintypes.BYTE),
        ("lfClipPrecision", wintypes.BYTE),
        ("lfQuality", wintypes.BYTE),
        ("lfPitchAndFamily", wintypes.BYTE),
        ("lfFaceName", wintypes.WCHAR * 32),
    ]


class _NONCLIENTMETRICSW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.UINT),
        ("iBorderWidth", ctypes.c_int),
        ("iScrollWidth", ctypes.c_int),
        ("iScrollHeight", ctypes.c_int),
        ("iCaptionWidth", ctypes.c_int),
        ("iCaptionHeight", ctypes.c_int),
        ("lfCaptionFont", _LOGFONTW),
        ("iSmCaptionWidth", ctypes.c_int),
        ("iSmCaptionHeight", ctypes.c_int),
        ("lfSmCaptionFont", _LOGFONTW),
        ("iMenuWidth", ctypes.c_int),
        ("iMenuHeight", ctypes.c_int),
        ("lfMenuFont", _LOGFONTW),
        ("lfStatusFont", _LOGFONTW),
        ("lfMessageFont", _LOGFONTW),
        ("iPaddedBorderWidth", ctypes.c_int),
    ]


class _MEASUREITEMSTRUCT(ctypes.Structure):
    _fields_ = [
        ("CtlType", wintypes.UINT),
        ("CtlID", wintypes.UINT),
        ("itemID", wintypes.UINT),
        ("itemWidth", wintypes.UINT),
        ("itemHeight", wintypes.UINT),
        ("itemData", ctypes.c_size_t),
    ]


class _DRAWITEMSTRUCT(ctypes.Structure):
    _fields_ = [
        ("CtlType", wintypes.UINT),
        ("CtlID", wintypes.UINT),
        ("itemID", wintypes.UINT),
        ("itemAction", wintypes.UINT),
        ("itemState", wintypes.UINT),
        ("hwndItem", wintypes.HWND),
        ("hDC", wintypes.HDC),
        ("rcItem", wintypes.RECT),
        ("itemData", ctypes.c_size_t),
    ]


class _BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class _ICONINFO(ctypes.Structure):
    _fields_ = [
        ("fIcon", wintypes.BOOL),
        ("xHotspot", wintypes.DWORD),
        ("yHotspot", wintypes.DWORD),
        ("hbmMask", wintypes.HBITMAP),
        ("hbmColor", wintypes.HBITMAP),
    ]


_kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
_kernel32.GetModuleHandleW.restype = wintypes.HMODULE

_shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(_NOTIFYICONDATAW)]
_shell32.Shell_NotifyIconW.restype = wintypes.BOOL

_user32.RegisterClassExW.argtypes = [ctypes.POINTER(_WNDCLASSEXW)]
_user32.RegisterClassExW.restype = wintypes.ATOM
_user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
_user32.UnregisterClassW.restype = wintypes.BOOL
_user32.RegisterWindowMessageW.argtypes = [wintypes.LPCWSTR]
_user32.RegisterWindowMessageW.restype = wintypes.UINT
_user32.CreateWindowExW.argtypes = [
    wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
    ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
    wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
]
_user32.CreateWindowExW.restype = wintypes.HWND
_user32.DestroyWindow.argtypes = [wintypes.HWND]
_user32.DestroyWindow.restype = wintypes.BOOL
_user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
_user32.DefWindowProcW.restype = ctypes.c_ssize_t
_user32.SetForegroundWindow.argtypes = [wintypes.HWND]
_user32.SetForegroundWindow.restype = wintypes.BOOL
_user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
_user32.GetCursorPos.restype = wintypes.BOOL
_user32.CreatePopupMenu.argtypes = []
_user32.CreatePopupMenu.restype = wintypes.HMENU
_user32.DestroyMenu.argtypes = [wintypes.HMENU]
_user32.DestroyMenu.restype = wintypes.BOOL
_user32.InsertMenuItemW.argtypes = [wintypes.HMENU, wintypes.UINT, wintypes.BOOL, ctypes.POINTER(_MENUITEMINFOW)]
_user32.InsertMenuItemW.restype = wintypes.BOOL
_user32.TrackPopupMenuEx.argtypes = [
    wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int, wintypes.HWND, ctypes.c_void_p
]
_user32.TrackPopupMenuEx.restype = wintypes.BOOL
_user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
_user32.ShowWindow.restype = wintypes.BOOL
_user32.SetWindowPos.argtypes = [
    wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
    ctypes.c_int, ctypes.c_int, wintypes.UINT,
]
_user32.SetWindowPos.restype = wintypes.BOOL
_user32.InvalidateRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT), wintypes.BOOL]
_user32.InvalidateRect.restype = wintypes.BOOL
_user32.BeginPaint.argtypes = [wintypes.HWND, ctypes.POINTER(_PAINTSTRUCT)]
_user32.BeginPaint.restype = wintypes.HDC
_user32.EndPaint.argtypes = [wintypes.HWND, ctypes.POINTER(_PAINTSTRUCT)]
_user32.EndPaint.restype = wintypes.BOOL
_user32.GetDC.argtypes = [wintypes.HWND]
_user32.GetDC.restype = wintypes.HDC
_user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
_user32.ReleaseDC.restype = ctypes.c_int
_user32.FillRect.argtypes = [wintypes.HDC, ctypes.POINTER(wintypes.RECT), wintypes.HBRUSH]
_user32.FillRect.restype = ctypes.c_int
_user32.FrameRect.argtypes = [wintypes.HDC, ctypes.POINTER(wintypes.RECT), wintypes.HBRUSH]
_user32.FrameRect.restype = ctypes.c_int
_user32.GetSysColor.argtypes = [ctypes.c_int]
_user32.GetSysColor.restype = wintypes.DWORD
_user32.GetSysColorBrush.argtypes = [ctypes.c_int]
_user32.GetSysColorBrush.restype = wintypes.HBRUSH
_user32.DrawTextW.argtypes = [
    wintypes.HDC, wintypes.LPCWSTR, ctypes.c_int, ctypes.POINTER(wintypes.RECT), wintypes.UINT
]
_user32.DrawTextW.restype = ctypes.c_int
_user32.SystemParametersInfoW.argtypes = [wintypes.UINT, wintypes.UINT, ctypes.c_void_p, wintypes.UINT]
_user32.SystemParametersInfoW.restype = wintypes.BOOL
_user32.LoadCursorW.argtypes = [wintypes.HINSTANCE, ctypes.c_void_p]
_user32.LoadCursorW.restype = wintypes.HANDLE
_user32.SetCursor.argtypes = [wintypes.HANDLE]
_user32.SetCursor.restype = wintypes.HANDLE
_user32.CreateIconIndirect.argtypes = [ctypes.POINTER(_ICONINFO)]
_user32.CreateIconIndirect.restype = wintypes.HICON
_user32.DestroyIcon.argtypes = [wintypes.HICON]
_user32.DestroyIcon.restype = wintypes.BOOL
_user32.SetTimer.argtypes = [wintypes.HWND, ctypes.c_size_t, wintypes.UINT, ctypes.c_void_p]
_user32.SetTimer.restype = ctypes.c_size_t
_user32.KillTimer.argtypes = [wintypes.HWND, ctypes.c_size_t]
_user32.KillTimer.restype = wintypes.BOOL
_user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
_user32.PostMessageW.restype = wintypes.BOOL
_user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
_user32.GetMessageW.restype = wintypes.BOOL
_user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
_user32.TranslateMessage.restype = wintypes.BOOL
_user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
_user32.DispatchMessageW.restype = ctypes.c_ssize_t
_user32.PostQuitMessage.argtypes = [ctypes.c_int]
_user32.PostQuitMessage.restype = None

_gdi32.CreateFontIndirectW.argtypes = [ctypes.POINTER(_LOGFONTW)]
_gdi32.CreateFontIndirectW.restype = wintypes.HFONT
_gdi32.CreateFontW.argtypes = [
    ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
    wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
    wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR,
]
_gdi32.CreateFontW.restype = wintypes.HFONT
_gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
_gdi32.SelectObject.restype = wintypes.HGDIOBJ
_gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
_gdi32.DeleteObject.restype = wintypes.BOOL
_gdi32.SetBkMode.argtypes = [wintypes.HDC, ctypes.c_int]
_gdi32.SetBkMode.restype = ctypes.c_int
_gdi32.SetTextColor.argtypes = [wintypes.HDC, wintypes.DWORD]
_gdi32.SetTextColor.restype = wintypes.DWORD
_gdi32.GetTextExtentPoint32W.argtypes = [
    wintypes.HDC, wintypes.LPCWSTR, ctypes.c_int, ctypes.POINTER(wintypes.SIZE)
]
_gdi32.GetTextExtentPoint32W.restype = wintypes.BOOL
_gdi32.CreateSolidBrush.argtypes = [wintypes.DWORD]
_gdi32.CreateSolidBrush.restype = wintypes.HBRUSH
_gdi32.CreatePen.argtypes = [ctypes.c_int, ctypes.c_int, wintypes.DWORD]
_gdi32.CreatePen.restype = wintypes.HPEN
_gdi32.Ellipse.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int]
_gdi32.Ellipse.restype = wintypes.BOOL
_gdi32.CreateDIBSection.argtypes = [
    wintypes.HDC, ctypes.POINTER(_BITMAPINFOHEADER), wintypes.UINT,
    ctypes.POINTER(ctypes.c_void_p), wintypes.HANDLE, wintypes.DWORD,
]
_gdi32.CreateDIBSection.restype = wintypes.HBITMAP
_gdi32.CreateBitmap.argtypes = [ctypes.c_int, ctypes.c_int, wintypes.UINT, wintypes.UINT, ctypes.c_void_p]
_gdi32.CreateBitmap.restype = wintypes.HBITMAP

if _uxtheme is not None:
    _uxtheme.OpenThemeData.argtypes = [wintypes.HWND, wintypes.LPCWSTR]
    _uxtheme.OpenThemeData.restype = ctypes.c_void_p
    _uxtheme.CloseThemeData.argtypes = [ctypes.c_void_p]
    _uxtheme.CloseThemeData.restype = ctypes.c_long
    _uxtheme.DrawThemeBackground.argtypes = [
        ctypes.c_void_p, wintypes.HDC, ctypes.c_int, ctypes.c_int,
        ctypes.POINTER(wintypes.RECT), ctypes.POINTER(wintypes.RECT),
    ]
    _uxtheme.DrawThemeBackground.restype = ctypes.c_long

if _dwmapi is not None:
    _dwmapi.DwmSetWindowAttribute.argtypes = [
        wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD
    ]
    _dwmapi.DwmSetWindowAttribute.restype = ctypes.c_long


# ---------------------------------------------------------------------------
# Network scanning helpers
# ---------------------------------------------------------------------------
@dataclass
class Device:
    ip: str
    mac: str
    hostname: str
    is_local: bool = False
    missed_scans: int = 0


def acquire_single_instance_mutex() -> Optional[int]:
    """Ensure only one instance of WiFi Monitor runs at a time."""
    handle = _kernel32.CreateMutexW(None, False, MUTEX_NAME)
    ERROR_ALREADY_EXISTS = 183
    if _kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
        if handle:
            _kernel32.CloseHandle(handle)
        return None
    return handle


def get_local_ip() -> Optional[str]:
    """Return the local IPv4 address of the active network interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        return ip if ip and not ip.startswith("127.") else None
    except OSError:
        try:
            ip = socket.gethostbyname(socket.gethostname())
            return ip if ip and not ip.startswith("127.") else None
        except OSError:
            return None
    finally:
        s.close()


def get_local_mac() -> str:
    """Return the local machine's MAC address formatted as AA:BB:CC:DD:EE:FF."""
    node = uuid.getnode()
    return ":".join(f"{(node >> shift) & 0xFF:02X}" for shift in range(40, -1, -8))


def probe_ip(ip: str) -> None:
    """Send a lightweight native ICMP echo (triggers OS ARP resolution too)."""
    handle = _iphlpapi.IcmpCreateFile()
    if not handle or handle == ctypes.c_void_p(-1).value:
        return
    try:
        dest_ip = struct.unpack("<I", socket.inet_aton(ip))[0]
        reply_buf = ctypes.create_string_buffer(64)
        _iphlpapi.IcmpSendEcho(
            handle, dest_ip, b"a", 1, None, reply_buf, 64, PING_TIMEOUT_MS
        )
    except OSError:
        pass
    finally:
        _iphlpapi.IcmpCloseHandle(handle)


def read_arp_table(subnet_prefix: str) -> Dict[str, str]:
    """Read dynamic ARP entries for subnet_prefix via Win32 GetIpNetTable. Returns {mac: ip}."""
    size = ctypes.c_ulong(0)
    _iphlpapi.GetIpNetTable(None, ctypes.byref(size), False)
    if size.value == 0:
        return {}

    buf = ctypes.create_string_buffer(size.value)
    if _iphlpapi.GetIpNetTable(buf, ctypes.byref(size), False) != 0:
        return {}

    count = struct.unpack_from("<I", buf.raw, 0)[0]
    row_size = ctypes.sizeof(_MIB_IPNETROW)
    discovered: Dict[str, str] = {}

    for i in range(count):
        offset = 4 + i * row_size
        if offset + row_size > len(buf.raw):
            break
        row = _MIB_IPNETROW.from_buffer_copy(buf.raw, offset)
        if row.dwType == MIB_IPNET_TYPE_DYNAMIC and row.dwPhysAddrLen == 6:
            ip = socket.inet_ntoa(struct.pack("<I", row.dwAddr))
            if ip.startswith(subnet_prefix):
                mac = ":".join(f"{row.bPhysAddr[j]:02X}" for j in range(6))
                if mac != "00:00:00:00:00:00":
                    discovered[mac] = ip

    return discovered


def verify_arp(ip: str, src_ip_int: int) -> Optional[Tuple[str, str]]:
    """Send a live Win32 SendARP request to verify a candidate IP is truly online."""
    try:
        dest_ip = struct.unpack("<I", socket.inet_aton(ip))[0]
    except OSError:
        return None

    mac_buf = (ctypes.c_ubyte * 6)()
    mac_len = ctypes.c_ulong(6)
    ret = _iphlpapi.SendARP(dest_ip, src_ip_int, ctypes.byref(mac_buf), ctypes.byref(mac_len))
    if ret == 0 and mac_len.value == 6:
        mac = ":".join(f"{mac_buf[i]:02X}" for i in range(6))
        if mac != "00:00:00:00:00:00":
            return (ip, mac)
    return None


def resolve_hostname(ip: str) -> str:
    """Resolve hostname via reverse DNS; returns 'Unknown device' on failure."""
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name.strip() or "Unknown device"
    except (socket.herror, socket.gaierror, OSError):
        return "Unknown device"


def ip_sort_key(ip: str) -> Tuple[int, ...]:
    try:
        return tuple(int(part) for part in ip.split("."))
    except ValueError:
        return (999, 999, 999, 999)


# ---------------------------------------------------------------------------
# Icon creation (in-memory HICON from Pillow RGBA)
# ---------------------------------------------------------------------------
def create_tray_icon_image(state: str = "online") -> Image.Image:
    """Draw a clean 64x64 Wi-Fi icon for the Windows system tray."""
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    if state == "scanning":
        accent = (245, 166, 35, 255)   # Amber
    elif state == "offline":
        accent = (150, 150, 150, 255)  # Gray
    else:
        accent = (46, 204, 113, 255)   # Green

    draw.ellipse((2, 2, size - 2, size - 2), fill=(28, 32, 38, 240), outline=accent, width=3)
    draw.arc((12, 16, 52, 56), start=225, end=315, fill=accent, width=4)
    draw.arc((20, 24, 44, 48), start=225, end=315, fill=accent, width=4)
    draw.ellipse((28, 40, 36, 48), fill=accent)
    return img


def pil_to_hicon(img: Image.Image) -> int:
    """Convert a Pillow RGBA image directly into a Win32 HICON in memory."""
    rgba = img.convert("RGBA")
    w, h = rgba.size
    bgra = rgba.tobytes("raw", "BGRA")

    bmi = _BITMAPINFOHEADER()
    bmi.biSize = ctypes.sizeof(_BITMAPINFOHEADER)
    bmi.biWidth = w
    bmi.biHeight = -h  # Top-down DIB
    bmi.biPlanes = 1
    bmi.biBitCount = 32
    bmi.biCompression = 0  # BI_RGB

    bits_ptr = ctypes.c_void_p()
    hbm_color = _gdi32.CreateDIBSection(
        None, ctypes.byref(bmi), _DIB_RGB_COLORS, ctypes.byref(bits_ptr), None, 0
    )
    if not hbm_color:
        raise RuntimeError("CreateDIBSection failed")

    ctypes.memmove(bits_ptr, bgra, len(bgra))
    hbm_mask = _gdi32.CreateBitmap(w, h, 1, 1, None)

    icon_info = _ICONINFO()
    icon_info.fIcon = True
    icon_info.hbmMask = hbm_mask
    icon_info.hbmColor = hbm_color
    hicon = _user32.CreateIconIndirect(ctypes.byref(icon_info))

    _gdi32.DeleteObject(hbm_color)
    _gdi32.DeleteObject(hbm_mask)
    return hicon


# ---------------------------------------------------------------------------
# Pure Win32 System Tray Icon & Owner-Draw Context Menu (zero LGPL deps)
# ---------------------------------------------------------------------------
class NativeTrayIcon:
    """Pure Win32 system tray icon with static black-text device list menu."""

    def __init__(
        self,
        get_menu_state: Callable[[], Tuple[List[str], bool]],
        on_toggle_notifications: Callable[[], None],
        on_quit: Callable[[], None],
        on_ready: Callable[[], None],
    ) -> None:
        self._get_menu_state = get_menu_state
        self._on_toggle_notifications = on_toggle_notifications
        self._on_quit = on_quit
        self._on_ready = on_ready

        self._lock = threading.Lock()
        self._state = "scanning"
        self._tooltip = f"{APP_NAME} — Starting..."
        self._hwnd: Optional[int] = None
        self._hicons: Dict[str, int] = {}
        self._ownerdraw_labels: Dict[int, str] = {}
        self._menu_font: Optional[int] = None
        self._menu_theme: Optional[int] = None
        self._font_px: int = 14
        self._arrow_cursor = _user32.LoadCursorW(None, ctypes.c_void_p(_IDC_ARROW))
        self._wm_taskbar_created = _user32.RegisterWindowMessageW("TaskbarCreated")
        self._wndproc_ref = _WNDPROC(self._wndproc)

    def update(self, state: str, tooltip: str) -> None:
        with self._lock:
            self._state = state
            self._tooltip = tooltip[:127]
        if self._hwnd:
            _user32.PostMessageW(self._hwnd, _WM_APP_UPDATE_TRAY, 0, 0)

    def stop(self) -> None:
        if self._hwnd:
            _user32.PostMessageW(self._hwnd, _WM_APP_QUIT_TRAY, 0, 0)

    def _ensure_menu_resources(self) -> None:
        if self._menu_font is None:
            ncm = _NONCLIENTMETRICSW()
            ncm.cbSize = ctypes.sizeof(_NONCLIENTMETRICSW)
            if _user32.SystemParametersInfoW(
                _SPI_GETNONCLIENTMETRICS, ncm.cbSize, ctypes.byref(ncm), 0
            ):
                self._menu_font = _gdi32.CreateFontIndirectW(ctypes.byref(ncm.lfMenuFont))
                if ncm.lfMenuFont.lfHeight:
                    self._font_px = abs(ncm.lfMenuFont.lfHeight)
        if self._menu_theme is None and _uxtheme is not None and self._hwnd:
            self._menu_theme = _uxtheme.OpenThemeData(self._hwnd, "MENU")

    def _shell_notify(self, message: int, hwnd: int) -> None:
        with self._lock:
            hicon = self._hicons.get(self._state, self._hicons.get("online", 0))
            tip = self._tooltip
        nid = _NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(_NOTIFYICONDATAW)
        nid.hWnd = hwnd
        nid.uID = 1
        nid.uFlags = _NIF_MESSAGE | _NIF_ICON | _NIF_TIP
        nid.uCallbackMessage = _WM_TRAYICON
        nid.hIcon = hicon
        nid.szTip = tip
        _shell32.Shell_NotifyIconW(message, ctypes.byref(nid))

    def _show_context_menu(self, hwnd: int) -> None:
        labels, notif_enabled = self._get_menu_state()
        hmenu = _user32.CreatePopupMenu()
        if not hmenu:
            return

        self._ownerdraw_labels.clear()
        pos = 0

        try:
            display_labels = labels if labels else ["No devices found yet"]
            for idx, text in enumerate(display_labels, start=1):
                self._ownerdraw_labels[idx] = text
                mii = _MENUITEMINFOW()
                mii.cbSize = ctypes.sizeof(_MENUITEMINFOW)
                mii.fMask = _MIIM_ID | _MIIM_FTYPE | _MIIM_STATE | _MIIM_DATA
                mii.wID = idx
                mii.fType = _MFT_OWNERDRAW
                mii.fState = _MFS_DISABLED
                mii.dwItemData = idx
                _user32.InsertMenuItemW(hmenu, pos, True, ctypes.byref(mii))
                pos += 1

            # Separator
            sep1 = _MENUITEMINFOW(
                cbSize=ctypes.sizeof(_MENUITEMINFOW), fMask=_MIIM_FTYPE, fType=_MFT_SEPARATOR
            )
            _user32.InsertMenuItemW(hmenu, pos, True, ctypes.byref(sep1))
            pos += 1

            # Notifications toggle
            notif = _MENUITEMINFOW()
            notif.cbSize = ctypes.sizeof(_MENUITEMINFOW)
            notif.fMask = _MIIM_ID | _MIIM_FTYPE | _MIIM_STATE | _MIIM_STRING
            notif.wID = _MENU_ID_NOTIFICATIONS
            notif.fType = _MFT_STRING
            notif.fState = _MFS_CHECKED if notif_enabled else 0
            notif.dwTypeData = "Notifications"
            _user32.InsertMenuItemW(hmenu, pos, True, ctypes.byref(notif))
            pos += 1

            # Separator
            sep2 = _MENUITEMINFOW(
                cbSize=ctypes.sizeof(_MENUITEMINFOW), fMask=_MIIM_FTYPE, fType=_MFT_SEPARATOR
            )
            _user32.InsertMenuItemW(hmenu, pos, True, ctypes.byref(sep2))
            pos += 1

            # Quit
            quit_item = _MENUITEMINFOW()
            quit_item.cbSize = ctypes.sizeof(_MENUITEMINFOW)
            quit_item.fMask = _MIIM_ID | _MIIM_FTYPE | _MIIM_STRING
            quit_item.wID = _MENU_ID_QUIT
            quit_item.fType = _MFT_STRING
            quit_item.dwTypeData = "Quit"
            _user32.InsertMenuItemW(hmenu, pos, True, ctypes.byref(quit_item))

            _user32.SetForegroundWindow(hwnd)
            pt = wintypes.POINT()
            _user32.GetCursorPos(ctypes.byref(pt))
            cmd = _user32.TrackPopupMenuEx(
                hmenu,
                _TPM_RIGHTALIGN | _TPM_BOTTOMALIGN | _TPM_RETURNCMD,
                pt.x,
                pt.y,
                hwnd,
                None,
            )
            if cmd == _MENU_ID_NOTIFICATIONS:
                self._on_toggle_notifications()
            elif cmd == _MENU_ID_QUIT:
                self._on_quit()
        finally:
            _user32.DestroyMenu(hmenu)

    def _on_measure_item(self, hwnd: int, lparam: int) -> int:
        mis = _MEASUREITEMSTRUCT.from_address(lparam)
        if mis.CtlType != _ODT_MENU:
            return 0
        text = self._ownerdraw_labels.get(mis.itemData)
        if text is None:
            return 0
        self._ensure_menu_resources()
        hdc = _user32.GetDC(hwnd)
        if hdc:
            try:
                old_font = _gdi32.SelectObject(hdc, self._menu_font) if self._menu_font else None
                size = wintypes.SIZE()
                _gdi32.GetTextExtentPoint32W(hdc, text, len(text), ctypes.byref(size))
                if old_font:
                    _gdi32.SelectObject(hdc, old_font)
                left_pad = max(24, int(self._font_px * 2.0))
                right_pad = 16
                mis.itemWidth = size.cx + left_pad + right_pad
                mis.itemHeight = max(size.cy + 10, int(self._font_px * 1.9))
            finally:
                _user32.ReleaseDC(hwnd, hdc)
        return 1

    def _on_draw_item(self, lparam: int) -> int:
        dis = _DRAWITEMSTRUCT.from_address(lparam)
        if dis.CtlType != _ODT_MENU:
            return 0
        text = self._ownerdraw_labels.get(dis.itemData)
        if text is None:
            return 0
        self._ensure_menu_resources()
        hdc = dis.hDC
        rc = dis.rcItem

        if self._menu_theme and _uxtheme is not None:
            _uxtheme.DrawThemeBackground(
                self._menu_theme, hdc, _MENU_POPUPBACKGROUND, 0, ctypes.byref(rc), None
            )
        else:
            _user32.FillRect(hdc, ctypes.byref(rc), _user32.GetSysColorBrush(_COLOR_WINDOW))

        old_font = _gdi32.SelectObject(hdc, self._menu_font) if self._menu_font else None
        _gdi32.SetBkMode(hdc, _TRANSPARENT)
        _gdi32.SetTextColor(hdc, _user32.GetSysColor(_COLOR_MENUTEXT))

        left_pad = max(24, int(self._font_px * 2.0))
        text_rc = wintypes.RECT(rc.left + left_pad, rc.top, rc.right - 8, rc.bottom)
        _user32.DrawTextW(
            hdc, text, -1, ctypes.byref(text_rc),
            _DT_LEFT | _DT_VCENTER | _DT_SINGLELINE | _DT_NOPREFIX,
        )
        if old_font:
            _gdi32.SelectObject(hdc, old_font)
        return 1

    def _wndproc(self, hwnd: int, msg: int, wparam: int, lparam: int) -> int:
        if msg == _WM_SETCURSOR:
            if self._arrow_cursor:
                _user32.SetCursor(self._arrow_cursor)
                return 1
        elif msg == _WM_TRAYICON:
            if lparam == _WM_RBUTTONUP:
                self._show_context_menu(hwnd)
            return 0
        elif msg == _WM_MEASUREITEM:
            return self._on_measure_item(hwnd, lparam)
        elif msg == _WM_DRAWITEM:
            return self._on_draw_item(lparam)
        elif msg == _WM_APP_UPDATE_TRAY:
            self._shell_notify(_NIM_MODIFY, hwnd)
            return 0
        elif msg == _WM_APP_QUIT_TRAY:
            self._shell_notify(_NIM_DELETE, hwnd)
            _user32.DestroyWindow(hwnd)
            return 0
        elif msg == self._wm_taskbar_created and self._wm_taskbar_created:
            self._shell_notify(_NIM_ADD, hwnd)
            return 0
        elif msg == _WM_DESTROY:
            _user32.PostQuitMessage(0)
            return 0
        return _user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def run(self) -> None:
        hinst = _kernel32.GetModuleHandleW(None)
        cls_name = f"WiFiMonitorTray_{id(self)}"

        for state in ("online", "scanning", "offline"):
            self._hicons[state] = pil_to_hicon(create_tray_icon_image(state))

        wc = _WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(_WNDCLASSEXW)
        wc.lpfnWndProc = self._wndproc_ref
        wc.hInstance = hinst
        wc.hCursor = self._arrow_cursor
        wc.lpszClassName = cls_name
        _user32.RegisterClassExW(ctypes.byref(wc))

        hwnd = _user32.CreateWindowExW(
            0, cls_name, APP_NAME, _WS_POPUP,
            0, 0, 0, 0, None, None, hinst, None,
        )
        self._hwnd = hwnd
        self._shell_notify(_NIM_ADD, hwnd)

        threading.Thread(target=self._on_ready, daemon=True).start()

        msg = wintypes.MSG()
        while _user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            _user32.TranslateMessage(ctypes.byref(msg))
            _user32.DispatchMessageW(ctypes.byref(msg))

        if self._menu_font:
            _gdi32.DeleteObject(self._menu_font)
            self._menu_font = None
        if self._menu_theme and _uxtheme is not None:
            _uxtheme.CloseThemeData(self._menu_theme)
            self._menu_theme = None
        for hicon in self._hicons.values():
            if hicon:
                _user32.DestroyIcon(hicon)
        self._hicons.clear()
        _user32.UnregisterClassW(cls_name, hinst)
        self._hwnd = None


# ---------------------------------------------------------------------------
# Custom Dark Win32 Toast Notification (no '...' menu button)
# ---------------------------------------------------------------------------
class ToastPopup:
    """Clean, dark Windows 11-style notification box without the '...' menu button."""

    WIDTH = 340
    HEIGHT = 96

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._title = ""
        self._message = ""
        self._accent = _rgb(46, 204, 113)
        self._hwnd: Optional[int] = None
        self._ready = threading.Event()
        self._wndproc_ref = _WNDPROC(self._wndproc)
        self._thread: Optional[threading.Thread] = None
        self._arrow_cursor = _user32.LoadCursorW(None, ctypes.c_void_p(_IDC_ARROW))
        self._font_header = None
        self._font_title = None
        self._font_body = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=3.0)

    def show(self, title: str, message: str, is_join: bool = True) -> None:
        with self._lock:
            self._title = title
            self._message = message
            self._accent = _rgb(46, 204, 113) if is_join else _rgb(245, 166, 35)
        if self._hwnd:
            _user32.PostMessageW(self._hwnd, _WM_APP_SHOW_TOAST, 0, 0)

    def stop(self) -> None:
        if self._hwnd:
            _user32.PostMessageW(self._hwnd, _WM_APP_QUIT_TOAST, 0, 0)

    def _run_loop(self) -> None:
        hinst = _kernel32.GetModuleHandleW(None)
        cls_name = f"WiFiMonitorToast_{id(self)}"

        wc = _WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(_WNDCLASSEXW)
        wc.lpfnWndProc = self._wndproc_ref
        wc.hInstance = hinst
        wc.hCursor = self._arrow_cursor
        wc.lpszClassName = cls_name
        _user32.RegisterClassExW(ctypes.byref(wc))

        self._font_header = _gdi32.CreateFontW(
            -13, 0, 0, 0, _FW_NORMAL, 0, 0, 0, _DEFAULT_CHARSET, 0, 0, _CLEARTYPE_QUALITY, 0, "Segoe UI"
        )
        self._font_title = _gdi32.CreateFontW(
            -15, 0, 0, 0, _FW_SEMIBOLD, 0, 0, 0, _DEFAULT_CHARSET, 0, 0, _CLEARTYPE_QUALITY, 0, "Segoe UI"
        )
        self._font_body = _gdi32.CreateFontW(
            -13, 0, 0, 0, _FW_NORMAL, 0, 0, 0, _DEFAULT_CHARSET, 0, 0, _CLEARTYPE_QUALITY, 0, "Segoe UI"
        )

        hwnd = _user32.CreateWindowExW(
            _WS_EX_TOPMOST | _WS_EX_TOOLWINDOW | _WS_EX_NOACTIVATE,
            cls_name,
            APP_NAME,
            _WS_POPUP,
            0, 0, self.WIDTH, self.HEIGHT,
            None, None, hinst, None,
        )
        self._hwnd = hwnd

        if _dwmapi is not None and hwnd:
            pref = ctypes.c_int(_DWMWCP_ROUND)
            _dwmapi.DwmSetWindowAttribute(
                hwnd, _DWMWA_WINDOW_CORNER_PREFERENCE, ctypes.byref(pref), ctypes.sizeof(pref)
            )

        self._ready.set()

        msg = wintypes.MSG()
        while _user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            _user32.TranslateMessage(ctypes.byref(msg))
            _user32.DispatchMessageW(ctypes.byref(msg))

        for f in (self._font_header, self._font_title, self._font_body):
            if f:
                _gdi32.DeleteObject(f)
        _user32.UnregisterClassW(cls_name, hinst)
        self._hwnd = None

    def _position_bottom_right(self, hwnd: int) -> None:
        work = wintypes.RECT()
        _user32.SystemParametersInfoW(_SPI_GETWORKAREA, 0, ctypes.byref(work), 0)
        x = work.right - self.WIDTH - 16
        y = work.bottom - self.HEIGHT - 16
        _user32.SetWindowPos(
            hwnd, _HWND_TOPMOST, x, y, self.WIDTH, self.HEIGHT,
            _SWP_NOACTIVATE | _SWP_SHOWWINDOW,
        )

    def _paint(self, hwnd: int) -> None:
        ps = _PAINTSTRUCT()
        hdc = _user32.BeginPaint(hwnd, ctypes.byref(ps))
        if not hdc:
            return
        try:
            with self._lock:
                title = self._title
                message = self._message
                accent = self._accent

            rc = wintypes.RECT(0, 0, self.WIDTH, self.HEIGHT)
            bg_brush = _gdi32.CreateSolidBrush(_rgb(32, 32, 32))
            border_brush = _gdi32.CreateSolidBrush(_rgb(68, 68, 68))
            _user32.FillRect(hdc, ctypes.byref(rc), bg_brush)
            _user32.FrameRect(hdc, ctypes.byref(rc), border_brush)
            _gdi32.DeleteObject(bg_brush)
            _gdi32.DeleteObject(border_brush)

            dot_brush = _gdi32.CreateSolidBrush(accent)
            dot_pen = _gdi32.CreatePen(0, 1, accent)
            old_brush = _gdi32.SelectObject(hdc, dot_brush)
            old_pen = _gdi32.SelectObject(hdc, dot_pen)
            _gdi32.Ellipse(hdc, 16, 17, 26, 27)
            _gdi32.SelectObject(hdc, old_brush)
            _gdi32.SelectObject(hdc, old_pen)
            _gdi32.DeleteObject(dot_brush)
            _gdi32.DeleteObject(dot_pen)

            _gdi32.SetBkMode(hdc, _TRANSPARENT)

            old_font = _gdi32.SelectObject(hdc, self._font_header)
            _gdi32.SetTextColor(hdc, _rgb(190, 195, 205))
            hdr_rc = wintypes.RECT(34, 12, self.WIDTH - 36, 32)
            _user32.DrawTextW(hdc, APP_NAME, -1, ctypes.byref(hdr_rc), _DT_LEFT | _DT_VCENTER | _DT_SINGLELINE)

            _gdi32.SetTextColor(hdc, _rgb(145, 150, 160))
            close_rc = wintypes.RECT(self.WIDTH - 32, 10, self.WIDTH - 14, 30)
            _user32.DrawTextW(hdc, "\u00D7", -1, ctypes.byref(close_rc), _DT_RIGHT | _DT_VCENTER | _DT_SINGLELINE)

            _gdi32.SelectObject(hdc, self._font_title)
            _gdi32.SetTextColor(hdc, _rgb(245, 247, 250))
            title_rc = wintypes.RECT(16, 40, self.WIDTH - 16, 62)
            _user32.DrawTextW(
                hdc, title, -1, ctypes.byref(title_rc),
                _DT_LEFT | _DT_VCENTER | _DT_SINGLELINE | _DT_END_ELLIPSIS | _DT_NOPREFIX,
            )

            _gdi32.SelectObject(hdc, self._font_body)
            _gdi32.SetTextColor(hdc, _rgb(175, 180, 190))
            body_rc = wintypes.RECT(16, 64, self.WIDTH - 16, 84)
            _user32.DrawTextW(
                hdc, message, -1, ctypes.byref(body_rc),
                _DT_LEFT | _DT_VCENTER | _DT_SINGLELINE | _DT_END_ELLIPSIS | _DT_NOPREFIX,
            )

            if old_font:
                _gdi32.SelectObject(hdc, old_font)
        finally:
            _user32.EndPaint(hwnd, ctypes.byref(ps))

    def _wndproc(self, hwnd: int, msg: int, wparam: int, lparam: int) -> int:
        if msg == _WM_SETCURSOR:
            if self._arrow_cursor:
                _user32.SetCursor(self._arrow_cursor)
                return 1
        if msg == _WM_PAINT:
            self._paint(hwnd)
            return 0
        if msg == _WM_APP_SHOW_TOAST:
            self._position_bottom_right(hwnd)
            _user32.ShowWindow(hwnd, _SW_SHOWNOACTIVATE)
            _user32.InvalidateRect(hwnd, None, True)
            _user32.SetTimer(hwnd, _TOAST_TIMER_ID, _TOAST_DURATION_MS, None)
            return 0
        if msg == _WM_TIMER and wparam == _TOAST_TIMER_ID:
            _user32.KillTimer(hwnd, _TOAST_TIMER_ID)
            _user32.ShowWindow(hwnd, _SW_HIDE)
            return 0
        if msg == _WM_LBUTTONUP:
            _user32.KillTimer(hwnd, _TOAST_TIMER_ID)
            _user32.ShowWindow(hwnd, _SW_HIDE)
            return 0
        if msg == _WM_APP_QUIT_TOAST:
            _user32.KillTimer(hwnd, _TOAST_TIMER_ID)
            _user32.DestroyWindow(hwnd)
            return 0
        if msg == _WM_DESTROY:
            _user32.PostQuitMessage(0)
            return 0
        return _user32.DefWindowProcW(hwnd, msg, wparam, lparam)


# ---------------------------------------------------------------------------
# Main Application
# ---------------------------------------------------------------------------
class WiFiMonitorApp:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

        self._devices: Dict[str, Device] = {}       # keyed by MAC address
        self._hostname_cache: Dict[str, str] = {}   # keyed by MAC address
        self._current_subnet: Optional[str] = None
        self._is_scanning: bool = False
        self._notifications_enabled: bool = True
        self._baseline_ready: bool = False

        self._toast = ToastPopup()
        self._tray = NativeTrayIcon(
            get_menu_state=self._get_menu_state,
            on_toggle_notifications=self._on_toggle_notifications,
            on_quit=self._on_quit,
            on_ready=self._on_ready,
        )

    def _get_menu_state(self) -> Tuple[List[str], bool]:
        with self._lock:
            devices = sorted(self._devices.values(), key=lambda d: ip_sort_key(d.ip))
            labels = [
                f"{d.ip}  —  {d.hostname}{' (This PC)' if d.is_local else ''}"
                for d in devices
            ]
            return labels, self._notifications_enabled

    def _on_toggle_notifications(self) -> None:
        with self._lock:
            self._notifications_enabled = not self._notifications_enabled

    def _on_quit(self) -> None:
        self._stop_event.set()
        self._toast.stop()
        self._tray.stop()

    def _refresh_tray(self) -> None:
        with self._lock:
            count = len(self._devices)
            subnet = self._current_subnet
            scanning = self._is_scanning

        if scanning:
            self._tray.update("scanning", f"{APP_NAME} — Scanning...")
        elif not subnet:
            self._tray.update("offline", f"{APP_NAME} — Offline")
        else:
            self._tray.update(
                "online", f"{APP_NAME} — {count} device{'s' if count != 1 else ''} online"
            )

    def _notify(self, title: str, message: str, is_join: bool = True) -> None:
        with self._lock:
            if not self._notifications_enabled:
                return
        try:
            self._toast.show(title, message, is_join=is_join)
        except Exception:
            pass

    def perform_scan(self, full_scan: bool = True, show_indicator: bool = False) -> None:
        """Run a fast liveness check or a full /24 discovery scan."""
        if show_indicator:
            with self._lock:
                self._is_scanning = True
            self._refresh_tray()

        local_ip = get_local_ip()
        if not local_ip:
            with self._lock:
                was_online = self._current_subnet is not None or bool(self._devices)
                self._current_subnet = None
                self._devices.clear()
                self._baseline_ready = False
                self._is_scanning = False
            if was_online or show_indicator:
                self._refresh_tray()
            return

        prefix = ".".join(local_ip.split(".")[:-1]) + "."
        src_ip_int = struct.unpack("<I", socket.inet_aton(local_ip))[0]

        subnet_changed = False
        with self._lock:
            if self._current_subnet is not None and self._current_subnet != prefix:
                self._devices.clear()
                self._hostname_cache.clear()
                self._baseline_ready = False
                subnet_changed = True
            self._current_subnet = prefix
            tracked_ips = {d.ip for d in self._devices.values() if not d.is_local}

        # Stage 1 (full scan only): Fast native ICMP sweep to wake ARP for newly joined devices
        if full_scan or subnet_changed:
            ips = [f"{prefix}{i}" for i in range(1, 255) if f"{prefix}{i}" != local_ip]
            with ThreadPoolExecutor(max_workers=PING_WORKERS) as executor:
                futures = [executor.submit(probe_ip, ip) for ip in ips]
                for fut in futures:
                    if self._stop_event.is_set():
                        return
                    fut.result()

        # Collect candidate IPs from OS ARP table + currently tracked devices
        arp_candidates = read_arp_table(prefix)
        candidate_ips = (set(arp_candidates.values()) | tracked_ips) - {local_ip}

        # Stage 2: Verify only the small set of candidates with live SendARP
        discovered: Dict[str, str] = {}
        if candidate_ips and not self._stop_event.is_set():
            workers = min(len(candidate_ips), 32)
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [executor.submit(verify_arp, ip, src_ip_int) for ip in candidate_ips]
                for fut in futures:
                    if self._stop_event.is_set():
                        return
                    res = fut.result()
                    if res:
                        ip, mac = res
                        discovered[mac] = ip

        # Ensure local PC is always present
        local_mac = get_local_mac()
        if local_ip not in discovered.values():
            discovered[local_mac] = local_ip

        # Resolve hostnames only for devices not yet cached
        ips_to_resolve: Dict[str, str] = {}
        with self._lock:
            for mac, ip in discovered.items():
                if ip == local_ip:
                    self._hostname_cache[mac] = socket.gethostname()
                elif mac not in self._hostname_cache or self._hostname_cache[mac] == "Unknown device":
                    ips_to_resolve[mac] = ip

        if ips_to_resolve and not self._stop_event.is_set():
            with ThreadPoolExecutor(max_workers=DNS_WORKERS) as executor:
                future_map = {
                    executor.submit(resolve_hostname, ip): mac
                    for mac, ip in ips_to_resolve.items()
                }
                for fut, mac in future_map.items():
                    if self._stop_event.is_set():
                        return
                    hostname = fut.result()
                    with self._lock:
                        self._hostname_cache[mac] = hostname

        joined: List[Device] = []
        left: List[Device] = []
        state_changed = subnet_changed

        with self._lock:
            for mac, ip in discovered.items():
                hostname = self._hostname_cache.get(mac, "Unknown device")
                is_local = ip == local_ip
                if mac in self._devices:
                    dev = self._devices[mac]
                    if dev.ip != ip or dev.hostname != hostname:
                        state_changed = True
                    dev.ip = ip
                    dev.hostname = hostname
                    dev.is_local = is_local
                    dev.missed_scans = 0
                else:
                    new_dev = Device(ip=ip, mac=mac, hostname=hostname, is_local=is_local)
                    self._devices[mac] = new_dev
                    state_changed = True
                    if self._baseline_ready and not is_local:
                        joined.append(new_dev)

            to_remove: List[str] = []
            for mac, dev in self._devices.items():
                if mac not in discovered:
                    dev.missed_scans += 1
                    if dev.missed_scans >= LEAVE_GRACE_SCANS:
                        to_remove.append(mac)

            for mac in to_remove:
                removed = self._devices.pop(mac)
                state_changed = True
                if self._baseline_ready and not removed.is_local:
                    left.append(removed)

            self._baseline_ready = True
            self._is_scanning = False

        if state_changed or show_indicator:
            self._refresh_tray()

        if joined:
            if len(joined) == 1:
                d = joined[0]
                self._notify("Device Joined Wi-Fi", f"{d.hostname} ({d.ip})", is_join=True)
            else:
                names = ", ".join(d.hostname for d in joined[:3])
                extra = f" +{len(joined) - 3} more" if len(joined) > 3 else ""
                self._notify(f"{len(joined)} Devices Joined Wi-Fi", f"{names}{extra}", is_join=True)

        if left:
            if len(left) == 1:
                d = left[0]
                self._notify("Device Left Wi-Fi", f"{d.hostname} ({d.ip})", is_join=False)
            else:
                names = ", ".join(d.hostname for d in left[:3])
                extra = f" +{len(left) - 3} more" if len(left) > 3 else ""
                self._notify(f"{len(left)} Devices Left Wi-Fi", f"{names}{extra}", is_join=False)

    def _background_loop(self) -> None:
        last_full_scan = 0.0
        first_run = True

        while not self._stop_event.is_set():
            now = time.monotonic()
            do_full = first_run or (now - last_full_scan >= FULL_SCAN_INTERVAL_SECONDS)

            try:
                self.perform_scan(full_scan=do_full, show_indicator=first_run)
                if do_full:
                    last_full_scan = time.monotonic()
                    first_run = False
            except Exception:
                with self._lock:
                    self._is_scanning = False
                self._refresh_tray()

            self._stop_event.wait(timeout=FAST_CHECK_INTERVAL_SECONDS)

    def _on_ready(self) -> None:
        self._toast.start()
        self._background_loop()

    def run(self) -> None:
        self._tray.run()


def main() -> None:
    mutex = acquire_single_instance_mutex()
    if mutex is None:
        sys.exit(0)
    try:
        app = WiFiMonitorApp()
        app.run()
    finally:
        _kernel32.CloseHandle(mutex)


if __name__ == "__main__":
    main()
