"""
Wi-Fi Monitor — Lightweight Windows System Tray Network Monitor.

Two-tier background scanning using native Win32 APIs (zero subprocesses):
- Fast check every 5s: live SendARP on known devices + OS ARP table (~0% CPU)
- Full /24 discovery every 30s: native IcmpSendEcho + SendARP verification
"""

from __future__ import annotations

import ctypes
import socket
import struct
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import pystray
from PIL import Image, ImageDraw

APP_NAME = "Wi-Fi Monitor"
FAST_CHECK_INTERVAL_SECONDS = 5    # Quick liveness check for known devices
FULL_SCAN_INTERVAL_SECONDS = 30    # Full /24 sweep to discover newly joined devices
LEAVE_GRACE_SCANS = 2              # 2 consecutive misses (~10-15s) before reporting "Left"
PING_TIMEOUT_MS = 250
PING_WORKERS = 64                  # I/O-bound kernel waits; completes /24 in ~1.5s with ~0% CPU
DNS_WORKERS = 8
MIB_IPNET_TYPE_DYNAMIC = 3
MUTEX_NAME = "Global\\WiFiMonitorTrayApp_SingleInstance_Mutex"

# Win32 iphlpapi.dll bindings (zero subprocesses, language-independent)
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


@dataclass
class Device:
    ip: str
    mac: str
    hostname: str
    is_local: bool = False
    missed_scans: int = 0


def acquire_single_instance_mutex() -> Optional[int]:
    """Ensure only one instance of Wi-Fi Monitor runs at a time."""
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateMutexW(None, False, MUTEX_NAME)
    ERROR_ALREADY_EXISTS = 183
    if kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
        if handle:
            kernel32.CloseHandle(handle)
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

    # Subtle dark circular badge for contrast on both light & dark taskbars
    draw.ellipse((2, 2, size - 2, size - 2), fill=(28, 32, 38, 240), outline=accent, width=3)

    # Wi-Fi arcs
    draw.arc((12, 16, 52, 56), start=225, end=315, fill=accent, width=4)
    draw.arc((20, 24, 44, 48), start=225, end=315, fill=accent, width=4)
    # Center dot
    draw.ellipse((28, 40, 36, 48), fill=accent)

    return img


class WiFiMonitorApp:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

        self._devices: Dict[str, Device] = {}       # keyed by MAC address
        self._hostname_cache: Dict[str, str] = {}   # keyed by MAC address
        self._current_subnet: Optional[str] = None
        self._last_scan_time: str = "Never"
        self._is_scanning: bool = False
        self._notifications_enabled: bool = True
        self._baseline_ready: bool = False

        self._icon_online = create_tray_icon_image("online")
        self._icon_scanning = create_tray_icon_image("scanning")
        self._icon_offline = create_tray_icon_image("offline")

        self.icon = pystray.Icon(
            name="wifi_monitor",
            icon=self._icon_scanning,
            title=f"{APP_NAME} — Starting...",
            menu=self._build_menu(),
        )

    def _build_menu(self) -> pystray.Menu:
        with self._lock:
            subnet = self._current_subnet
            last_scan = self._last_scan_time
            scanning = self._is_scanning
            devices = sorted(self._devices.values(), key=lambda d: ip_sort_key(d.ip))

        items: List[pystray.MenuItem] = []

        if subnet:
            header = f"Network {subnet}0/24 — {len(devices)} device{'s' if len(devices) != 1 else ''}"
        else:
            header = "No active network"

        items.append(pystray.MenuItem(header, None, enabled=False))
        status_text = "Scanning..." if scanning else f"Last scan: {last_scan}"
        items.append(pystray.MenuItem(status_text, None, enabled=False))
        items.append(pystray.Menu.SEPARATOR)

        if devices:
            for dev in devices:
                tag = " (This PC)" if dev.is_local else ""
                label = f"{dev.ip}  —  {dev.hostname}{tag}"
                items.append(pystray.MenuItem(label, self._noop))
        else:
            items.append(pystray.MenuItem("No devices found yet", None, enabled=False))

        items.append(pystray.Menu.SEPARATOR)
        items.append(
            pystray.MenuItem(
                "Notifications",
                self._on_toggle_notifications,
                checked=lambda _: self._notifications_enabled,
            )
        )
        items.append(pystray.Menu.SEPARATOR)
        items.append(pystray.MenuItem("Quit", self._on_quit))

        return pystray.Menu(*items)

    @staticmethod
    def _noop(icon: pystray.Icon, item: pystray.MenuItem) -> None:
        pass

    def _on_toggle_notifications(self, icon: pystray.Icon, item: pystray.MenuItem) -> None:
        self._notifications_enabled = not self._notifications_enabled
        self._refresh_tray()

    def _on_quit(self, icon: pystray.Icon, item: pystray.MenuItem) -> None:
        self._stop_event.set()
        icon.stop()

    def _refresh_tray(self) -> None:
        with self._lock:
            count = len(self._devices)
            subnet = self._current_subnet
            scanning = self._is_scanning

        if scanning:
            self.icon.icon = self._icon_scanning
            self.icon.title = f"{APP_NAME} — Scanning..."
        elif not subnet:
            self.icon.icon = self._icon_offline
            self.icon.title = f"{APP_NAME} — Offline"
        else:
            self.icon.icon = self._icon_online
            self.icon.title = f"{APP_NAME} — {count} device{'s' if count != 1 else ''} online"

        self.icon.menu = self._build_menu()
        try:
            self.icon.update_menu()
        except Exception:
            pass

    def _notify(self, title: str, message: str) -> None:
        if not self._notifications_enabled:
            return
        try:
            self.icon.notify(message, title)
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
                self._last_scan_time = datetime.now().strftime("%H:%M:%S")
            if was_online or show_indicator or full_scan:
                self._refresh_tray()
            return

        prefix = ".".join(local_ip.split(".")[:-1]) + "."
        src_ip_int = struct.unpack("<I", socket.inet_aton(local_ip))[0]

        # If we switched Wi-Fi networks, reset state silently
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
        # (prevents Windows' stale ARP cache from keeping offline devices listed)
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
            # Update existing & add newly joined devices
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

            # Check for missing devices (with grace period)
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
            if full_scan or state_changed or show_indicator:
                self._last_scan_time = datetime.now().strftime("%H:%M:%S")

        if full_scan or state_changed or show_indicator:
            self._refresh_tray()

        # Send consolidated notifications
        if joined:
            if len(joined) == 1:
                d = joined[0]
                self._notify("Device Joined Wi-Fi", f"{d.hostname} ({d.ip})")
            else:
                names = ", ".join(d.hostname for d in joined[:3])
                extra = f" +{len(joined) - 3} more" if len(joined) > 3 else ""
                self._notify(f"{len(joined)} Devices Joined Wi-Fi", f"{names}{extra}")

        if left:
            if len(left) == 1:
                d = left[0]
                self._notify("Device Left Wi-Fi", f"{d.hostname} ({d.ip})")
            else:
                names = ", ".join(d.hostname for d in left[:3])
                extra = f" +{len(left) - 3} more" if len(left) > 3 else ""
                self._notify(f"{len(left)} Devices Left Wi-Fi", f"{names}{extra}")

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

            # Sleep with 0% CPU until next fast check (5s)
            self._stop_event.wait(timeout=FAST_CHECK_INTERVAL_SECONDS)

    def _on_setup(self, icon: pystray.Icon) -> None:
        icon.visible = True
        self._background_loop()

    def run(self) -> None:
        self.icon.run(setup=self._on_setup)


def main() -> None:
    mutex = acquire_single_instance_mutex()
    if mutex is None:
        sys.exit(0)
    try:
        app = WiFiMonitorApp()
        app.run()
    finally:
        ctypes.windll.kernel32.CloseHandle(mutex)


if __name__ == "__main__":
    main()
