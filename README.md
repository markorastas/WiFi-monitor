# Wi-Fi Monitor

A lightweight Windows system tray utility that monitors your local Wi-Fi (`/24`) network and notifies you when devices join or leave.

## Features

- **System tray icon** next to the Windows clock with a right-click menu listing all active devices (`IP — Hostname`), a **Notifications** toggle, and **Quit**.
- **Join & Leave notifications** via native Windows notifications.
- **Near-zero system load** — uses native Win32 APIs (`IcmpSendEcho`, `GetIpNetTable`, and `SendARP` from `iphlpapi.dll`) directly in-process:
  - Zero subprocesses and no flashing console windows.
  - Works on any Windows display language.
  - Two-tier scanning: fast live ARP verification on known devices every **5 seconds** (~0% CPU) and full `/24` discovery every **30 seconds**.
  - 2-check grace period (~10–15 s) before reporting a device as disconnected to reduce false alarms from sleeping phones.
- **Single-instance guard** via a Windows mutex.
- **Single-file implementation** (`wifi_monitor.py`).

## Requirements

- Windows 10 / 11
- Python 3.10+
- `pystray` and `Pillow`

```powershell
pip install pystray Pillow
```

## Usage

Run silently in the background (no console window):

```powershell
pythonw wifi_monitor.py
```

Or run from a terminal:

```powershell
python wifi_monitor.py
```

Right-click the green Wi-Fi icon in the system tray to view connected devices, toggle notifications, or quit.
