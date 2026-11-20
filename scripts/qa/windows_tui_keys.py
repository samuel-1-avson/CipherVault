"""Real Windows console key test for the TUI Explorer [b] toggle.

Run INSIDE a fresh classic console:  conhost.exe python -I tui_keys.py <exe> <out.json> <mode>

The harness shares its console with the TUI child and drives it with real
key input, then reads the active screen buffer back:

  mode "sendinput": SendInput() keystrokes (scan-code key down + key up)
      into this console window, the same path a physical keyboard takes.
  mode "console":   WriteConsoleInputW() KEY_EVENT down+up record pairs,
      exactly what conhost queues for one physical key press.

Sequence: wait for the first frame, press [7] (Explorer tab), press [b],
wait, capture; press [b] again, capture; then [q] to quit. The result is
whether " Local CipherChain " is on screen after the first [b].
"""
import ctypes
import json
import os
import subprocess
import sys
import time
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
u32 = ctypes.WinDLL("user32", use_last_error=True)

EXE, OUT, MODE = sys.argv[1], sys.argv[2], sys.argv[3]

GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
FILE_SHARE_RW = 0x3
OPEN_EXISTING = 3


class COORD(ctypes.Structure):
    _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]


class SMALL_RECT(ctypes.Structure):
    _fields_ = [("Left", ctypes.c_short), ("Top", ctypes.c_short), ("Right", ctypes.c_short), ("Bottom", ctypes.c_short)]


class CSBI(ctypes.Structure):
    _fields_ = [("dwSize", COORD), ("dwCursorPosition", COORD), ("wAttributes", wintypes.WORD),
                ("srWindow", SMALL_RECT), ("dwMaximumWindowSize", COORD)]


class KEY_EVENT_RECORD(ctypes.Structure):
    _fields_ = [("bKeyDown", wintypes.BOOL), ("wRepeatCount", wintypes.WORD), ("wVirtualKeyCode", wintypes.WORD),
                ("wVirtualScanCode", wintypes.WORD), ("UnicodeChar", wintypes.WCHAR), ("dwControlKeyState", wintypes.DWORD)]


class INPUT_RECORD(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [("KeyEvent", KEY_EVENT_RECORD), ("pad", ctypes.c_byte * 16)]
    _fields_ = [("EventType", wintypes.WORD), ("Event", _U)]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD), ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_size_t)]


class INPUT(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [("ki", KEYBDINPUT), ("pad", ctypes.c_byte * 32)]
    _fields_ = [("type", wintypes.DWORD), ("u", _U)]


def handle(name):
    h = k32.CreateFileW(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_RW, None, OPEN_EXISTING, 0, None)
    if h in (0, -1):
        raise OSError(ctypes.get_last_error(), name)
    return h


def screen_text():
    out = handle("CONOUT$")  # the ACTIVE buffer, i.e. the TUI's alternate screen
    try:
        info = CSBI()
        k32.GetConsoleScreenBufferInfo(out, ctypes.byref(info))
        width = info.dwSize.X
        top, bottom = info.srWindow.Top, info.srWindow.Bottom
        lines = []
        buf = ctypes.create_unicode_buffer(width + 1)
        read = wintypes.DWORD()
        for y in range(top, bottom + 1):
            k32.ReadConsoleOutputCharacterW(out, buf, width, COORD(0, y), ctypes.byref(read))
            lines.append(buf.value[: read.value].rstrip())
        return "\n".join(lines)
    finally:
        k32.CloseHandle(out)


VK = {"7": 0x37, "b": 0x42, "q": 0x51}


def press(ch):
    vk = VK[ch]
    scan = u32.MapVirtualKeyW(vk, 0)
    if MODE == "sendinput":
        KEYEVENTF_KEYUP = 0x2
        seq = (INPUT * 2)()
        for i, flags in enumerate((0, KEYEVENTF_KEYUP)):
            seq[i].type = 1  # INPUT_KEYBOARD
            seq[i].u.ki = KEYBDINPUT(vk, scan, flags, 0, 0)
        sent = u32.SendInput(2, seq, ctypes.sizeof(INPUT))
        return {"key": ch, "sendinput_events": sent}
    conin = handle("CONIN$")
    try:
        recs = (INPUT_RECORD * 2)()
        for i, down in enumerate((True, False)):
            recs[i].EventType = 1  # KEY_EVENT
            recs[i].Event.KeyEvent = KEY_EVENT_RECORD(down, 1, vk, scan, ch, 0)
        written = wintypes.DWORD()
        k32.WriteConsoleInputW(conin, recs, 2, ctypes.byref(written))
        return {"key": ch, "records_written": written.value}
    finally:
        k32.CloseHandle(conin)


result = {"exe": EXE, "mode": MODE, "steps": []}
hwnd = k32.GetConsoleWindow()
if MODE == "sendinput":
    u32.ShowWindow(hwnd, 9)
    u32.SetForegroundWindow(hwnd)
    time.sleep(0.5)
    result["foreground_is_console"] = u32.GetForegroundWindow() == hwnd

env = dict(os.environ)
child = subprocess.Popen([EXE, "tui"], env=env)
time.sleep(6)  # first frame + initial background polls
result["steps"].append({"after": "start", "explorer_hint_visible": "Explorer" in screen_text()})
result["steps"].append(press("7"))
time.sleep(2)
txt = screen_text()
result["steps"].append({"after": "7", "explorer_tab": "Object Quorum Lookup" in txt})
result["steps"].append(press("b"))
time.sleep(2.5)
txt = screen_text()
first_b_open = " Local CipherChain " in txt
result["steps"].append({"after": "b #1", "local_cipherchain_open": first_b_open})
result["screen_after_first_b"] = txt
result["steps"].append(press("b"))
time.sleep(2)
second = " Local CipherChain " in screen_text()
result["steps"].append({"after": "b #2", "local_cipherchain_open": second})
result["steps"].append(press("q"))
time.sleep(2)
if child.poll() is None:
    result["steps"].append(press("q"))
    time.sleep(2)
if child.poll() is None:
    child.terminate()
    result["terminated"] = True
result["exit_code"] = child.poll()
result["verdict"] = "PASS: [b] keeps Local CipherChain open" if first_b_open and not second else (
    "BUG REPRODUCED: [b] opened then closed on key release" if not first_b_open else "UNEXPECTED: second [b] did not close")
with open(OUT, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)
