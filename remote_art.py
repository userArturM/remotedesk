#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
remote-Art — портативный удалённый доступ между компьютерами.

  • шифрование TLS + защита от подмены (привязка пароля к ключу компьютера)
  • управление мышью и клавиатурой, несколько мониторов
  • передача файлов и обмен буфером обмена
  • адресная книга, постоянный пароль, автозапуск доступа
  • портативность: все настройки лежат рядом с программой

Запуск из исходников:
    pip install customtkinter mss pillow pynput cryptography
    python remote_art.py
"""
import datetime
import hashlib
import hmac
import io
import json
import os
import queue
import re
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

import tkinter as tk
from tkinter import filedialog, messagebox

if sys.platform == "win32":
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass

try:
    import customtkinter as ctk
    import mss
    from PIL import Image, ImageDraw, ImageTk
    from pynput import keyboard as pkeyboard
    from pynput import mouse as pmouse
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
except ImportError as exc:
    _r = tk.Tk()
    _r.withdraw()
    messagebox.showerror(
        "remote-Art",
        f"Не хватает библиотеки: {exc.name}\n\nУстановите:\n"
        "pip install customtkinter mss pillow pynput cryptography",
    )
    sys.exit(1)

APP_NAME = "remote-Art"
APP_ID = "remote-Art"
VERSION = "1.0"
PROTO = 2
DEFAULT_PORT = 7777
T_JSON, T_FRAME, T_FILE = 1, 2, 3
MAX_MSG = 64 * 1024 * 1024
MAX_CLIP = 1_000_000
RESAMPLE = getattr(Image, "Resampling", Image).BILINEAR
PW_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

QUALITY = {
    "Быстро": dict(q=40, w=960, fps=15),
    "Баланс": dict(q=60, w=1280, fps=12),
    "Чётко": dict(q=80, w=1920, fps=10),
}

TK_TO_KEY = {
    "Return": "enter", "KP_Enter": "enter", "BackSpace": "backspace", "Tab": "tab",
    "ISO_Left_Tab": "tab", "Escape": "esc", "space": "space", "Delete": "delete",
    "Home": "home", "End": "end", "Prior": "page_up", "Next": "page_down",
    "Up": "up", "Down": "down", "Left": "left", "Right": "right",
    "Shift_L": "shift", "Shift_R": "shift", "Control_L": "ctrl", "Control_R": "ctrl",
    "Alt_L": "alt", "Alt_R": "alt", "Super_L": "cmd", "Super_R": "cmd",
    "Caps_Lock": "caps_lock", "Insert": "insert",
}
for _i in range(1, 13):
    TK_TO_KEY[f"F{_i}"] = f"f{_i}"
ALLOWED_SPECIAL = set(TK_TO_KEY.values())
BTN_MAP = {1: "l", 2: "r", 3: "m"} if sys.platform == "darwin" else {1: "l", 2: "m", 3: "r"}

# --- палитра
BG, SIDE, CARD, BORDER, FIELD = "#0d0f14", "#11141b", "#171a22", "#232838", "#0f1117"
ACCENT, ACCENT_H, CYAN = "#7c5cff", "#6a48f0", "#22d3ee"
TEXT, MUTED = "#e8eaf0", "#8b93a7"
GREEN, AMBER, RED, BLUE = "#22c55e", "#f59e0b", "#ef4444", "#3b82f6"
SEC, SEC_H = "#232838", "#2e3550"


# ----------------------------------------------------------------------------
# Файлы, настройки, сертификат
# ----------------------------------------------------------------------------
def app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def data_dir():
    """Портативный режим: папка с данными рядом с программой."""
    d = os.path.join(app_dir(), "remote-Art-data")
    try:
        os.makedirs(d, exist_ok=True)
        t = os.path.join(d, ".w")
        with open(t, "w"):
            pass
        os.remove(t)
        return d
    except OSError:
        d = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "remote-Art")
        os.makedirs(d, exist_ok=True)
        return d


def open_folder(path):
    try:
        if sys.platform == "win32":
            os.startfile(path)  # noqa
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception:
        pass


class Settings:
    DEFAULTS = {
        "port": DEFAULT_PORT, "quality": "Баланс", "auto_start": False,
        "persist_pw": False, "password": "", "allow_control": True,
        "allow_files": True, "confirm": True, "devices": [],
    }

    def __init__(self, path):
        self.path = path
        self.d = dict(self.DEFAULTS)
        try:
            with open(path, "r", encoding="utf-8") as f:
                self.d.update(json.load(f))
        except Exception:
            pass

    def __getitem__(self, k):
        return self.d[k]

    def __setitem__(self, k, v):
        self.d[k] = v

    def save(self):
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.d, f, ensure_ascii=False, indent=1)
            os.replace(tmp, self.path)
        except Exception:
            pass


def ensure_cert(folder):
    cert_p, key_p = os.path.join(folder, "cert.pem"), os.path.join(folder, "key.pem")
    if os.path.exists(cert_p) and os.path.exists(key_p):
        return cert_p, key_p
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "remote-Art")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    with open(key_p, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(cert_p, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert_p, key_p


def cert_fingerprint(cert_path):
    with open(cert_path, "r", encoding="ascii") as f:
        der = ssl.PEM_cert_to_DER_cert(f.read())
    return hashlib.sha256(der).hexdigest()


def fmt_fp(fp):
    s = fp[:16].upper()
    return " ".join(s[i:i + 4] for i in range(0, 16, 4))


# ----------------------------------------------------------------------------
# Протокол
# ----------------------------------------------------------------------------
class Channel:
    """Сообщение: 1 байт тип + 4 байта длина + данные."""

    def __init__(self, sock):
        self.sock = sock
        self.lock = threading.Lock()
        self.closed = False

    def _send(self, typ, payload):
        with self.lock:
            self.sock.sendall(struct.pack("!BI", typ, len(payload)) + payload)

    def send_json(self, obj):
        self._send(T_JSON, json.dumps(obj).encode("utf-8"))

    def send_frame(self, data):
        self._send(T_FRAME, data)

    def send_chunk(self, data):
        self._send(T_FILE, data)

    def _recv_exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Соединение закрыто")
            buf.extend(chunk)
        return bytes(buf)

    def recv(self):
        typ, ln = struct.unpack("!BI", self._recv_exact(5))
        if ln > MAX_MSG:
            raise ConnectionError("Слишком большое сообщение")
        return typ, self._recv_exact(ln)

    def close(self):
        self.closed = True
        for fn in (lambda: self.sock.shutdown(socket.SHUT_RDWR), self.sock.close):
            try:
                fn()
            except Exception:
                pass


def norm_pw(p):
    return re.sub(r"[\s\-]", "", p).upper()


def make_auth(password, nonce, fp):
    """Пароль привязан к отпечатку ключа компьютера — защита от подмены (MITM)."""
    return hmac.new(norm_pw(password).encode("utf-8"),
                    f"{nonce}:{fp}".encode("utf-8"), hashlib.sha256).hexdigest()


def new_password():
    return "".join(secrets.choice(PW_ALPHABET) for _ in range(8))


def fmt_pw(p):
    p = norm_pw(p)
    return "-".join(p[i:i + 4] for i in range(0, len(p), 4))


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"
    finally:
        s.close()


def parse_addr(addr):
    addr = addr.strip()
    host, port = addr, DEFAULT_PORT
    try:
        if ":" in addr:
            host, p = addr.rsplit(":", 1)
            port = int(p)
        host = host.strip()
        if not host or not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        raise RuntimeError("Адрес указан неверно. Пример: 192.168.1.5:7777")
    return host, port


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def safe_name(name):
    name = os.path.basename(str(name)).strip()
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    return name or "file"


def unique_path(folder, name):
    base, ext = os.path.splitext(name)
    p, n = os.path.join(folder, name), 1
    while os.path.exists(p):
        p = os.path.join(folder, f"{base} ({n}){ext}")
        n += 1
    return p


# ----------------------------------------------------------------------------
# Хост: даёт доступ к этому компьютеру
# ----------------------------------------------------------------------------
class HostServer:
    def __init__(self, app):
        self.app = app
        self.password = ""
        self.allow_control = True
        self.allow_files = True
        self.confirm = True
        self.running = False
        self.listener = None
        self.active = None
        self.lock = threading.Lock()
        self.fails = {}
        self.pressed = set()
        self.mouse = None
        self.kbd = None
        self.ctx = None
        self.fp = ""

    def event(self, kind, text):
        self.app.ui(self.app.host_event, kind, text)

    def start(self, port, cert, key):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        self.ctx = ctx
        self.fp = cert_fingerprint(cert)
        self.mouse = pmouse.Controller()
        self.kbd = pkeyboard.Controller()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(5)
        self.listener = s
        self.running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self):
        self.running = False
        try:
            self.listener.close()
        except Exception:
            pass
        self.kick()

    def kick(self):
        with self.lock:
            ch = self.active
        if ch:
            ch.close()

    def _accept_loop(self):
        while self.running:
            try:
                sock, addr = self.listener.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(sock, addr[0]), daemon=True).start()

    def _blocked(self, ip):
        n, t = self.fails.get(ip, (0, 0.0))
        if time.time() - t > 60:
            self.fails.pop(ip, None)
            return False
        return n >= 5

    def _fail(self, ip):
        n, _ = self.fails.get(ip, (0, 0.0))
        self.fails[ip] = (n + 1, time.time())

    def _handle(self, sock, ip):
        ch, stop, became_active = None, threading.Event(), False
        try:
            sock.settimeout(15)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            ssock = self.ctx.wrap_socket(sock, server_side=True)
            ch = Channel(ssock)
            if self._blocked(ip):
                ch.send_json({"t": "error", "msg": "Слишком много неверных попыток. Подождите минуту."})
                return
            nonce = secrets.token_hex(16)
            ch.send_json({"t": "hello", "app": APP_ID, "v": PROTO, "nonce": nonce})
            typ, data = ch.recv()
            msg = json.loads(data)
            if msg.get("t") != "auth":
                return
            if len(norm_pw(self.password)) < 6:
                ch.send_json({"t": "error", "msg": "На удалённом ПК не задан пароль"})
                return
            expected = make_auth(self.password, nonce, self.fp)
            if not hmac.compare_digest(expected, str(msg.get("h", ""))):
                self._fail(ip)
                time.sleep(1)
                ch.send_json({"t": "error", "msg": "Неверный пароль"})
                return
            name = str(msg.get("name", "?"))[:60]
            with self.lock:
                if self.active is not None:
                    ch.send_json({"t": "error", "msg": "Компьютер уже занят другим подключением"})
                    return
                self.active = ch
                became_active = True
            who = f"{name} ({ip})"
            if self.confirm:
                self.event("info", f"Запрос подключения: {name}")
                ch.send_json({"t": "wait"})
                if not self.app.ask_confirm(who):
                    ch.send_json({"t": "error", "msg": "Владелец отклонил подключение"})
                    return
            with mss.mss() as sct:
                mons = [dict(m) for m in sct.monitors]
            ssock.settimeout(None)
            ch.send_json({"t": "ok", "host": socket.gethostname(),
                          "control": self.allow_control, "files": self.allow_files,
                          "monitors": max(1, len(mons) - 1)})
            self.event("connected", name)
            self._serve(ch, stop, mons)
        except (OSError, ConnectionError, ValueError):
            pass
        finally:
            stop.set()
            self._release_keys()
            if ch:
                ch.close()
            else:
                try:
                    sock.close()
                except Exception:
                    pass
            if became_active:
                with self.lock:
                    if self.active is ch:
                        self.active = None
                if self.running:
                    self.event("idle", "Ожидание подключения")

    def _serve(self, ch, stop, mons):
        cfg = dict(QUALITY["Баланс"])
        cfg["mon"] = 1
        threading.Thread(target=self._sender, args=(ch, stop, cfg), daemon=True).start()
        fh, fpath = None, ""
        try:
            while True:
                typ, data = ch.recv()
                if typ == T_FILE:
                    if fh and self.allow_files:
                        fh.write(data)
                    continue
                if typ != T_JSON:
                    continue
                m = json.loads(data)
                t = m.get("t")
                if t == "settings":
                    cfg["q"] = clamp(int(m.get("q", 60)), 10, 95)
                    cfg["w"] = clamp(int(m.get("w", 1280)), 320, 3840)
                    cfg["fps"] = clamp(int(m.get("fps", 12)), 1, 30)
                elif t == "monitor":
                    cfg["mon"] = clamp(int(m.get("i", 1)), 1, max(1, len(mons) - 1))
                elif t == "bye":
                    break
                elif t in ("mm", "mb", "mw", "kd", "ku"):
                    if self.allow_control:
                        try:
                            self._input(m, mons[cfg["mon"]] if cfg["mon"] < len(mons) else mons[0])
                        except Exception:
                            pass
                elif t == "file_start" and self.allow_files:
                    if fh:
                        fh.close()
                    fpath = unique_path(self.app.recv_dir, safe_name(m.get("name", "file")))
                    fh = open(fpath, "wb")
                elif t == "file_end" and fh:
                    fh.close()
                    fh = None
                    nm = os.path.basename(fpath)
                    ch.send_json({"t": "file_ok", "name": nm})
                    self.app.ui(self.app.notify, f"Получен файл: {nm}")
                elif t == "clip" and self.allow_files:
                    self.app.call_ui(self.app.set_clipboard, str(m.get("text", ""))[:MAX_CLIP], timeout=3)
                elif t == "clip_get" and self.allow_files:
                    text = self.app.call_ui(self.app.get_clipboard, timeout=3) or ""
                    ch.send_json({"t": "clip", "text": text[:MAX_CLIP]})
        finally:
            if fh:
                try:
                    fh.close()
                except Exception:
                    pass

    def _sender(self, ch, stop, cfg):
        try:
            with mss.mss() as sct:
                last, last_t = None, 0.0
                while not stop.is_set():
                    t0 = time.time()
                    idx = cfg["mon"] if cfg["mon"] < len(sct.monitors) else 1
                    shot = sct.grab(sct.monitors[idx])
                    img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
                    w = cfg["w"]
                    if img.width > w:
                        img = img.resize((w, max(1, img.height * w // img.width)), RESAMPLE)
                    buf = io.BytesIO()
                    img.save(buf, "JPEG", quality=cfg["q"])
                    data = buf.getvalue()
                    dig = hashlib.md5(data).digest()
                    if dig != last or t0 - last_t > 1.0:
                        ch.send_frame(data)
                        last, last_t = dig, t0
                    time.sleep(max(0.005, 1.0 / cfg["fps"] - (time.time() - t0)))
        except Exception:
            pass
        finally:
            ch.close()

    def _input(self, m, mon):
        t = m["t"]
        if t in ("mm", "mb"):
            x = mon["left"] + int(clamp(float(m["x"]), 0, 1) * (mon["width"] - 1))
            y = mon["top"] + int(clamp(float(m["y"]), 0, 1) * (mon["height"] - 1))
            self.mouse.position = (x, y)
        if t == "mb":
            btn = {"l": pmouse.Button.left, "m": pmouse.Button.middle,
                   "r": pmouse.Button.right}.get(m.get("b"))
            if btn:
                (self.mouse.press if m.get("d") else self.mouse.release)(btn)
        elif t == "mw":
            self.mouse.scroll(int(m.get("dx", 0)), int(m.get("dy", 0)))
        elif t in ("kd", "ku"):
            key = self._resolve_key(m)
            if key is None:
                return
            if t == "kd":
                self.kbd.press(key)
                self.pressed.add(key)
            else:
                self.kbd.release(key)
                self.pressed.discard(key)

    def _resolve_key(self, m):
        if "s" in m:
            name = m["s"]
            return getattr(pkeyboard.Key, name, None) if name in ALLOWED_SPECIAL else None
        c = m.get("c")
        if isinstance(c, str) and len(c) == 1:
            if sys.platform == "win32" and c.isascii() and c.isalnum():
                held = {pkeyboard.Key.ctrl, pkeyboard.Key.alt, pkeyboard.Key.cmd}
                if self.pressed & held:
                    return pkeyboard.KeyCode.from_vk(ord(c.upper()))
            return c
        return None

    def _release_keys(self):
        for k in list(self.pressed):
            try:
                self.kbd.release(k)
            except Exception:
                pass
        self.pressed.clear()


# ----------------------------------------------------------------------------
# UI-хелперы
# ----------------------------------------------------------------------------
def F(size=13, weight="normal", mono=False):
    return ctk.CTkFont(family="Consolas" if mono else "Segoe UI", size=size, weight=weight)


def card(parent, radius=14):
    return ctk.CTkFrame(parent, fg_color=CARD, corner_radius=radius,
                        border_width=1, border_color=BORDER)


def button(parent, text, cmd, kind="accent", width=None, height=40, size=13):
    fg, hov = {"accent": (ACCENT, ACCENT_H), "sec": (SEC, SEC_H), "danger": (RED, "#c93a3f")}[kind]
    kw = {"width": width} if width else {}
    return ctk.CTkButton(parent, text=text, command=cmd, fg_color=fg, hover_color=hov,
                         text_color="white", height=height, corner_radius=10,
                         font=F(size, "bold"), **kw)


def field(parent, var=None, placeholder="", show="", mono=True):
    return ctk.CTkEntry(parent, textvariable=var, placeholder_text=placeholder, show=show,
                        height=44, corner_radius=10, fg_color=FIELD, border_color=BORDER,
                        border_width=1, text_color=TEXT, font=F(15, mono=mono))


def label(parent, text, size=13, weight="normal", color=TEXT, mono=False, **kw):
    return ctk.CTkLabel(parent, text=text, font=F(size, weight, mono), text_color=color, **kw)


def make_icon_image(size=256):
    s = size
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((0, 0, s - 1, s - 1), radius=int(s * 0.22), fill=(124, 92, 255, 255))
    w = max(2, int(s * 0.045))
    d.rounded_rectangle((int(s * .18), int(s * .24), int(s * .82), int(s * .64)),
                        radius=int(s * .05), outline=(255, 255, 255, 255), width=w)
    d.rectangle((int(s * .46), int(s * .64), int(s * .54), int(s * .74)), fill=(255, 255, 255, 255))
    d.rounded_rectangle((int(s * .32), int(s * .73), int(s * .68), int(s * .79)),
                        radius=int(s * .03), fill=(255, 255, 255, 255))
    pts = [(.50, .33), (.50, .56), (.56, .51), (.61, .62), (.66, .60), (.61, .49), (.69, .49)]
    d.polygon([(int(x * s), int(y * s)) for x, y in pts], fill=(34, 211, 238, 255))
    return img


# ----------------------------------------------------------------------------
# Окно удалённого экрана
# ----------------------------------------------------------------------------
class Viewer:
    def __init__(self, app, ch, info, addr):
        self.app, self.ch = app, ch
        self.closed = False
        self.can_control = bool(info.get("control"))
        self.can_files = bool(info.get("files"))
        self.lock = threading.Lock()
        self.latest = self.last_img = self.photo = self.item = None
        self.drawn_key = None
        self.geom = (0, 0, 1, 1)
        self.down = {}
        self.last_move = 0.0
        self.fullscreen = False
        self.sending = False

        self.win = ctk.CTkToplevel(app.root)
        self.win.title(f"{APP_NAME} — {info.get('host', addr)}")
        self.win.geometry("1180x760")
        self.win.configure(fg_color=BG)
        self.win.protocol("WM_DELETE_WINDOW", self.close)

        bar = self.bar = ctk.CTkFrame(self.win, fg_color=SIDE, corner_radius=0, height=54)
        bar.pack(side="top", fill="x")
        label(bar, f"🖥  {info.get('host', addr)}", 14, "bold").pack(side="left", padx=(16, 14), pady=10)

        self.q_seg = ctk.CTkSegmentedButton(
            bar, values=list(QUALITY), command=lambda v: self._send_settings(),
            fg_color=SEC, selected_color=ACCENT, selected_hover_color=ACCENT_H,
            unselected_color=SEC, unselected_hover_color=SEC_H, font=F(12, "bold"), height=32)
        self.q_seg.set(app.settings["quality"] if app.settings["quality"] in QUALITY else "Баланс")
        self.q_seg.pack(side="left", padx=4)

        n = int(info.get("monitors", 1))
        if n > 1:
            om = ctk.CTkOptionMenu(bar, values=[f"Экран {i}" for i in range(1, n + 1)],
                                   command=self._on_monitor, width=100, height=32,
                                   fg_color=SEC, button_color=SEC_H, button_hover_color=ACCENT,
                                   font=F(12, "bold"))
            om.pack(side="left", padx=6)

        self.ctl_var = tk.BooleanVar(value=self.can_control)
        sw = ctk.CTkSwitch(bar, text="Управление", variable=self.ctl_var, progress_color=ACCENT,
                           font=F(12, "bold"), command=lambda: self.canvas.focus_set(),
                           state="normal" if self.can_control else "disabled")
        sw.pack(side="left", padx=10)

        if self.can_files:
            for txt, cmd in (("📋 →", self.clip_send), ("📋 ←", self.clip_get), ("📁 Файл", self.send_file)):
                button(bar, txt, cmd, "sec", height=32, size=12, width=70 if "📋" in txt else 84
                       ).pack(side="left", padx=3)

        button(bar, "✕  Отключить", self.close, "danger", height=32, size=12, width=110).pack(side="right", padx=(6, 14))
        button(bar, "⛶", self.toggle_fullscreen, "sec", height=32, size=14, width=40).pack(side="right", padx=3)
        self.info_lbl = label(bar, "", 12, color=CYAN)
        self.info_lbl.pack(side="right", padx=10)

        self.canvas = tk.Canvas(self.win, bg="#0b0c10", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        c = self.canvas
        c.bind("<Motion>", self._on_move)
        c.bind("<ButtonPress>", lambda e: self._on_button(e, True))
        c.bind("<ButtonRelease>", lambda e: self._on_button(e, False))
        c.bind("<MouseWheel>", self._on_wheel)
        c.bind("<Button-4>", lambda e: self._wheel(1))
        c.bind("<Button-5>", lambda e: self._wheel(-1))
        c.bind("<KeyPress>", lambda e: self._on_key(e, True))
        c.bind("<KeyRelease>", lambda e: self._on_key(e, False))
        c.bind("<FocusOut>", lambda e: self._release_all())
        c.bind("<Enter>", lambda e: c.focus_set())
        self.win.after(200, c.focus_set)

        self._send_settings()
        threading.Thread(target=self._recv_loop, daemon=True).start()
        self._tick()

    # --- приём
    def _recv_loop(self):
        try:
            while True:
                typ, data = self.ch.recv()
                if typ == T_FRAME:
                    img = Image.open(io.BytesIO(data))
                    img.load()
                    with self.lock:
                        self.latest = img
                elif typ == T_JSON:
                    m = json.loads(data)
                    if m.get("t") == "clip":
                        self.app.ui(self._got_clip, str(m.get("text", "")))
                    elif m.get("t") == "file_ok":
                        self.app.ui(self._set_info, f"✓ Файл доставлен: {m.get('name', '')}")
        except Exception:
            pass
        finally:
            self.app.ui(self._on_lost)

    def _on_lost(self):
        if not self.closed:
            self.close()
            messagebox.showinfo(APP_NAME, "Соединение закрыто.", parent=self.app.root)

    def _tick(self):
        if self.closed:
            return
        with self.lock:
            img, self.latest = self.latest, None
        if img is not None:
            self.last_img = img
        cw, chh = max(self.canvas.winfo_width(), 2), max(self.canvas.winfo_height(), 2)
        if self.last_img is not None and (img is not None or self.drawn_key != (cw, chh)):
            iw, ih = self.last_img.size
            s = min(cw / iw, chh / ih)
            dw, dh = max(1, int(iw * s)), max(1, int(ih * s))
            shown = self.last_img if (dw, dh) == (iw, ih) else self.last_img.resize((dw, dh), RESAMPLE)
            self.photo = ImageTk.PhotoImage(shown)
            ox, oy = (cw - dw) // 2, (chh - dh) // 2
            if self.item is None:
                self.item = self.canvas.create_image(ox, oy, anchor="nw", image=self.photo)
            else:
                self.canvas.coords(self.item, ox, oy)
                self.canvas.itemconfigure(self.item, image=self.photo)
            self.geom = (ox, oy, dw, dh)
            self.drawn_key = (cw, chh)
        self.win.after(25, self._tick)

    # --- отправка
    def _send(self, obj):
        if self.closed:
            return
        try:
            self.ch.send_json(obj)
        except Exception:
            self.close()

    def _send_settings(self):
        self._send({"t": "settings", **QUALITY[self.q_seg.get()]})

    def _on_monitor(self, v):
        self._send({"t": "monitor", "i": int(v.split()[-1])})
        self.canvas.focus_set()

    def _set_info(self, text):
        if self.closed:
            return
        self.info_lbl.configure(text=text)
        self.win.after(4000, lambda: (not self.closed) and self.info_lbl.configure(text=""))

    # --- буфер и файлы
    def clip_send(self):
        try:
            text = self.win.clipboard_get()
        except tk.TclError:
            text = ""
        if not text:
            self._set_info("Буфер пуст")
            return
        self._send({"t": "clip", "text": text[:MAX_CLIP]})
        self._set_info("✓ Буфер отправлен")

    def clip_get(self):
        self._send({"t": "clip_get"})

    def _got_clip(self, text):
        if self.closed:
            return
        self.win.clipboard_clear()
        self.win.clipboard_append(text)
        self._set_info("✓ Буфер получен")

    def send_file(self):
        if self.sending:
            self._set_info("Подождите, идёт отправка")
            return
        path = filedialog.askopenfilename(parent=self.win, title="Выберите файл для отправки")
        if path:
            self.sending = True
            threading.Thread(target=self._send_file_worker, args=(path,), daemon=True).start()

    def _send_file_worker(self, path):
        try:
            size, name = os.path.getsize(path), os.path.basename(path)
            self.ch.send_json({"t": "file_start", "name": name, "size": size})
            sent, last = 0, 0.0
            with open(path, "rb") as f:
                while not self.closed:
                    chunk = f.read(256 * 1024)
                    if not chunk:
                        break
                    self.ch.send_chunk(chunk)
                    sent += len(chunk)
                    if time.time() - last > 0.2:
                        self.app.ui(self._set_info, f"Отправка: {sent * 100 // max(size, 1)}%")
                        last = time.time()
            self.ch.send_json({"t": "file_end"})
        except Exception as e:
            self.app.ui(self._set_info, f"Ошибка отправки: {e}")
        finally:
            self.sending = False

    # --- мышь
    def _active(self):
        return self.can_control and self.ctl_var.get() and not self.closed

    def _norm(self, e):
        ox, oy, dw, dh = self.geom
        if dw <= 0 or dh <= 0:
            return None
        return clamp((e.x - ox) / dw, 0, 1), clamp((e.y - oy) / dh, 0, 1)

    def _on_move(self, e):
        if not self._active():
            return
        now = time.time()
        if now - self.last_move < 0.016:
            return
        self.last_move = now
        p = self._norm(e)
        if p:
            self._send({"t": "mm", "x": p[0], "y": p[1]})

    def _on_button(self, e, down):
        self.canvas.focus_set()
        if not self._active():
            return
        b, p = BTN_MAP.get(e.num), self._norm(e)
        if b and p:
            self._send({"t": "mb", "b": b, "d": down, "x": p[0], "y": p[1]})

    def _on_wheel(self, e):
        d = e.delta / 120 if sys.platform == "win32" else e.delta
        self._wheel(int(d) or (1 if e.delta > 0 else -1))

    def _wheel(self, dy):
        if self._active():
            self._send({"t": "mw", "dx": 0, "dy": dy})

    # --- клавиатура
    def _on_key(self, e, down):
        if down and e.keysym == "F11":
            self.toggle_fullscreen()
            return "break"
        if not self._active():
            return "break"
        if down:
            name = TK_TO_KEY.get(e.keysym)
            if name:
                tok = {"s": name}
            elif e.char and len(e.char) == 1 and ord(e.char) >= 32 and ord(e.char) != 127:
                tok = {"c": e.char}
            elif len(e.keysym) == 1:
                tok = {"c": e.keysym.lower()}
            else:
                return "break"
            self.down[e.keycode] = tok
        else:
            tok = self.down.pop(e.keycode, None)
            if tok is None:
                return "break"
        self._send({"t": "kd" if down else "ku", **tok})
        return "break"

    def _release_all(self):
        for tok in list(self.down.values()):
            self._send({"t": "ku", **tok})
        self.down.clear()

    # --- окно
    def toggle_fullscreen(self):
        self.fullscreen = not self.fullscreen
        self.win.attributes("-fullscreen", self.fullscreen)
        if self.fullscreen:
            self.bar.pack_forget()
        else:
            self.bar.pack(side="top", fill="x", before=self.canvas)
        self.canvas.focus_set()

    def close(self):
        if self.closed:
            return
        self._release_all()
        self.closed = True
        try:
            self.ch.send_json({"t": "bye"})
        except Exception:
            pass
        self.ch.close()
        try:
            self.win.destroy()
        except Exception:
            pass
        self.app.on_viewer_closed()


# ----------------------------------------------------------------------------
# Главное окно
# ----------------------------------------------------------------------------
class App:
    def __init__(self):
        ctk.set_appearance_mode("dark")
        self.root = ctk.CTk()
        self.root.title(f"{APP_NAME}")
        self.root.geometry("1040x720")
        self.root.minsize(980, 660)
        self.root.configure(fg_color=BG)

        self.data = data_dir()
        self.recv_dir = os.path.join(self.data, "received")
        os.makedirs(self.recv_dir, exist_ok=True)
        self.settings = Settings(os.path.join(self.data, "settings.json"))
        self.cert, self.key = ensure_cert(self.data)
        self.fp = cert_fingerprint(self.cert)

        self.q = queue.Queue()
        self.viewer = None
        self.host = HostServer(self)
        self.password = (self.settings["password"] if self.settings["persist_pw"]
                         and len(norm_pw(self.settings["password"])) >= 6 else new_password())
        self.host.allow_control = self.settings["allow_control"]
        self.host.allow_files = self.settings["allow_files"]
        self.host.confirm = self.settings["confirm"]
        self.host.password = self.password

        self._set_icon()
        self._build()
        self.show_page("connect")
        self.root.protocol("WM_DELETE_WINDOW", self.on_exit)
        self.root.after(50, self._poll)
        if self.settings["auto_start"]:
            self.root.after(600, lambda: self.toggle_host(auto=True))

    # --- служебное
    def ui(self, fn, *args):
        self.q.put((fn, args))

    def call_ui(self, fn, *args, timeout=5):
        ev, box = threading.Event(), [None]

        def run():
            try:
                box[0] = fn(*args)
            finally:
                ev.set()

        self.ui(run)
        ev.wait(timeout)
        return box[0]

    def _poll(self):
        try:
            while True:
                fn, args = self.q.get_nowait()
                try:
                    fn(*args)
                except Exception:
                    pass
        except queue.Empty:
            pass
        self.root.after(50, self._poll)

    def _set_icon(self):
        try:
            path = os.path.join(tempfile.gettempdir(), "remote-art-icon.ico")
            make_icon_image(256).save(path, format="ICO",
                                      sizes=[(16, 16), (32, 32), (48, 48), (256, 256)])
            if sys.platform == "win32":
                self.root.iconbitmap(path)
            else:
                self.root.iconphoto(True, ImageTk.PhotoImage(make_icon_image(64)))
        except Exception:
            pass

    def get_clipboard(self):
        try:
            return self.root.clipboard_get()
        except tk.TclError:
            return ""

    def set_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def copy(self, text, note="Скопировано"):
        self.set_clipboard(text)
        self.notify(note)

    def notify(self, text):
        self.note_lbl.configure(text=text)
        self.root.after(5000, lambda: self.note_lbl.configure(text=""))

    # --- каркас
    def _build(self):
        side = ctk.CTkFrame(self.root, width=226, fg_color=SIDE, corner_radius=0)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)

        logo = ctk.CTkFrame(side, fg_color="transparent")
        logo.pack(anchor="w", padx=22, pady=(26, 22))
        label(logo, "remote", 24, "bold").pack(side="left")
        label(logo, "-Art", 24, "bold", ACCENT).pack(side="left")

        self.nav = {}
        for key, text in (("connect", "🖥   Подключиться"), ("access", "🛡   Мой доступ"),
                          ("settings", "⚙   Настройки")):
            b = ctk.CTkButton(side, text=text, anchor="w", height=44, corner_radius=10,
                              fg_color="transparent", hover_color=SEC, text_color=MUTED,
                              font=F(14, "bold"), command=lambda k=key: self.show_page(k))
            b.pack(fill="x", padx=14, pady=3)
            self.nav[key] = b

        foot = card(side, 12)
        foot.pack(side="bottom", fill="x", padx=14, pady=16)
        row = ctk.CTkFrame(foot, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=(10, 2))
        self.side_dot = label(row, "●", 14, color="#4b5263")
        self.side_dot.pack(side="left")
        self.side_status = label(row, "Доступ выключен", 12, "bold", wraplength=150, justify="left")
        self.side_status.pack(side="left", padx=6)
        label(foot, f"v{VERSION} • портативная", 11, color=MUTED).pack(anchor="w", padx=14, pady=(0, 10))

        self.content = ctk.CTkFrame(self.root, fg_color=BG, corner_radius=0)
        self.content.pack(side="left", fill="both", expand=True)

        self.pages = {
            "connect": self._build_connect(),
            "access": self._build_access(),
            "settings": self._build_settings(),
        }

    def show_page(self, key):
        for k, p in self.pages.items():
            p.pack_forget()
            self.nav[k].configure(fg_color="transparent", text_color=MUTED)
        self.pages[key].pack(fill="both", expand=True, padx=28, pady=(24, 16))
        self.nav[key].configure(fg_color=SEC, text_color=TEXT)

    def _title(self, parent, title, sub):
        label(parent, title, 26, "bold").pack(anchor="w")
        label(parent, sub, 13, color=MUTED).pack(anchor="w", pady=(2, 14))

    # --- страница: подключение
    def _build_connect(self):
        p = ctk.CTkFrame(self.content, fg_color="transparent")
        self._title(p, "Удалённое подключение", "Введите адрес и пароль компьютера, к которому нужен доступ")

        c = card(p)
        c.pack(fill="x")
        inner = ctk.CTkFrame(c, fg_color="transparent")
        inner.pack(fill="x", padx=22, pady=20)
        inner.columnconfigure(0, weight=3)
        inner.columnconfigure(1, weight=2)
        label(inner, "Адрес компьютера", 12, color=MUTED).grid(row=0, column=0, sticky="w")
        label(inner, "Пароль", 12, color=MUTED).grid(row=0, column=1, sticky="w", padx=(12, 0))
        self.addr_var, self.cpw_var = tk.StringVar(), tk.StringVar()
        field(inner, self.addr_var, "192.168.1.5:7777").grid(row=1, column=0, sticky="ew", pady=(4, 0))
        self.cpw_entry = field(inner, self.cpw_var, "XXXX-XXXX", show="•")
        self.cpw_entry.grid(row=1, column=1, sticky="ew", padx=(12, 0), pady=(4, 0))
        self.cpw_entry.bind("<Return>", lambda e: self.connect())
        self.conn_btn = button(inner, "Подключиться", self.connect, height=46, size=14)
        self.conn_btn.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(16, 0))
        self.conn_status = label(inner, "", 13, color=MUTED, wraplength=640, justify="left")
        self.conn_status.grid(row=3, column=0, columnspan=2, sticky="w", pady=(10, 0))

        label(p, "Мои устройства", 16, "bold").pack(anchor="w", pady=(22, 6))
        self.dev_frame = ctk.CTkScrollableFrame(p, fg_color="transparent", corner_radius=0)
        self.dev_frame.pack(fill="both", expand=True)
        self.refresh_devices()
        return p

    def refresh_devices(self):
        for w in self.dev_frame.winfo_children():
            w.destroy()
        devs = self.settings["devices"]
        if not devs:
            label(self.dev_frame, "Пока пусто. Устройства появятся здесь после первого подключения.",
                  13, color=MUTED).pack(anchor="w", pady=8)
            return
        for d in devs:
            row = card(self.dev_frame, 12)
            row.pack(fill="x", pady=4)
            label(row, "🖥", 22).pack(side="left", padx=(16, 10), pady=12)
            col = ctk.CTkFrame(row, fg_color="transparent")
            col.pack(side="left", fill="x", expand=True)
            label(col, d.get("name", "?"), 14, "bold").pack(anchor="w")
            label(col, d["addr"], 12, color=MUTED, mono=True).pack(anchor="w")
            button(row, "✕", lambda d=d: self.remove_device(d), "sec", width=38, height=34
                   ).pack(side="right", padx=(4, 14))
            button(row, "Подключиться", lambda d=d: self.pick_device(d), "sec", width=130, height=34
                   ).pack(side="right", padx=4)

    def pick_device(self, d):
        self.addr_var.set(d["addr"])
        self.cpw_var.set("")
        self.cpw_entry.focus_set()

    def remove_device(self, d):
        self.settings["devices"] = [x for x in self.settings["devices"] if x["addr"] != d["addr"]]
        self.settings.save()
        self.refresh_devices()

    # --- страница: мой доступ
    def _build_access(self):
        p = ctk.CTkScrollableFrame(self.content, fg_color="transparent", corner_radius=0)
        self._title(p, "Мой доступ", "Сообщите адрес и пароль тому, кто будет подключаться")

        c = card(p)
        c.pack(fill="x")
        inner = ctk.CTkFrame(c, fg_color="transparent")
        inner.pack(fill="x", padx=22, pady=18)
        label(inner, "Ваш адрес", 12, color=MUTED).pack(anchor="w")
        r = ctk.CTkFrame(inner, fg_color="transparent")
        r.pack(fill="x", pady=(0, 12))
        self.my_addr = label(r, self._my_addr(), 26, "bold", CYAN, mono=True)
        self.my_addr.pack(side="left")
        button(r, "Копировать", lambda: self.copy(self.my_addr.cget("text"), "Адрес скопирован"),
               "sec", width=110, height=34).pack(side="right")

        label(inner, "Пароль", 12, color=MUTED).pack(anchor="w")
        r = ctk.CTkFrame(inner, fg_color="transparent")
        r.pack(fill="x")
        self.pw_lbl = label(r, fmt_pw(self.password), 26, "bold", TEXT, mono=True)
        self.pw_lbl.pack(side="left")
        button(r, "Свой…", self.custom_password, "sec", width=70, height=34).pack(side="right")
        button(r, "Новый", lambda: self.set_password(new_password()), "sec", width=70, height=34
               ).pack(side="right", padx=6)
        button(r, "Копировать", lambda: self.copy(self.pw_lbl.cget("text"), "Пароль скопирован"),
               "sec", width=110, height=34).pack(side="right")
        label(inner, f"Отпечаток ключа: {fmt_fp(self.fp)}", 11, color=MUTED, mono=True
              ).pack(anchor="w", pady=(14, 0))

        c2 = card(p)
        c2.pack(fill="x", pady=14)
        inner = ctk.CTkFrame(c2, fg_color="transparent")
        inner.pack(fill="x", padx=22, pady=16)
        self.sw_ctrl = tk.BooleanVar(value=self.settings["allow_control"])
        self.sw_files = tk.BooleanVar(value=self.settings["allow_files"])
        self.sw_conf = tk.BooleanVar(value=self.settings["confirm"])
        for text, var, attr in (("Разрешить управление мышью и клавиатурой", self.sw_ctrl, "allow_control"),
                                ("Разрешить передачу файлов и буфера обмена", self.sw_files, "allow_files"),
                                ("Спрашивать разрешение при каждом подключении", self.sw_conf, "confirm")):
            ctk.CTkSwitch(inner, text=text, variable=var, progress_color=ACCENT, font=F(13),
                          command=lambda v=var, a=attr: self._toggle(a, v)).pack(anchor="w", pady=5)
        r = ctk.CTkFrame(inner, fg_color="transparent")
        r.pack(anchor="w", pady=(8, 0))
        label(r, "Порт", 13, color=MUTED).pack(side="left")
        self.port_var = tk.StringVar(value=str(self.settings["port"]))
        self.port_entry = ctk.CTkEntry(r, textvariable=self.port_var, width=90, height=34,
                                       fg_color=FIELD, border_color=BORDER, font=F(13, mono=True))
        self.port_entry.pack(side="left", padx=10)

        self.host_btn = button(p, "▶   Включить доступ", self.toggle_host, height=50, size=15)
        self.host_btn.pack(fill="x")
        self.kick_btn = button(p, "Отключить клиента", self.host.kick, "danger", height=40)
        self.kick_btn.configure(state="disabled")
        self.kick_btn.pack(fill="x", pady=(8, 0))
        self.pill = label(p, "●  Доступ выключен", 13, "bold", MUTED)
        self.pill.pack(anchor="w", pady=(14, 0))
        self.note_lbl = label(p, "", 12, color=CYAN)
        self.note_lbl.pack(anchor="w", pady=(4, 0))
        return p

    def _my_addr(self):
        return f"{local_ip()}:{self.settings['port']}"

    def _toggle(self, attr, var):
        setattr(self.host, attr, var.get())
        self.settings[attr] = var.get()
        self.settings.save()

    def set_password(self, pw):
        self.password = pw
        self.host.password = pw
        self.pw_lbl.configure(text=fmt_pw(pw))
        if self.settings["persist_pw"]:
            self.settings["password"] = pw
            self.settings.save()

    def custom_password(self):
        dlg = ctk.CTkInputDialog(text="Введите свой пароль (минимум 6 символов):", title="Свой пароль")
        val = dlg.get_input()
        if val is None:
            return
        if len(norm_pw(val)) < 6:
            messagebox.showwarning(APP_NAME, "Пароль должен быть не короче 6 символов.")
            return
        self.set_password(norm_pw(val))

    def toggle_host(self, auto=False):
        if self.host.running:
            self.host.stop()
            self.host_btn.configure(text="▶   Включить доступ")
            self.port_entry.configure(state="normal")
            self.host_event("off", "Доступ выключен")
            return
        try:
            port = int(self.port_var.get())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showwarning(APP_NAME, "Порт должен быть числом от 1 до 65535.")
            return
        self.host.password = self.password
        try:
            self.host.start(port, self.cert, self.key)
        except Exception as e:
            if not auto:
                messagebox.showerror(APP_NAME, f"Не удалось запустить доступ:\n{e}")
            return
        self.settings["port"] = port
        self.settings.save()
        self.my_addr.configure(text=self._my_addr())
        self.host_btn.configure(text="■   Выключить доступ")
        self.port_entry.configure(state="disabled")
        self.host_event("idle", "Ожидание подключения")

    def host_event(self, kind, text):
        color = {"off": "#4b5263", "idle": GREEN, "info": AMBER, "connected": BLUE}.get(kind, MUTED)
        if kind == "connected":
            text = f"Подключён: {text}"
        self.side_dot.configure(text_color=color)
        self.side_status.configure(text=text)
        self.pill.configure(text=f"●  {text}", text_color=color)
        self.kick_btn.configure(state="normal" if kind == "connected" else "disabled")

    def ask_confirm(self, who):
        ev, res = threading.Event(), [False]

        def show():
            self.root.deiconify()
            self.root.lift()
            res[0] = messagebox.askyesno(
                "Запрос подключения",
                f"{who}\nхочет подключиться к вашему компьютеру.\n\nРазрешить?", parent=self.root)
            ev.set()

        self.ui(show)
        ev.wait(45)
        return res[0]

    # --- страница: настройки
    def _build_settings(self):
        p = ctk.CTkFrame(self.content, fg_color="transparent")
        self._title(p, "Настройки", "Программа портативная: всё хранится рядом с ней")

        c = card(p)
        c.pack(fill="x")
        inner = ctk.CTkFrame(c, fg_color="transparent")
        inner.pack(fill="x", padx=22, pady=18)
        label(inner, "Качество изображения по умолчанию", 12, color=MUTED).pack(anchor="w")
        seg = ctk.CTkSegmentedButton(inner, values=list(QUALITY), command=self._set_quality,
                                     fg_color=SEC, selected_color=ACCENT, selected_hover_color=ACCENT_H,
                                     unselected_color=SEC, unselected_hover_color=SEC_H,
                                     font=F(12, "bold"), height=34)
        seg.set(self.settings["quality"] if self.settings["quality"] in QUALITY else "Баланс")
        seg.pack(anchor="w", pady=(4, 14))

        self.sw_auto = tk.BooleanVar(value=self.settings["auto_start"])
        self.sw_persist = tk.BooleanVar(value=self.settings["persist_pw"])
        ctk.CTkSwitch(inner, text="Включать доступ при запуске программы", variable=self.sw_auto,
                      progress_color=ACCENT, font=F(13),
                      command=lambda: self._save_flag("auto_start", self.sw_auto)).pack(anchor="w", pady=5)
        ctk.CTkSwitch(inner, text="Запомнить пароль (для постоянного доступа без вас)",
                      variable=self.sw_persist, progress_color=ACCENT, font=F(13),
                      command=self._persist_changed).pack(anchor="w", pady=5)

        r = ctk.CTkFrame(inner, fg_color="transparent")
        r.pack(anchor="w", pady=(14, 0))
        button(r, "📁  Принятые файлы", lambda: open_folder(self.recv_dir), "sec", height=36, width=170
               ).pack(side="left")
        button(r, "⚙  Папка с данными", lambda: open_folder(self.data), "sec", height=36, width=170
               ).pack(side="left", padx=8)

        c2 = card(p)
        c2.pack(fill="x", pady=14)
        label(c2, "О программе", 15, "bold").pack(anchor="w", padx=22, pady=(16, 4))
        label(c2, (f"remote-Art {VERSION}\n"
                   "• Всё соединение шифруется (TLS 1.2+).\n"
                   "• Пароль привязан к ключу компьютера — подмена по пути не пройдёт.\n"
                   "• Отпечаток ключа сохраняется для каждого устройства: если он изменится, "
                   "программа предупредит.\n"
                   "• 5 неверных паролей — блокировка адреса на минуту."),
              12, color=MUTED, justify="left", wraplength=640).pack(anchor="w", padx=22, pady=(0, 16))
        return p

    def _set_quality(self, v):
        self.settings["quality"] = v
        self.settings.save()

    def _save_flag(self, key, var):
        self.settings[key] = var.get()
        self.settings.save()

    def _persist_changed(self):
        self.settings["persist_pw"] = self.sw_persist.get()
        self.settings["password"] = self.password if self.sw_persist.get() else ""
        self.settings.save()

    # --- подключение
    def connect(self):
        if self.viewer:
            return
        addr = self.addr_var.get().strip()
        if not addr:
            self._conn_msg("Введите адрес компьютера", RED)
            return
        self.conn_btn.configure(state="disabled")
        self._conn_msg("Подключение…", MUTED)
        threading.Thread(target=self._connect_worker, args=(addr, self.cpw_var.get()),
                         daemon=True).start()

    def _conn_msg(self, text, color):
        self.conn_status.configure(text=text, text_color=color)

    def _connect_worker(self, addr, password):
        ch = None
        try:
            host, port = parse_addr(addr)
            key = f"{host}:{port}"
            raw = socket.create_connection((host, port), timeout=8)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ssock = ctx.wrap_socket(raw)
            except (ssl.SSLError, OSError):
                raw.close()
                raise RuntimeError("Не удалось установить защищённое соединение. "
                                   "Проверьте адрес и порт: на том ПК должен работать remote-Art.")
            fp = hashlib.sha256(ssock.getpeercert(binary_form=True)).hexdigest()
            ch = Channel(ssock)
            known = next((d for d in self.settings["devices"] if d["addr"] == key), None)
            if known and known.get("fp") and known["fp"] != fp:
                raise RuntimeError("Ключ компьютера изменился — возможна подмена. Если вы "
                                   "переустанавливали программу на том ПК, удалите его из списка "
                                   "«Мои устройства» и подключитесь заново.")
            typ, data = ch.recv()
            hello = json.loads(data)
            if hello.get("app") != APP_ID:
                raise RuntimeError("Это не remote-Art")
            ch.send_json({"t": "auth", "h": make_auth(password, hello["nonce"], fp),
                          "name": socket.gethostname()})
            ssock.settimeout(60)
            while True:
                typ, data = ch.recv()
                m = json.loads(data)
                if m.get("t") == "wait":
                    self.ui(self._conn_msg, "Ждём подтверждения от владельца…", AMBER)
                elif m.get("t") == "error":
                    raise RuntimeError(m.get("msg", "Ошибка"))
                elif m.get("t") == "ok":
                    break
            ssock.settimeout(None)
            self.ui(self._open_viewer, ch, m, key, fp)
        except Exception as e:
            if ch:
                ch.close()
            msg = str(e) if isinstance(e, RuntimeError) else f"Не удалось подключиться: {e}"
            self.ui(self._conn_failed, msg)

    def _conn_failed(self, msg):
        self.conn_btn.configure(state="normal")
        self._conn_msg(msg, RED)

    def _open_viewer(self, ch, info, key, fp):
        devs = [d for d in self.settings["devices"] if d["addr"] != key]
        self.settings["devices"] = ([{"name": info.get("host", key), "addr": key, "fp": fp}] + devs)[:20]
        self.settings.save()
        self.refresh_devices()
        self._conn_msg(f"✓ Сеанс: {info.get('host', key)}", GREEN)
        self.viewer = Viewer(self, ch, info, key)

    def on_viewer_closed(self):
        self.viewer = None
        self.conn_btn.configure(state="normal")
        self._conn_msg("Сеанс завершён", MUTED)

    def on_exit(self):
        try:
            if self.viewer:
                self.viewer.close()
            if self.host.running:
                self.host.stop()
        finally:
            self.root.destroy()

    def run(self):
        self.root.mainloop()


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "--make-icon":
        make_icon_image(256).save(sys.argv[2], format="ICO",
                                  sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
        return
    App().run()


if __name__ == "__main__":
    main()
