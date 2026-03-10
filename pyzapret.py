#!/usr/bin/env python3
"""
PyZapret GUI — Windows Edition
DPI bypass tool: pydivert (встроенный движок) + winws.exe (zapret, внешний движок)
"""

import os
import sys
import struct
import socket
import time
import threading
import queue
import ctypes
import subprocess
import shlex
from dataclasses import dataclass, field
from typing import Optional, Set, List
from pathlib import Path

import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog

try:
    import ttkbootstrap as ttk
    from ttkbootstrap.constants import *
    HAS_BOOT = True
except ImportError:
    import tkinter.ttk as ttk
    HAS_BOOT = False

try:
    import pydivert
    HAS_WD = True
except ImportError:
    pydivert = None
    HAS_WD = False


# ═══════════════════════════════════════════════════════════════════
TCP_PSH = 0x008
TCP_ACK = 0x010

STRATEGIES = {
    "split":      "Разрезать пакет на 2 TCP-сегмента",
    "disorder":   "Разрезать + обратный порядок отправки",
    "fake":       "Фейк (TTL=1) перед настоящим пакетом",
    "fakedsplit": "Фейк + разрез — максимальный обход",
}

PRESETS = [
    ("YouTube/Discord", "disorder",   "443",     "auto", 1),
    ("HTTP Sites",      "split",      "80",      "auto", 1),
    ("Max Bypass",      "fakedsplit", "80, 443", "auto", 2),
    ("Gentle",          "fake",       "80, 443", "auto", 1),
]


# ═══════════════════════════════════════════════════════════════════
#  Admin
# ═══════════════════════════════════════════════════════════════════

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def request_admin():
    params = " ".join(f'"{a}"' for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1
    )
    sys.exit(0)


# ═══════════════════════════════════════════════════════════════════
#  Packet parser
# ═══════════════════════════════════════════════════════════════════

class PacketParser:
    def __init__(self, raw: bytes):
        self.raw = bytes(raw)
        self.ip_ihl       = (self.raw[0] & 0x0F) * 4
        self.ip_total_len = struct.unpack("!H", self.raw[2:4])[0]
        self.ip_id        = struct.unpack("!H", self.raw[4:6])[0]
        self.ip_ttl       = self.raw[8]
        self.src_ip_raw   = self.raw[12:16]
        self.dst_ip_raw   = self.raw[16:20]
        self.src_ip       = socket.inet_ntoa(self.src_ip_raw)
        self.dst_ip       = socket.inet_ntoa(self.dst_ip_raw)
        t = self.ip_ihl
        self.src_port     = struct.unpack("!H", self.raw[t:t+2])[0]
        self.dst_port     = struct.unpack("!H", self.raw[t+2:t+4])[0]
        self.seq          = struct.unpack("!I", self.raw[t+4:t+8])[0]
        self.ack_num      = struct.unpack("!I", self.raw[t+8:t+12])[0]
        off_flags         = struct.unpack("!H", self.raw[t+12:t+14])[0]
        self.tcp_hdr_len  = ((off_flags >> 12) & 0xF) * 4
        self.tcp_flags    = off_flags & 0x1FF
        self.window       = struct.unpack("!H", self.raw[t+14:t+16])[0]
        self.tcp_options  = bytes(self.raw[t+20 : t+self.tcp_hdr_len])
        self.payload      = bytes(self.raw[t+self.tcp_hdr_len :])


# ═══════════════════════════════════════════════════════════════════
#  Packet builder
# ═══════════════════════════════════════════════════════════════════

class PacketBuilder:

    @staticmethod
    def _checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            s += (data[i] << 8) | data[i + 1]
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    @staticmethod
    def build(src_ip_raw, dst_ip_raw, sport, dport, seq, ack,
              flags, window, tcp_options, payload, ttl=128, ip_id=0) -> bytes:
        opt = bytes(tcp_options)
        pad = (4 - len(opt) % 4) % 4
        opt += b"\x00" * pad
        tcp_hdr_len = 20 + len(opt)
        doff_flags  = ((tcp_hdr_len // 4) << 12) | (flags & 0x1FF)
        tcp_hdr = struct.pack("!HHIIHHHH",
            sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
            doff_flags, window, 0, 0) + opt
        tcp_segment = tcp_hdr + payload
        pseudo = (bytes(src_ip_raw) + bytes(dst_ip_raw)
                  + struct.pack("!BBH", 0, 6, len(tcp_segment)))
        tcp_cksum = PacketBuilder._checksum(pseudo + tcp_segment)
        tcp_hdr = struct.pack("!HHIIHHHH",
            sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
            doff_flags, window, tcp_cksum, 0) + opt
        ip_total = 20 + tcp_hdr_len + len(payload)
        ip_hdr_no = struct.pack("!BBHHHBBH4s4s",
            0x45, 0, ip_total, ip_id & 0xFFFF, 0x4000,
            ttl, 6, 0, bytes(src_ip_raw), bytes(dst_ip_raw))
        ip_cksum = PacketBuilder._checksum(ip_hdr_no)
        ip_hdr = struct.pack("!BBHHHBBH4s4s",
            0x45, 0, ip_total, ip_id & 0xFFFF, 0x4000,
            ttl, 6, ip_cksum, bytes(src_ip_raw), bytes(dst_ip_raw))
        return ip_hdr + tcp_hdr + payload


# ═══════════════════════════════════════════════════════════════════
#  Protocol detection
# ═══════════════════════════════════════════════════════════════════

def is_tls_hello(d: bytes) -> bool:
    return (len(d) > 5 and d[0] == 0x16
            and d[1:3] in (b"\x03\x00", b"\x03\x01", b"\x03\x02", b"\x03\x03")
            and d[5] == 0x01)

def is_http(d: bytes) -> bool:
    return any(d.startswith(m) for m in
               (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ",
                b"PATCH ", b"OPTIONS ", b"CONNECT "))

def _find_sni(d: bytes):
    if not is_tls_hello(d): return None
    try:
        p = 5 + 4 + 2 + 32
        p += 1 + d[p]
        p += 2 + struct.unpack("!H", d[p:p+2])[0]
        p += 1 + d[p]
        ext_len = struct.unpack("!H", d[p:p+2])[0]; p += 2
        ext_end = p + ext_len
        while p + 4 <= ext_end:
            et = struct.unpack("!H", d[p:p+2])[0]
            el = struct.unpack("!H", d[p+2:p+4])[0]
            if et == 0:
                off = p + 4 + 2 + 1 + 2
                nl  = struct.unpack("!H", d[off-2:off])[0]
                if off + nl <= len(d): return off, nl
            p += 4 + el
    except (IndexError, struct.error): pass
    return None

def _find_host(d: bytes):
    try:
        t = d.decode("ascii", errors="ignore").lower()
        i = t.find("\r\nhost: ")
        if i >= 0:
            vs = i + 8; end = t.find("\r\n", vs)
            return vs, (end if end > 0 else len(t)) - vs
    except Exception: pass
    return None

def get_split_pos(d: bytes, manual=None) -> int:
    if manual and 0 < manual < len(d): return manual
    sni = _find_sni(d)
    if sni: return sni[0] + min(sni[1] // 2, 3)
    host = _find_host(d)
    if host: return host[0] + min(host[1] // 2, 3)
    return min(2, len(d) - 1)

def extract_hostname(d: bytes) -> str:
    for fn in (_find_sni, _find_host):
        r = fn(d)
        if r:
            try: return d[r[0]:r[0]+r[1]].decode("ascii", errors="replace")
            except Exception: pass
    return "?"


# ═══════════════════════════════════════════════════════════════════
#  Settings
# ═══════════════════════════════════════════════════════════════════

@dataclass
class Settings:
    strategy:  str           = "disorder"
    ports:     Set[int]      = field(default_factory=lambda: {80, 443})
    split_pos: Optional[int] = None
    fake_ttl:  int           = 1


# ═══════════════════════════════════════════════════════════════════
#  DPI Bypass (pydivert engine)
# ═══════════════════════════════════════════════════════════════════

class DPIBypass:
    def __init__(self, settings, log_q):
        self.s = settings
        self.log_q = log_q

    def log(self, msg, lvl="INFO"):
        self.log_q.put((lvl, msg))

    def _seg(self, p, seq_off, chunk, ttl=None, id_add=0):
        return PacketBuilder.build(
            p.src_ip_raw, p.dst_ip_raw, p.src_port, p.dst_port,
            p.seq + seq_off, p.ack_num, TCP_PSH | TCP_ACK, p.window,
            p.tcp_options, chunk, ttl=ttl or p.ip_ttl, ip_id=p.ip_id + id_add)

    def _fake_pkt(self, p, seq_off, length, id_add=10):
        return PacketBuilder.build(
            p.src_ip_raw, p.dst_ip_raw, p.src_port, p.dst_port,
            p.seq + seq_off, p.ack_num, TCP_PSH | TCP_ACK, p.window,
            p.tcp_options, os.urandom(length),
            ttl=self.s.fake_ttl, ip_id=p.ip_id + id_add)

    def _split(self, p, pos):
        return [self._seg(p, 0, p.payload[:pos]),
                self._seg(p, pos, p.payload[pos:], id_add=1)]

    def _disorder(self, p, pos):
        s1 = self._seg(p, 0,   p.payload[:pos])
        s2 = self._seg(p, pos, p.payload[pos:], id_add=1)
        return [s2, s1]

    def _do_fake(self, p, pos):
        return [self._fake_pkt(p, 0, len(p.payload)),
                self._seg(p, 0, p.payload)]

    def _fakedsplit(self, p, pos):
        c1, c2 = p.payload[:pos], p.payload[pos:]
        return [self._fake_pkt(p, 0,   len(c1), id_add=10),
                self._seg(p,  0,   c1),
                self._fake_pkt(p, pos, len(c2), id_add=11),
                self._seg(p,  pos, c2, id_add=1)]

    def process(self, p):
        pos = get_split_pos(p.payload, self.s.split_pos)
        if pos <= 0 or pos >= len(p.payload): return None
        proto    = "TLS" if is_tls_hello(p.payload) else "HTTP"
        hostname = extract_hostname(p.payload)
        self.log(f"[{proto}] {p.dst_ip}:{p.dst_port} -> {hostname}  "
                 f"strategy={self.s.strategy}  split@{pos}  {len(p.payload)}B")
        fn = {"split": self._split, "disorder": self._disorder,
              "fake": self._do_fake, "fakedsplit": self._fakedsplit}[self.s.strategy]
        return fn(p, pos)


# ═══════════════════════════════════════════════════════════════════
#  PyDivert Engine thread
# ═══════════════════════════════════════════════════════════════════

class EngineThread(threading.Thread):
    def __init__(self, settings, log_q):
        super().__init__(daemon=True)
        self.settings = settings
        self.log_q    = log_q
        self._stop_ev = threading.Event()
        self._wd      = None

    def log(self, msg, lvl="INFO"):
        self.log_q.put((lvl, msg))

    def _wd_send(self, raw_data: bytes, template_pkt):
        raw_ba = bytearray(raw_data)
        try:
            new_pkt = pydivert.Packet(memoryview(raw_ba),
                                      template_pkt.interface, template_pkt.direction)
            self._wd.send(new_pkt, recalculate_checksum=True); return
        except Exception: pass
        try:
            new_pkt = pydivert.Packet(memoryview(bytearray(raw_data)),
                                      template_pkt.interface, template_pkt.direction)
            self._wd.send(new_pkt, recalculate_checksum=False); return
        except Exception: pass
        try:
            template_pkt._raw = memoryview(bytearray(raw_data))
            self._wd.send(template_pkt, recalculate_checksum=False); return
        except Exception as e:
            if not self._stop_ev.is_set():
                self.log(f"Send error: {e}", "ERROR")

    def run(self):
        ports_filter = " or ".join(f"tcp.DstPort == {p}" for p in sorted(self.settings.ports))
        filt = f"outbound and tcp and ({ports_filter}) and tcp.PayloadLength > 0"
        self.log(f"Filter: {filt}")
        try:
            self._wd = pydivert.WinDivert(filt)
            self._wd.open()
        except Exception as e:
            self.log(f"WinDivert error: {e}", "ERROR")
            self.log("Проверьте: pydivert + запуск от Администратора", "ERROR")
            return
        bypass = DPIBypass(self.settings, self.log_q)
        self.log("Engine started — перехват пакетов", "SUCCESS")
        try:
            while not self._stop_ev.is_set():
                try: pkt = self._wd.recv()
                except Exception: break
                if self._stop_ev.is_set():
                    try: self._wd.send(pkt)
                    except Exception: pass
                    break
                try:
                    parsed = PacketParser(bytes(pkt.raw))
                    if (not parsed.payload or
                            (not is_tls_hello(parsed.payload) and not is_http(parsed.payload))):
                        self._wd.send(pkt); continue
                    new_pkts = bypass.process(parsed)
                    if new_pkts is None: self._wd.send(pkt)
                    else:
                        for raw_segment in new_pkts:
                            self._wd_send(raw_segment, pkt)
                except Exception as e:
                    if not self._stop_ev.is_set():
                        self.log(f"Process error: {e}", "ERROR")
                    try: self._wd.send(pkt)
                    except Exception: pass
        finally:
            try: self._wd.close()
            except Exception: pass
            self.log("Engine stopped")

    def stop(self):
        self._stop_ev.set()
        if self._wd:
            try: self._wd.close()
            except Exception: pass


# ═══════════════════════════════════════════════════════════════════
#  WinWS (zapret) Engine
# ═══════════════════════════════════════════════════════════════════

@dataclass
class WinWSConfig:
    """Конфигурация для winws.exe (из bat файла)."""
    bin_dir:         str = ""          # путь к bin/
    lists_dir:       str = ""          # путь к lists/
    game_filter_tcp: str = ""          # результат load_game_filter (TCP порты)
    game_filter_udp: str = ""          # результат load_game_filter (UDP порты)
    # Включить/выключить группы правил
    rule_youtube_discord: bool = True
    rule_google:          bool = True
    rule_general_http:    bool = True
    rule_quic_general:    bool = True
    rule_ipset_tcp:       bool = True
    rule_game_tcp:        bool = True
    rule_game_udp:        bool = True
    # WF порты
    wf_tcp_extra: str = "2053,2083,2087,2096,8443"
    wf_udp_extra: str = "19294-19344,50000-50100"


class WinWSEngine(threading.Thread):
    """
    Запускает winws.exe с аргументами, аналогичными bat файлу.
    Читает stdout/stderr и пишет в log_queue.
    """

    def __init__(self, config: WinWSConfig, log_q: queue.Queue):
        super().__init__(daemon=True)
        self.cfg      = config
        self.log_q    = log_q
        self._stop_ev = threading.Event()
        self._proc: Optional[subprocess.Popen] = None

    def log(self, msg, lvl="INFO"):
        self.log_q.put((lvl, msg))

    # ── Загрузка переменных из service.bat ──────────────────────────

    @staticmethod
    def _load_service_vars(bin_dir: str, command: str) -> dict:
        """
        Выполняет `service.bat <command>` и парсит SET-вывод.
        Возвращает словарь переменных среды.
        """
        service_bat = os.path.join(os.path.dirname(bin_dir), "service.bat")
        if not os.path.exists(service_bat):
            return {}
        try:
            # Запускаем в cmd.exe и после вызова service.bat делаем SET
            cmd = f'cmd.exe /c "call "{service_bat}" {command} && set"'
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=15,
                cwd=os.path.dirname(bin_dir),
            )
            env = {}
            for line in result.stdout.splitlines():
                if "=" in line:
                    k, _, v = line.partition("=")
                    env[k.strip()] = v.strip()
            return env
        except Exception:
            return {}

    def _resolve_vars(self) -> tuple[str, str]:
        """
        Пытается получить GameFilterTCP / GameFilterUDP из service.bat.
        Если не получается — берёт из конфига (ручной ввод).
        """
        if self.cfg.game_filter_tcp and self.cfg.game_filter_udp:
            return self.cfg.game_filter_tcp, self.cfg.game_filter_udp

        self.log("Загрузка game-filter из service.bat...")
        env = self._load_service_vars(self.cfg.bin_dir, "load_game_filter")
        tcp = env.get("GameFilterTCP", self.cfg.game_filter_tcp or "")
        udp = env.get("GameFilterUDP", self.cfg.game_filter_udp or "")
        if tcp: self.log(f"GameFilterTCP={tcp}")
        if udp: self.log(f"GameFilterUDP={udp}")
        return tcp, udp

    # ── Сборка аргументов winws.exe ──────────────────────────────────

    def _build_args(self, game_tcp: str, game_udp: str) -> List[str]:
        c   = self.cfg
        B   = c.bin_dir.rstrip("\\/")
        L   = c.lists_dir.rstrip("\\/")
        exe = os.path.join(B, "winws.exe")

        def b(name):  return os.path.join(B, name)
        def l(name):  return os.path.join(L, name)

        # WF TCP/UDP порты
        wf_tcp = f"80,443,{c.wf_tcp_extra}"
        if game_tcp: wf_tcp += f",{game_tcp}"
        wf_udp = f"443,{c.wf_udp_extra}"
        if game_udp: wf_udp += f",{game_udp}"

        args = [exe,
                f"--wf-tcp={wf_tcp}",
                f"--wf-udp={wf_udp}"]

        # ── Группа 1: QUIC (UDP 443) + general hostlist ──
        if c.rule_youtube_discord:
            args += [
                "--filter-udp=443",
                f"--hostlist={l('list-general.txt')}",
                f"--hostlist={l('list-general-user.txt')}",
                f"--hostlist-exclude={l('list-exclude.txt')}",
                f"--hostlist-exclude={l('list-exclude-user.txt')}",
                f"--ipset-exclude={l('ipset-exclude.txt')}",
                f"--ipset-exclude={l('ipset-exclude-user.txt')}",
                "--dpi-desync=fake",
                "--dpi-desync-repeats=6",
                f"--dpi-desync-fake-quic={b('quic_initial_www_google_com.bin')}",
                "--new",
            ]

        # ── Группа 2: UDP Discord/STUN ──
        if c.rule_youtube_discord and game_udp:
            args += [
                f"--filter-udp={c.wf_udp_extra}",
                "--filter-l7=discord,stun",
                "--dpi-desync=fake",
                "--dpi-desync-repeats=6",
                "--new",
            ]

        # ── Группа 3: TCP альтернативные порты + Discord TLS ──
        if c.rule_youtube_discord:
            args += [
                f"--filter-tcp={c.wf_tcp_extra}",
                "--hostlist-domains=discord.media",
                "--dpi-desync=fake",
                "--dpi-desync-repeats=6",
                "--dpi-desync-fooling=ts",
                f"--dpi-desync-fake-tls={b('tls_clienthello_www_google_com.bin')}",
                "--dpi-desync-fake-tls-mod=none",
                "--new",
            ]

        # ── Группа 4: TCP 443 Google list ──
        if c.rule_google:
            args += [
                "--filter-tcp=443",
                f"--hostlist={l('list-google.txt')}",
                "--ip-id=zero",
                "--dpi-desync=fake",
                "--dpi-desync-repeats=6",
                "--dpi-desync-fooling=ts",
                f"--dpi-desync-fake-tls={b('tls_clienthello_www_google_com.bin')}",
                "--new",
            ]

        # ── Группа 5: TCP 80/443 general (HTTP+HTTPS) ──
        if c.rule_general_http:
            args += [
                "--filter-tcp=80,443",
                f"--hostlist={l('list-general.txt')}",
                f"--hostlist={l('list-general-user.txt')}",
                f"--hostlist-exclude={l('list-exclude.txt')}",
                f"--hostlist-exclude={l('list-exclude-user.txt')}",
                f"--ipset-exclude={l('ipset-exclude.txt')}",
                f"--ipset-exclude={l('ipset-exclude-user.txt')}",
                "--dpi-desync=fake",
                "--dpi-desync-repeats=6",
                "--dpi-desync-fooling=ts",
                f"--dpi-desync-fake-tls={b('stun.bin')}",
                f"--dpi-desync-fake-tls={b('tls_clienthello_4pda_to.bin')}",
                f"--dpi-desync-fake-http={b('tls_clienthello_max_ru.bin')}",
                "--new",
            ]

        # ── Группа 6: QUIC ipset-all ──
        if c.rule_quic_general:
            args += [
                "--filter-udp=443",
                f"--ipset={l('ipset-all.txt')}",
                f"--hostlist-exclude={l('list-exclude.txt')}",
                f"--hostlist-exclude={l('list-exclude-user.txt')}",
                f"--ipset-exclude={l('ipset-exclude.txt')}",
                f"--ipset-exclude={l('ipset-exclude-user.txt')}",
                "--dpi-desync=fake",
                "--dpi-desync-repeats=6",
                f"--dpi-desync-fake-quic={b('quic_initial_www_google_com.bin')}",
                "--new",
            ]

        # ── Группа 7: TCP 80/443/8443 ipset-all ──
        if c.rule_ipset_tcp:
            args += [
                "--filter-tcp=80,443,8443",
                f"--ipset={l('ipset-all.txt')}",
                f"--hostlist-exclude={l('list-exclude.txt')}",
                f"--hostlist-exclude={l('list-exclude-user.txt')}",
                f"--ipset-exclude={l('ipset-exclude.txt')}",
                f"--ipset-exclude={l('ipset-exclude-user.txt')}",
                "--dpi-desync=fake",
                "--dpi-desync-repeats=6",
                "--dpi-desync-fooling=ts",
                f"--dpi-desync-fake-tls={b('stun.bin')}",
                f"--dpi-desync-fake-tls={b('tls_clienthello_4pda_to.bin')}",
                f"--dpi-desync-fake-http={b('tls_clienthello_max_ru.bin')}",
                "--new",
            ]

        # ── Группа 8: Game TCP ──
        if c.rule_game_tcp and game_tcp:
            args += [
                f"--filter-tcp={game_tcp}",
                f"--ipset={l('ipset-all.txt')}",
                f"--ipset-exclude={l('ipset-exclude.txt')}",
                f"--ipset-exclude={l('ipset-exclude-user.txt')}",
                "--dpi-desync=fake",
                "--dpi-desync-repeats=6",
                "--dpi-desync-any-protocol=1",
                "--dpi-desync-cutoff=n3",
                "--dpi-desync-fooling=ts",
                f"--dpi-desync-fake-tls={b('stun.bin')}",
                f"--dpi-desync-fake-tls={b('tls_clienthello_4pda_to.bin')}",
                f"--dpi-desync-fake-http={b('tls_clienthello_max_ru.bin')}",
                "--new",
            ]

        # ── Группа 9: Game UDP ──
        if c.rule_game_udp and game_udp:
            args += [
                f"--filter-udp={game_udp}",
                f"--ipset={l('ipset-all.txt')}",
                f"--ipset-exclude={l('ipset-exclude.txt')}",
                f"--ipset-exclude={l('ipset-exclude-user.txt')}",
                "--dpi-desync=fake",
                "--dpi-desync-repeats=12",
                "--dpi-desync-any-protocol=1",
                f"--dpi-desync-fake-unknown-udp={b('quic_initial_www_google_com.bin')}",
                "--dpi-desync-cutoff=n2",
            ]

        return args

    # ── Запуск ───────────────────────────────────────────────────────

    def run(self):
        exe = os.path.join(self.cfg.bin_dir, "winws.exe")
        if not os.path.exists(exe):
            self.log(f"winws.exe не найден: {exe}", "ERROR")
            self.log("Укажите правильную папку bin/ в настройках WinWS", "ERROR")
            return

        game_tcp, game_udp = self._resolve_vars()
        args = self._build_args(game_tcp, game_udp)

        self.log("Командная строка winws.exe:", "INFO")
        self.log("  " + " ".join(f'"{a}"' if " " in a else a for a in args[1:]), "INFO")

        try:
            self._proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception as e:
            self.log(f"Не удалось запустить winws.exe: {e}", "ERROR")
            return

        self.log(f"winws.exe запущен (PID={self._proc.pid})", "SUCCESS")

        # Читаем stdout/stderr в реальном времени
        for line in self._proc.stdout:
            line = line.rstrip()
            if not line: continue
            lvl = "ERROR" if any(w in line.lower() for w in ("error", "fail", "cannot")) else "INFO"
            self.log(f"[winws] {line}", lvl)
            if self._stop_ev.is_set(): break

        self._proc.wait()
        rc = self._proc.returncode
        if rc != 0 and not self._stop_ev.is_set():
            self.log(f"winws.exe завершился с кодом {rc}", "ERROR")
        else:
            self.log("winws.exe остановлен")

    def stop(self):
        self._stop_ev.set()
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                try: self._proc.kill()
                except Exception: pass


# ═══════════════════════════════════════════════════════════════════
#  Stats
# ═══════════════════════════════════════════════════════════════════

class Stats:
    def __init__(self):
        self.total = self.tls = self.http = 0
        self._lock = threading.Lock()

    def add(self, proto):
        with self._lock:
            self.total += 1
            if proto == "TLS": self.tls += 1
            else: self.http += 1

    def reset(self):
        with self._lock:
            self.total = self.tls = self.http = 0

    def get(self):
        with self._lock:
            return self.total, self.tls, self.http


# ═══════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════

def make_labelframe(parent, text):
    lf    = ttk.LabelFrame(parent, text=text)
    inner = ttk.Frame(lf)
    inner.pack(fill="both", expand=True, padx=12, pady=8)
    return lf, inner

def browse_dir(var: tk.StringVar, title="Выберите папку"):
    d = filedialog.askdirectory(title=title)
    if d: var.set(d)


# ═══════════════════════════════════════════════════════════════════
#  GUI
# ═══════════════════════════════════════════════════════════════════

class PyZapretGUI:
    TITLE  = "PyZapret — DPI Bypass Tool  (Windows)"
    W, H   = 920, 820

    C_GREEN  = "#00e676"
    C_RED    = "#ff1744"
    C_ORANGE = "#ff9100"
    C_BLUE   = "#448aff"
    C_DIM    = "#757575"
    C_LOG_BG = "#0d1117"
    C_LOG_FG = "#c9d1d9"
    C_ACCENT = "#0f3460"

    def __init__(self):
        if HAS_BOOT:
            self.root = ttk.Window(
                title=self.TITLE, themename="darkly",
                size=(self.W, self.H), resizable=(True, True))
        else:
            self.root = tk.Tk()
            self.root.title(self.TITLE)
            self.root.geometry(f"{self.W}x{self.H}")

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.log_queue = queue.Queue()
        self.stats     = Stats()
        self.engine    = None
        self.running   = False

        self._build_ui()
        self._poll()

    # ─────────────────────────────────────────────────────────────────
    def _build_ui(self):
        main = ttk.Frame(self.root)
        main.pack(fill="both", expand=True, padx=10, pady=10)

        # ═══ HEADER ═══
        hdr = ttk.Frame(main); hdr.pack(fill="x", pady=(0, 8))
        ttk.Label(hdr, text="⚡ PyZapret  (Windows)",
                  font=("Segoe UI", 20, "bold")).pack(side="left")
        self.lbl_status = ttk.Label(
            hdr, text="● STOPPED",
            font=("Segoe UI", 12, "bold"), foreground=self.C_RED)
        self.lbl_status.pack(side="right", padx=10)

        # ═══ ENGINE SELECTOR ═══
        eng_f = ttk.Frame(main); eng_f.pack(fill="x", pady=(0, 6))
        ttk.Label(eng_f, text="Движок:", font=("Segoe UI", 10, "bold")).pack(side="left", padx=(0, 8))
        self.var_engine = tk.StringVar(value="winws")
        rb_kw = {}
        ttk.Radiobutton(eng_f, text="winws.exe  (zapret, рекомендуется)",
                        variable=self.var_engine, value="winws",
                        command=self._on_engine_change, **rb_kw).pack(side="left", padx=4)
        ttk.Radiobutton(eng_f, text="pydivert  (встроенный)",
                        variable=self.var_engine, value="pydivert",
                        command=self._on_engine_change, **rb_kw).pack(side="left", padx=4)

        # ═══ NOTEBOOK (вкладки настроек) ═══
        self.nb = ttk.Notebook(main)
        self.nb.pack(fill="x", pady=(0, 8))

        # ── Вкладка 1: WinWS ──
        tab_ws = ttk.Frame(self.nb)
        self.nb.add(tab_ws, text="  WinWS (zapret)  ")
        self._build_winws_tab(tab_ws)

        # ── Вкладка 2: PyDivert ──
        tab_pd = ttk.Frame(self.nb)
        self.nb.add(tab_pd, text="  PyDivert  ")
        self._build_pydivert_tab(tab_pd)

        # ═══ CONTROLS ═══
        ctrl = ttk.Frame(main); ctrl.pack(fill="x", pady=8)
        sk = {"bootstyle": "success"} if HAS_BOOT else {}
        dk = {"bootstyle": "danger"}  if HAS_BOOT else {}
        self.btn_start = ttk.Button(ctrl, text="▶  START",
                                    command=self._start, width=16, **sk)
        self.btn_stop  = ttk.Button(ctrl, text="■  STOP",
                                    command=self._stop, width=16,
                                    state="disabled", **dk)
        self.btn_start.pack(side="left", padx=(0, 8))
        self.btn_stop.pack(side="left", padx=(0, 20))
        sf2 = ttk.Frame(ctrl); sf2.pack(side="right")
        self.lbl_total = ttk.Label(sf2, text="Packets: 0", font=("Consolas", 10))
        self.lbl_total.pack(side="left", padx=8)
        self.lbl_tls = ttk.Label(sf2, text="TLS: 0",
                                 font=("Consolas", 10), foreground=self.C_BLUE)
        self.lbl_tls.pack(side="left", padx=8)
        self.lbl_http = ttk.Label(sf2, text="HTTP: 0",
                                  font=("Consolas", 10), foreground=self.C_ORANGE)
        self.lbl_http.pack(side="left", padx=8)

        # ═══ LOG ═══
        lf, li = make_labelframe(main, "  📋  Лог  ")
        lf.pack(fill="both", expand=True)
        self.log_text = scrolledtext.ScrolledText(
            li, font=("Consolas", 9),
            bg=self.C_LOG_BG, fg=self.C_LOG_FG,
            insertbackground=self.C_LOG_FG,
            selectbackground=self.C_ACCENT,
            wrap="word", state="disabled", height=18)
        self.log_text.pack(fill="both", expand=True)
        for tag, color in [
            ("INFO", "#58a6ff"), ("ERROR", "#ff6b6b"),
            ("WARNING", "#ffa657"), ("SUCCESS", "#3fb950"),
            ("TIME", "#6e7681"), ("TLS", "#d2a8ff"), ("HTTP", "#ffa657"),
        ]:
            self.log_text.tag_config(tag, foreground=color)
        lc = ttk.Frame(li); lc.pack(fill="x", pady=(4, 0))
        ttk.Button(lc, text="Clear", command=self._clear_log).pack(side="right")
        self.var_scroll = tk.BooleanVar(value=True)
        ttk.Checkbutton(lc, text="Auto-scroll",
                        variable=self.var_scroll).pack(side="right", padx=8)

        # ═══ FOOTER ═══
        ttk.Label(main, font=("Segoe UI", 8), foreground=self.C_DIM,
                  text="⚠ Требуются права Администратора | Windows 10/11 | WinDivert / winws.exe"
                  ).pack(fill="x", pady=(4, 0))

        # Init
        admin_ok = is_admin()
        self._log("INFO", "PyZapret GUI (Windows) initialized")
        self._log("INFO", f"Admin: {'yes' if admin_ok else 'NO'}")
        self._log("INFO", f"pydivert: {'loaded' if HAS_WD else 'NOT FOUND'}")
        if not admin_ok:
            self._log("WARNING", "Запустите от имени Администратора!")

        self._on_engine_change()   # выставить правильную вкладку

    # ─── WinWS tab ────────────────────────────────────────────────────

    def _build_winws_tab(self, parent):
        f = ttk.Frame(parent); f.pack(fill="both", expand=True, padx=8, pady=6)

        # Paths
        def row(text, var, r):
            ttk.Label(r, text=text, width=14, font=("Segoe UI", 9)).pack(side="left")
            ttk.Entry(r, textvariable=var, font=("Segoe UI", 9)).pack(
                side="left", fill="x", expand=True, padx=(0, 4))
            ttk.Button(r, text="…", width=3,
                       command=lambda v=var: browse_dir(v)).pack(side="left")

        r1 = ttk.Frame(f); r1.pack(fill="x", pady=2)
        self.var_bin  = tk.StringVar(value=r"C:\zapret\bin")
        row("Папка bin/:", self.var_bin, r1)

        r2 = ttk.Frame(f); r2.pack(fill="x", pady=2)
        self.var_lists = tk.StringVar(value=r"C:\zapret\lists")
        row("Папка lists/:", self.var_lists, r2)

        # Game filter
        r3 = ttk.Frame(f); r3.pack(fill="x", pady=2)
        ttk.Label(r3, text="GameFilter TCP:", width=14,
                  font=("Segoe UI", 9)).pack(side="left")
        self.var_game_tcp = tk.StringVar(value="")
        ttk.Entry(r3, textvariable=self.var_game_tcp, width=26,
                  font=("Segoe UI", 9)).pack(side="left", padx=(0, 16))
        ttk.Label(r3, text="GameFilter UDP:",
                  font=("Segoe UI", 9)).pack(side="left")
        self.var_game_udp = tk.StringVar(value="")
        ttk.Entry(r3, textvariable=self.var_game_udp, width=26,
                  font=("Segoe UI", 9)).pack(side="left")
        ttk.Label(r3, text="(пусто → auto из service.bat)",
                  font=("Segoe UI", 8), foreground=self.C_DIM).pack(side="left", padx=6)

        # WF extra ports
        r4 = ttk.Frame(f); r4.pack(fill="x", pady=2)
        ttk.Label(r4, text="WF TCP extra:", width=14,
                  font=("Segoe UI", 9)).pack(side="left")
        self.var_wf_tcp = tk.StringVar(value="2053,2083,2087,2096,8443")
        ttk.Entry(r4, textvariable=self.var_wf_tcp, width=30,
                  font=("Segoe UI", 9)).pack(side="left", padx=(0, 16))
        ttk.Label(r4, text="WF UDP extra:",
                  font=("Segoe UI", 9)).pack(side="left")
        self.var_wf_udp = tk.StringVar(value="19294-19344,50000-50100")
        ttk.Entry(r4, textvariable=self.var_wf_udp, width=24,
                  font=("Segoe UI", 9)).pack(side="left")

        # Rule toggles
        r5 = ttk.Frame(f); r5.pack(fill="x", pady=(6, 0))
        ttk.Label(r5, text="Группы правил:",
                  font=("Segoe UI", 9)).pack(side="left", padx=(0, 8))
        self.var_rule_yt    = tk.BooleanVar(value=True)
        self.var_rule_ggl   = tk.BooleanVar(value=True)
        self.var_rule_gen   = tk.BooleanVar(value=True)
        self.var_rule_quic  = tk.BooleanVar(value=True)
        self.var_rule_ipset = tk.BooleanVar(value=True)
        self.var_rule_gtcp  = tk.BooleanVar(value=True)
        self.var_rule_gudp  = tk.BooleanVar(value=True)
        for text, var in [
            ("YouTube/Discord", self.var_rule_yt),
            ("Google",          self.var_rule_ggl),
            ("General HTTP/S",  self.var_rule_gen),
            ("QUIC ipset",      self.var_rule_quic),
            ("ipset TCP",       self.var_rule_ipset),
            ("Game TCP",        self.var_rule_gtcp),
            ("Game UDP",        self.var_rule_gudp),
        ]:
            ttk.Checkbutton(r5, text=text, variable=var).pack(side="left", padx=3)

    # ─── PyDivert tab ─────────────────────────────────────────────────

    def _build_pydivert_tab(self, parent):
        f = ttk.Frame(parent); f.pack(fill="both", expand=True, padx=8, pady=6)

        r1 = ttk.Frame(f); r1.pack(fill="x", pady=3)
        ttk.Label(r1, text="Стратегия:", width=16,
                  font=("Segoe UI", 10)).pack(side="left")
        self.var_strat = tk.StringVar(value="disorder")
        cb = ttk.Combobox(r1, textvariable=self.var_strat,
                          values=list(STRATEGIES), state="readonly",
                          width=16, font=("Segoe UI", 10))
        cb.pack(side="left", padx=(0, 10))
        cb.bind("<<ComboboxSelected>>", self._on_strat)
        self.lbl_desc = ttk.Label(r1, text=STRATEGIES["disorder"],
                                  font=("Segoe UI", 9, "italic"),
                                  foreground=self.C_DIM)
        self.lbl_desc.pack(side="left", fill="x", expand=True)

        r2 = ttk.Frame(f); r2.pack(fill="x", pady=3)
        ttk.Label(r2, text="Порты:", width=16,
                  font=("Segoe UI", 10)).pack(side="left")
        self.var_ports = tk.StringVar(value="80, 443")
        ttk.Entry(r2, textvariable=self.var_ports, width=28,
                  font=("Segoe UI", 10)).pack(side="left", padx=(0, 10))
        ttk.Label(r2, text="(через запятую)",
                  font=("Segoe UI", 9), foreground=self.C_DIM).pack(side="left")

        r3 = ttk.Frame(f); r3.pack(fill="x", pady=3)
        ttk.Label(r3, text="Split position:", width=16,
                  font=("Segoe UI", 10)).pack(side="left")
        self.var_split = tk.StringVar(value="auto")
        ttk.Entry(r3, textvariable=self.var_split, width=10,
                  font=("Segoe UI", 10)).pack(side="left", padx=(0, 20))
        ttk.Label(r3, text="Fake TTL:", font=("Segoe UI", 10)).pack(side="left", padx=(0, 5))
        self.var_ttl = tk.IntVar(value=1)
        ttk.Spinbox(r3, from_=1, to=10, textvariable=self.var_ttl,
                    width=5, font=("Segoe UI", 10)).pack(side="left")

        r4 = ttk.Frame(f); r4.pack(fill="x", pady=(8, 0))
        ttk.Label(r4, text="Пресеты:",
                  font=("Segoe UI", 10)).pack(side="left", padx=(0, 8))
        for name, st, po, sp, ft in PRESETS:
            kw = {"bootstyle": "outline"} if HAS_BOOT else {}
            ttk.Button(r4, text=name,
                       command=lambda s=st, p=po, spl=sp, f=ft:
                           self._preset(s, p, spl, f), **kw).pack(side="left", padx=3)

        if not HAS_WD:
            ttk.Label(f, text="⚠ pydivert не установлен! Выполните: pip install pydivert",
                      font=("Segoe UI", 9), foreground=self.C_RED).pack(pady=6)

    # ─── helpers ───────────────────────────────────────────────────────

    def _on_engine_change(self):
        eng = self.var_engine.get()
        self.nb.select(0 if eng == "winws" else 1)

    def _on_strat(self, _e=None):
        self.lbl_desc.config(text=STRATEGIES.get(self.var_strat.get(), ""))

    def _preset(self, strat, ports, sp, ttl):
        self.var_strat.set(strat); self.var_ports.set(ports)
        self.var_split.set(sp); self.var_ttl.set(ttl)
        self._on_strat()
        self._log("INFO", f"Preset: {strat} / ports={ports}")

    # ─── log ───────────────────────────────────────────────────────────

    def _log(self, level, msg):
        self.log_text.configure(state="normal")
        ts = time.strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{ts}] ", "TIME")
        tag = level
        if "[TLS]" in msg:  tag = "TLS"
        elif "[HTTP]" in msg: tag = "HTTP"
        self.log_text.insert("end", f"[{level}] {msg}\n", tag)
        self.log_text.configure(state="disabled")
        if self.var_scroll.get():
            self.log_text.see("end")
        if "[TLS]" in msg or "[HTTP]" in msg:
            self.stats.add("TLS" if "[TLS]" in msg else "HTTP")
            self._refresh_stats()

    def _refresh_stats(self):
        t, tls, http = self.stats.get()
        self.lbl_total.config(text=f"Packets: {t}")
        self.lbl_tls.config(text=f"TLS: {tls}")
        self.lbl_http.config(text=f"HTTP: {http}")

    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self.stats.reset(); self._refresh_stats()

    def _poll(self):
        try:
            while True:
                lvl, msg = self.log_queue.get_nowait()
                self._log(lvl, msg)
        except queue.Empty:
            pass
        if self.running and self.engine and not self.engine.is_alive():
            self._on_stopped()
        self.root.after(100, self._poll)

    # ─── validation ────────────────────────────────────────────────────

    def _parse_winws_settings(self) -> Optional[WinWSConfig]:
        bin_dir   = self.var_bin.get().strip()
        lists_dir = self.var_lists.get().strip()
        if not bin_dir or not os.path.isdir(bin_dir):
            messagebox.showerror("Ошибка", f"Папка bin не найдена:\n{bin_dir}")
            return None
        if not lists_dir or not os.path.isdir(lists_dir):
            messagebox.showerror("Ошибка", f"Папка lists не найдена:\n{lists_dir}")
            return None
        return WinWSConfig(
            bin_dir=bin_dir,
            lists_dir=lists_dir,
            game_filter_tcp=self.var_game_tcp.get().strip(),
            game_filter_udp=self.var_game_udp.get().strip(),
            wf_tcp_extra=self.var_wf_tcp.get().strip(),
            wf_udp_extra=self.var_wf_udp.get().strip(),
            rule_youtube_discord=self.var_rule_yt.get(),
            rule_google=self.var_rule_ggl.get(),
            rule_general_http=self.var_rule_gen.get(),
            rule_quic_general=self.var_rule_quic.get(),
            rule_ipset_tcp=self.var_rule_ipset.get(),
            rule_game_tcp=self.var_rule_gtcp.get(),
            rule_game_udp=self.var_rule_gudp.get(),
        )

    def _parse_pydivert_settings(self) -> Optional[Settings]:
        if not HAS_WD:
            messagebox.showerror("Ошибка", "pydivert не установлен!\npip install pydivert")
            return None
        if not is_admin():
            if messagebox.askyesno("Администратор",
                                   "Нужны права Администратора.\nПерезапустить?"):
                request_admin()
            return None
        try:
            ports = {int(p.strip()) for p in self.var_ports.get().split(",") if p.strip()}
            if not ports: raise ValueError
        except ValueError:
            messagebox.showerror("Ошибка", "Неверные порты!\nПример: 80, 443")
            return None
        sp = self.var_split.get().strip().lower()
        split_pos = None
        if sp not in ("auto", ""):
            try:
                split_pos = int(sp)
                if split_pos < 1: raise ValueError
            except ValueError:
                messagebox.showerror("Ошибка", "Split: 'auto' или число > 0")
                return None
        return Settings(strategy=self.var_strat.get(), ports=ports,
                        split_pos=split_pos, fake_ttl=self.var_ttl.get())

    # ─── start / stop ──────────────────────────────────────────────────

    def _start(self):
        if self.running: return
        if not is_admin():
            if messagebox.askyesno("Администратор",
                                   "Нужны права Администратора.\nПерезапустить?"):
                request_admin()
            return

        eng = self.var_engine.get()
        if eng == "winws":
            cfg = self._parse_winws_settings()
            if not cfg: return
            self.engine = WinWSEngine(cfg, self.log_queue)
        else:
            s = self._parse_pydivert_settings()
            if not s: return
            self.engine = EngineThread(s, self.log_queue)

        self.running = True
        self.stats.reset(); self._refresh_stats()
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.lbl_status.config(text="● RUNNING", foreground=self.C_GREEN)
        self._log("SUCCESS", f"Запуск движка: {eng.upper()}")
        self.engine.start()

    def _stop(self):
        if not self.running: return
        self._log("WARNING", "Остановка...")
        self.running = False
        if self.engine:
            self.engine.stop()
            threading.Thread(
                target=lambda: (self.engine.join(5),
                                self.root.after(0, self._on_stopped)),
                daemon=True).start()
        else:
            self._on_stopped()

    def _on_stopped(self):
        self.running = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.lbl_status.config(text="● STOPPED", foreground=self.C_RED)

    def _on_close(self):
        if self.running:
            if not messagebox.askyesno("Выход", "Остановить движок и выйти?"):
                return
            self._stop()
            self.root.after(2000, self.root.destroy)
        else:
            self.root.destroy()

    def run(self):
        self.root.mainloop()


# ═══════════════════════════════════════════════════════════════════
def main():
    PyZapretGUI().run()

if __name__ == "__main__":
    main()
