"""
SENTINEL — Cybersecurity Incident Response Platform
Main GUI Application
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import time
import random
import math
import os
import sys
from datetime import datetime
from collections import defaultdict

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.scanner import SentinelScanner, THREAT_LEVELS, THREAT_SIGNATURES
from core.reporter import generate_text_report, save_json_report

# ─── Color Palette ────────────────────────────────────────────────────────────
C = {
    "bg":         "#080C14",
    "panel":      "#0D1421",
    "panel2":     "#101828",
    "border":     "#1A2540",
    "border2":    "#243050",
    "accent":     "#00D4FF",
    "accent2":    "#0066FF",
    "critical":   "#FF2D55",
    "high":       "#FF9500",
    "medium":     "#FFCC00",
    "low":        "#34C759",
    "clean":      "#00D4AA",
    "text":       "#E8F0FF",
    "text2":      "#8899BB",
    "text3":      "#445577",
    "green":      "#00FF88",
    "red":        "#FF3366",
    "purple":     "#BF5AF2",
    "white":      "#FFFFFF",
}

LEVEL_COLOR = {
    "CRITICAL": C["critical"],
    "HIGH":     C["high"],
    "MEDIUM":   C["medium"],
    "LOW":      C["low"],
    "CLEAN":    C["clean"],
}

STATUS_COLOR = {
    "ACTIVE":    C["red"],
    "BLOCKED":   C["critical"],
    "ISOLATED":  C["medium"],
    "ESCALATED": C["purple"],
}


# ─── Utility ──────────────────────────────────────────────────────────────────

def human_bytes(b):
    if b >= 1_048_576:
        return f"{b/1_048_576:.1f}MB"
    if b >= 1024:
        return f"{b/1024:.1f}KB"
    return f"{b}B"


# ─── Animated Widgets ─────────────────────────────────────────────────────────

class PulsingDot(tk.Canvas):
    """Animated status indicator."""

    def __init__(self, parent, color=C["green"], size=12, **kw):
        super().__init__(parent, width=size, height=size,
                         bg=C["bg"], highlightthickness=0, **kw)
        self._color = color
        self._size = size
        self._phase = 0
        self._running = False
        self._dot = self.create_oval(2, 2, size-2, size-2,
                                     fill=color, outline="")
        self._animate()

    def set_color(self, color):
        self._color = color

    def _animate(self):
        self._phase = (self._phase + 0.15) % (2 * math.pi)
        alpha = int(100 + 155 * (0.5 + 0.5 * math.sin(self._phase)))
        # Convert to hex shade
        r = int(int(self._color[1:3], 16) * alpha / 255)
        g = int(int(self._color[3:5], 16) * alpha / 255)
        b = int(int(self._color[5:7], 16) * alpha / 255)
        color = f"#{r:02x}{g:02x}{b:02x}"
        self.itemconfig(self._dot, fill=color)
        self.after(50, self._animate)


class StatCard(tk.Frame):
    """Numerical stat card."""

    def __init__(self, parent, label, value="0", color=C["accent"], **kw):
        super().__init__(parent, bg=C["panel"], relief="flat", **kw)
        self.config(highlightthickness=1, highlightbackground=C["border"])

        tk.Label(self, text=label, font=("Courier New", 8, "bold"),
                 fg=C["text2"], bg=C["panel"]).pack(pady=(8, 0))
        self._val = tk.StringVar(value=value)
        tk.Label(self, textvariable=self._val, font=("Courier New", 20, "bold"),
                 fg=color, bg=C["panel"]).pack()
        tk.Frame(self, height=2, bg=color).pack(fill="x", side="bottom")

    def set(self, val):
        self._val.set(str(val))


class ScrollableFrame(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        canvas = tk.Canvas(self, bg=C["panel"], highlightthickness=0)
        scrollbar = tk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.inner = tk.Frame(canvas, bg=C["panel"])
        self.inner.bind("<Configure>",
                        lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(-1 * (e.delta // 120), "units"))


# ─── Main Application ─────────────────────────────────────────────────────────

class SentinelApp(tk.Tk):

    def __init__(self):
        super().__init__()

        self.title("SENTINEL — Cybersecurity Incident Response Platform")
        self.geometry("1400x900")
        self.configure(bg=C["bg"])
        self.minsize(1100, 700)

        self.scanner = SentinelScanner()
        self.scanner.register_callback(self._on_scanner_event)

        self._event_queue = []
        self._queue_lock = threading.Lock()
        self._selected_event = None
        self._selected_ip = None

        self._build_ui()
        self._refresh_loop()

    # ─── UI Construction ──────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_topbar()
        self._build_main()
        self._build_statusbar()

    def _build_topbar(self):
        bar = tk.Frame(self, bg=C["panel"], height=56)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)
        bar.config(highlightthickness=1, highlightbackground=C["border"])

        # Logo
        logo = tk.Frame(bar, bg=C["panel"])
        logo.pack(side="left", padx=16, pady=8)
        tk.Label(logo, text="⬡ SENTINEL", font=("Courier New", 18, "bold"),
                 fg=C["accent"], bg=C["panel"]).pack(side="left")
        tk.Label(logo, text="  INCIDENT RESPONSE PLATFORM",
                 font=("Courier New", 9), fg=C["text2"], bg=C["panel"]).pack(side="left", pady=(6, 0))

        # Right controls
        right = tk.Frame(bar, bg=C["panel"])
        right.pack(side="right", padx=16)

        self._clock_var = tk.StringVar()
        tk.Label(right, textvariable=self._clock_var,
                 font=("Courier New", 10), fg=C["text2"], bg=C["panel"]).pack(side="right", padx=10)

        self._scan_btn = tk.Button(
            right, text="▶  START SCAN", font=("Courier New", 10, "bold"),
            fg=C["bg"], bg=C["green"], activeforeground=C["bg"],
            activebackground="#00CC77", relief="flat", padx=16, pady=4,
            cursor="hand2", command=self._toggle_scan
        )
        self._scan_btn.pack(side="right", padx=6)

        self._dot = PulsingDot(right, color=C["text3"])
        self._dot.pack(side="right", padx=4)

        self._status_var = tk.StringVar(value="IDLE")
        tk.Label(right, textvariable=self._status_var,
                 font=("Courier New", 9, "bold"), fg=C["text3"], bg=C["panel"]).pack(side="right")

    def _build_main(self):
        outer = tk.Frame(self, bg=C["bg"])
        outer.pack(fill="both", expand=True, padx=0, pady=0)

        # Left sidebar
        self._sidebar = tk.Frame(outer, bg=C["panel"], width=260)
        self._sidebar.pack(side="left", fill="y", padx=(8, 0), pady=8)
        self._sidebar.pack_propagate(False)
        self._sidebar.config(highlightthickness=1, highlightbackground=C["border"])

        # Notebook (right)
        self._nb = ttk.Notebook(outer)
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=C["bg"], borderwidth=0)
        style.configure("TNotebook.Tab",
                        background=C["panel"], foreground=C["text2"],
                        font=("Courier New", 9, "bold"),
                        padding=[16, 6], borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", C["border2"])],
                  foreground=[("selected", C["accent"])])
        self._nb.pack(side="left", fill="both", expand=True, padx=8, pady=8)

        self._build_sidebar()
        self._build_tab_events()
        self._build_tab_threats()
        self._build_tab_network()
        self._build_tab_logs()
        self._build_tab_report()

    def _build_sidebar(self):
        s = self._sidebar

        # Title
        tk.Label(s, text="THREAT OVERVIEW", font=("Courier New", 9, "bold"),
                 fg=C["accent"], bg=C["panel"]).pack(pady=(12, 6))

        # Stat cards
        cards_frame = tk.Frame(s, bg=C["panel"])
        cards_frame.pack(fill="x", padx=8)

        self._stats = {}
        configs = [
            ("CRITICAL", C["critical"]),
            ("HIGH",     C["high"]),
            ("MEDIUM",   C["medium"]),
            ("LOW",      C["low"]),
            ("TOTAL",    C["accent"]),
            ("BLOCKED",  C["red"]),
        ]
        for i, (label, color) in enumerate(configs):
            r, c = divmod(i, 2)
            card = StatCard(cards_frame, label, color=color)
            card.grid(row=r, column=c, padx=3, pady=3, sticky="ew")
            self._stats[label] = card
        cards_frame.columnconfigure(0, weight=1)
        cards_frame.columnconfigure(1, weight=1)

        # Separator
        tk.Frame(s, height=1, bg=C["border"]).pack(fill="x", padx=8, pady=8)

        # Action Panel
        tk.Label(s, text="RESPONSE ACTIONS", font=("Courier New", 9, "bold"),
                 fg=C["accent"], bg=C["panel"]).pack(pady=(0, 6))

        btn_cfg = [
            ("🚨  ESCALATE EVENT",   C["purple"],   self._action_escalate),
            ("🔒  ISOLATE IP",       C["medium"],   self._action_isolate),
            ("🚫  BLOCK IP",         C["critical"], self._action_block),
            ("📄  GENERATE REPORT",  C["accent2"],  self._action_report),
            ("🔍  DEEP SCAN",        C["accent"],   self._action_deep_scan),
            ("🔓  UNBLOCK IP",       C["low"],      self._action_unblock),
            ("📊  EXPORT JSON",      C["text2"],    self._action_export_json),
        ]
        for text, color, cmd in btn_cfg:
            b = tk.Button(s, text=text, font=("Courier New", 9, "bold"),
                          fg=color, bg=C["panel2"],
                          activeforeground=color, activebackground=C["border"],
                          relief="flat", anchor="w", padx=12, pady=7,
                          cursor="hand2", command=cmd,
                          highlightthickness=1, highlightbackground=C["border"])
            b.pack(fill="x", padx=8, pady=2)

        # Separator
        tk.Frame(s, height=1, bg=C["border"]).pack(fill="x", padx=8, pady=8)

        # Selected info
        tk.Label(s, text="SELECTED EVENT", font=("Courier New", 9, "bold"),
                 fg=C["accent"], bg=C["panel"]).pack(pady=(0, 4))
        self._sel_info = tk.Text(s, height=10, font=("Courier New", 8),
                                 fg=C["text2"], bg=C["panel2"],
                                 relief="flat", wrap="word", padx=6, pady=4,
                                 highlightthickness=1, highlightbackground=C["border"])
        self._sel_info.pack(fill="x", padx=8, pady=(0, 8))
        self._sel_info.config(state="disabled")

        # Threat meter
        tk.Label(s, text="THREAT LEVEL", font=("Courier New", 9, "bold"),
                 fg=C["accent"], bg=C["panel"]).pack()
        self._threat_canvas = tk.Canvas(s, height=20, bg=C["panel"],
                                        highlightthickness=0)
        self._threat_canvas.pack(fill="x", padx=8, pady=4)
        self._draw_threat_meter(0)

    def _draw_threat_meter(self, pct):
        c = self._threat_canvas
        c.delete("all")
        w = c.winfo_width() or 230
        h = 18
        c.create_rectangle(0, 0, w, h, fill=C["border"], outline="")
        if pct > 0:
            fill = C["low"] if pct < 30 else C["medium"] if pct < 60 else C["high"] if pct < 85 else C["critical"]
            c.create_rectangle(0, 0, int(w * pct / 100), h, fill=fill, outline="")
        c.create_text(w // 2, h // 2, text=f"{pct:.0f}%",
                      fill=C["white"], font=("Courier New", 8, "bold"))

    def _build_tab_events(self):
        frame = tk.Frame(self._nb, bg=C["bg"])
        self._nb.add(frame, text="  LIVE EVENTS  ")

        # Toolbar
        toolbar = tk.Frame(frame, bg=C["panel2"])
        toolbar.pack(fill="x", pady=(0, 4))
        toolbar.config(highlightthickness=1, highlightbackground=C["border"])

        tk.Label(toolbar, text="FILTER:", font=("Courier New", 8, "bold"),
                 fg=C["text2"], bg=C["panel2"]).pack(side="left", padx=8)

        self._filter_var = tk.StringVar(value="ALL")
        for lvl in ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            color = LEVEL_COLOR.get(lvl, C["text2"])
            rb = tk.Radiobutton(toolbar, text=lvl, variable=self._filter_var,
                                value=lvl, font=("Courier New", 8, "bold"),
                                fg=color, bg=C["panel2"], activebackground=C["panel2"],
                                selectcolor=C["border"], relief="flat",
                                command=self._apply_filter)
            rb.pack(side="left", padx=4, pady=4)

        tk.Label(toolbar, text="  IP FILTER:", font=("Courier New", 8, "bold"),
                 fg=C["text2"], bg=C["panel2"]).pack(side="left", padx=(12, 4))
        self._ip_filter = tk.Entry(toolbar, font=("Courier New", 9),
                                   fg=C["text"], bg=C["border"],
                                   insertbackground=C["accent"], relief="flat",
                                   width=16)
        self._ip_filter.pack(side="left")
        self._ip_filter.bind("<Return>", lambda e: self._apply_filter())

        self._event_count_var = tk.StringVar(value="Events: 0")
        tk.Label(toolbar, textvariable=self._event_count_var,
                 font=("Courier New", 8), fg=C["text2"],
                 bg=C["panel2"]).pack(side="right", padx=12)

        # Treeview
        cols = ("time", "level", "src", "dst", "threat", "protocol", "status", "confidence")
        tree_frame = tk.Frame(frame, bg=C["bg"])
        tree_frame.pack(fill="both", expand=True)

        style = ttk.Style()
        style.configure("Sentinel.Treeview",
                        background=C["panel"],
                        foreground=C["text"],
                        rowheight=24,
                        fieldbackground=C["panel"],
                        borderwidth=0,
                        font=("Courier New", 9))
        style.configure("Sentinel.Treeview.Heading",
                        background=C["panel2"],
                        foreground=C["accent"],
                        font=("Courier New", 8, "bold"),
                        relief="flat")
        style.map("Sentinel.Treeview",
                  background=[("selected", C["border2"])],
                  foreground=[("selected", C["white"])])

        self._tree = ttk.Treeview(tree_frame, columns=cols, show="headings",
                                  style="Sentinel.Treeview", selectmode="browse")
        vsb = tk.Scrollbar(tree_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)

        headers = {
            "time":       ("TIMESTAMP", 140),
            "level":      ("LEVEL",     80),
            "src":        ("SOURCE IP", 135),
            "dst":        ("DEST IP",   135),
            "threat":     ("THREAT",    180),
            "protocol":   ("PROTO",     60),
            "status":     ("STATUS",    90),
            "confidence": ("CONF%",     60),
        }
        for col, (hdr, w) in headers.items():
            self._tree.heading(col, text=hdr)
            self._tree.column(col, width=w, anchor="center" if col in ("level","protocol","status","confidence") else "w")

        self._tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self._tree.bind("<<TreeviewSelect>>", self._on_event_select)
        self._tree.bind("<Button-3>", self._context_menu)

        # Tags for row colors
        for lvl, color in LEVEL_COLOR.items():
            self._tree.tag_configure(lvl, foreground=color)
        self._tree.tag_configure("BLOCKED",   foreground=C["critical"])
        self._tree.tag_configure("ESCALATED", foreground=C["purple"])

        self._displayed_events = []
        self._all_events_cache = []

    def _build_tab_threats(self):
        frame = tk.Frame(self._nb, bg=C["bg"])
        self._nb.add(frame, text="  THREAT MAP  ")

        # Top attackers
        left = tk.Frame(frame, bg=C["panel"], width=320)
        left.pack(side="left", fill="y", padx=(0, 4), pady=0)
        left.pack_propagate(False)
        left.config(highlightthickness=1, highlightbackground=C["border"])

        tk.Label(left, text="TOP ATTACKERS", font=("Courier New", 9, "bold"),
                 fg=C["accent"], bg=C["panel"]).pack(pady=8)

        self._attacker_frame = tk.Frame(left, bg=C["panel"])
        self._attacker_frame.pack(fill="both", expand=True, padx=8)

        # Threat distribution
        right = tk.Frame(frame, bg=C["panel"])
        right.pack(side="left", fill="both", expand=True)
        right.config(highlightthickness=1, highlightbackground=C["border"])

        tk.Label(right, text="THREAT DISTRIBUTION", font=("Courier New", 9, "bold"),
                 fg=C["accent"], bg=C["panel"]).pack(pady=8)

        self._dist_canvas = tk.Canvas(right, bg=C["panel"], highlightthickness=0)
        self._dist_canvas.pack(fill="both", expand=True, padx=16, pady=8)

    def _build_tab_network(self):
        frame = tk.Frame(self._nb, bg=C["bg"])
        self._nb.add(frame, text="  NETWORK  ")

        # IP Management
        top = tk.Frame(frame, bg=C["panel"])
        top.pack(fill="x", pady=(0, 4))
        top.config(highlightthickness=1, highlightbackground=C["border"])

        tk.Label(top, text="IP MANAGEMENT", font=("Courier New", 9, "bold"),
                 fg=C["accent"], bg=C["panel"]).pack(side="left", padx=12, pady=8)

        right_top = tk.Frame(top, bg=C["panel"])
        right_top.pack(side="right", padx=12)
        tk.Label(right_top, text="Manual IP:", font=("Courier New", 9),
                 fg=C["text2"], bg=C["panel"]).pack(side="left")
        self._manual_ip = tk.Entry(right_top, font=("Courier New", 10),
                                   fg=C["text"], bg=C["border"],
                                   insertbackground=C["accent"], relief="flat", width=18)
        self._manual_ip.pack(side="left", padx=6)
        for label, cmd, color in [
            ("BLOCK",   self._manual_block,   C["critical"]),
            ("ISOLATE", self._manual_isolate, C["medium"]),
        ]:
            tk.Button(right_top, text=label, font=("Courier New", 9, "bold"),
                      fg=C["bg"], bg=color, relief="flat", padx=10, pady=4,
                      cursor="hand2", command=cmd).pack(side="left", padx=3)

        # Two panels
        panels = tk.Frame(frame, bg=C["bg"])
        panels.pack(fill="both", expand=True)

        for title, attr in [("BLOCKED IPs", "_blocked_list"), ("ISOLATED IPs", "_isolated_list")]:
            pf = tk.Frame(panels, bg=C["panel"])
            pf.pack(side="left", fill="both", expand=True, padx=4)
            pf.config(highlightthickness=1, highlightbackground=C["border"])
            tk.Label(pf, text=title, font=("Courier New", 9, "bold"),
                     fg=C["critical"] if "BLOCKED" in title else C["medium"],
                     bg=C["panel"]).pack(pady=6)
            lb = tk.Listbox(pf, font=("Courier New", 10),
                            fg=C["text"], bg=C["panel2"],
                            selectbackground=C["border2"],
                            relief="flat", highlightthickness=0)
            lb.pack(fill="both", expand=True, padx=8, pady=(0, 8))
            setattr(self, attr, lb)

    def _build_tab_logs(self):
        frame = tk.Frame(self._nb, bg=C["bg"])
        self._nb.add(frame, text="  AUDIT LOG  ")

        toolbar = tk.Frame(frame, bg=C["panel2"])
        toolbar.pack(fill="x")
        toolbar.config(highlightthickness=1, highlightbackground=C["border"])
        tk.Label(toolbar, text="SYSTEM AUDIT LOG", font=("Courier New", 9, "bold"),
                 fg=C["accent"], bg=C["panel2"]).pack(side="left", padx=10, pady=6)
        tk.Button(toolbar, text="CLEAR", font=("Courier New", 8, "bold"),
                  fg=C["text2"], bg=C["panel"], relief="flat", padx=8,
                  cursor="hand2", command=self._clear_log).pack(side="right", padx=8, pady=4)

        self._log = scrolledtext.ScrolledText(
            frame, font=("Courier New", 9),
            fg=C["text2"], bg=C["bg"],
            relief="flat", wrap="word",
            state="disabled", padx=8, pady=6
        )
        self._log.pack(fill="both", expand=True)
        self._log.tag_configure("CRITICAL", foreground=C["critical"])
        self._log.tag_configure("HIGH",     foreground=C["high"])
        self._log.tag_configure("MEDIUM",   foreground=C["medium"])
        self._log.tag_configure("LOW",      foreground=C["low"])
        self._log.tag_configure("ACTION",   foreground=C["accent"])
        self._log.tag_configure("SYSTEM",   foreground=C["purple"])

    def _build_tab_report(self):
        frame = tk.Frame(self._nb, bg=C["bg"])
        self._nb.add(frame, text="  REPORT  ")

        toolbar = tk.Frame(frame, bg=C["panel2"])
        toolbar.pack(fill="x")
        toolbar.config(highlightthickness=1, highlightbackground=C["border"])
        tk.Label(toolbar, text="INCIDENT REPORT VIEWER", font=("Courier New", 9, "bold"),
                 fg=C["accent"], bg=C["panel2"]).pack(side="left", padx=10, pady=6)

        for label, cmd, color in [
            ("GENERATE", self._action_report, C["accent2"]),
            ("SAVE TXT",  self._save_txt_report, C["accent"]),
            ("SAVE JSON", self._action_export_json, C["text2"]),
        ]:
            tk.Button(toolbar, text=label, font=("Courier New", 9, "bold"),
                      fg=C["white"], bg=color, relief="flat", padx=10, pady=4,
                      cursor="hand2", command=cmd).pack(side="right", padx=4, pady=4)

        self._report_text = scrolledtext.ScrolledText(
            frame, font=("Courier New", 9),
            fg=C["text"], bg=C["bg"],
            relief="flat", wrap="none",
            state="disabled", padx=12, pady=8
        )
        self._report_text.pack(fill="both", expand=True)
        self._report_text.tag_configure("HEADER",   foreground=C["accent"],  font=("Courier New", 10, "bold"))
        self._report_text.tag_configure("CRITICAL", foreground=C["critical"])
        self._report_text.tag_configure("HIGH",     foreground=C["high"])
        self._report_text.tag_configure("SECTION",  foreground=C["accent2"])

    def _build_statusbar(self):
        bar = tk.Frame(self, bg=C["panel"], height=24)
        bar.pack(fill="x", side="bottom")
        bar.config(highlightthickness=1, highlightbackground=C["border"])
        bar.pack_propagate(False)

        self._status_bar_var = tk.StringVar(value="System ready. Start scan to begin monitoring.")
        tk.Label(bar, textvariable=self._status_bar_var,
                 font=("Courier New", 8), fg=C["text2"], bg=C["panel"]).pack(side="left", padx=10)

        self._packets_var = tk.StringVar(value="PKT: 0")
        tk.Label(bar, textvariable=self._packets_var,
                 font=("Courier New", 8), fg=C["text3"], bg=C["panel"]).pack(side="right", padx=10)

    # ─── Scanner Event Handler ─────────────────────────────────────────────────

    def _on_scanner_event(self, event_type, data):
        with self._queue_lock:
            self._event_queue.append((event_type, data))

    # ─── Main Refresh Loop ────────────────────────────────────────────────────

    def _refresh_loop(self):
        # Clock
        self._clock_var.set(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))

        # Process queue
        batch = []
        with self._queue_lock:
            batch = self._event_queue[:]
            self._event_queue.clear()

        for event_type, data in batch:
            self._process_event(event_type, data)

        # Update UI periodically
        self._update_stats_cards()
        self._update_event_tree()
        self._update_threat_chart()
        self._update_top_attackers()
        self._update_ip_lists()
        self._update_threat_meter()
        self._update_packets_bar()

        self.after(500, self._refresh_loop)

    def _process_event(self, event_type, data):
        from core.scanner import ThreatEvent
        if event_type == "NEW_EVENT" and isinstance(data, ThreatEvent):
            self._all_events_cache.append(data)
            if len(self._all_events_cache) > 2000:
                self._all_events_cache = self._all_events_cache[-2000:]
            self._log_event(data)
        elif event_type == "SCAN_STARTED":
            self._log_sys("Scan engine started. Monitoring all interfaces.")
            self._status_var.set("SCANNING")
            self._dot.set_color(C["green"])
        elif event_type == "SCAN_STOPPED":
            self._log_sys("Scan engine stopped.")
            self._status_var.set("IDLE")
            self._dot.set_color(C["text3"])
        elif event_type in ("IP_BLOCKED", "IP_ISOLATED", "IP_UNBLOCKED", "EVENT_ESCALATED"):
            self._log_action(event_type, data)

    def _log_event(self, ev):
        self._log.config(state="normal")
        ts = ev.timestamp.strftime("%H:%M:%S")
        msg = f"[{ts}] [{ev.level:<8}] {ev.source_ip:<18} → {ev.dest_ip:<18} | {ev.threat_label}\n"
        self._log.insert("end", msg, ev.level)
        self._log.see("end")
        self._log.config(state="disabled")

    def _log_sys(self, msg):
        self._log.config(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self._log.insert("end", f"[{ts}] [SYSTEM  ] {msg}\n", "SYSTEM")
        self._log.see("end")
        self._log.config(state="disabled")

    def _log_action(self, action_type, data):
        self._log.config(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        if action_type == "IP_BLOCKED":
            msg = f"[{ts}] [ACTION  ] IP BLOCKED: {data.get('ip')}\n"
        elif action_type == "IP_ISOLATED":
            msg = f"[{ts}] [ACTION  ] IP ISOLATED: {data.get('ip')}\n"
        elif action_type == "IP_UNBLOCKED":
            msg = f"[{ts}] [ACTION  ] IP UNBLOCKED: {data.get('ip')}\n"
        elif action_type == "EVENT_ESCALATED":
            from core.scanner import ThreatEvent
            msg = f"[{ts}] [ACTION  ] EVENT ESCALATED: {data.event_id if isinstance(data, ThreatEvent) else data}\n"
        else:
            msg = f"[{ts}] [ACTION  ] {action_type}: {data}\n"
        self._log.insert("end", msg, "ACTION")
        self._log.see("end")
        self._log.config(state="disabled")

    def _clear_log(self):
        self._log.config(state="normal")
        self._log.delete("1.0", "end")
        self._log.config(state="disabled")

    # ─── UI Updates ───────────────────────────────────────────────────────────

    def _update_stats_cards(self):
        s = self.scanner.stats
        self._stats["CRITICAL"].set(s.get("critical", 0))
        self._stats["HIGH"].set(s.get("high", 0))
        self._stats["MEDIUM"].set(s.get("medium", 0))
        self._stats["LOW"].set(s.get("low", 0))
        self._stats["TOTAL"].set(s.get("total_events", 0))
        self._stats["BLOCKED"].set(s.get("blocked", 0))

    def _apply_filter(self):
        pass  # Triggered on next refresh

    def _update_event_tree(self):
        lvl = self._filter_var.get()
        ip_f = self._ip_filter.get().strip()

        evs = self._all_events_cache[:]
        if lvl != "ALL":
            evs = [e for e in evs if e.level == lvl]
        if ip_f:
            evs = [e for e in evs if ip_f in e.source_ip or ip_f in e.dest_ip]

        evs = evs[-100:]  # Show last 100

        if evs == self._displayed_events:
            return

        # Preserve selection
        sel = self._tree.selection()
        sel_id = self._tree.item(sel[0])["values"][0] if sel else None

        self._tree.delete(*self._tree.get_children())
        for ev in reversed(evs):
            tag = ev.status if ev.status in ("BLOCKED", "ESCALATED") else ev.level
            vals = (
                ev.timestamp.strftime("%H:%M:%S.%f")[:12],
                ev.level,
                ev.source_ip,
                ev.dest_ip,
                ev.threat_label[:28],
                ev.protocol,
                ev.status,
                f"{ev.confidence*100:.0f}%",
            )
            iid = self._tree.insert("", "end", values=vals, tags=(tag,))

        self._displayed_events = evs
        self._event_count_var.set(f"Events: {len(self._all_events_cache):,}")

    def _update_threat_chart(self):
        c = self._dist_canvas
        c.delete("all")
        w = c.winfo_width()
        h = c.winfo_height()
        if w < 10 or h < 10:
            return

        dist = defaultdict(int)
        for ev in self._all_events_cache:
            dist[ev.level] += 1
        total = sum(dist.values()) or 1

        levels_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        bar_h = min(40, (h - 80) // len(levels_order))
        y = 30

        c.create_text(w // 2, 12, text="REAL-TIME THREAT DISTRIBUTION",
                      fill=C["text2"], font=("Courier New", 8, "bold"))

        for lvl in levels_order:
            count = dist.get(lvl, 0)
            pct = count / total
            color = LEVEL_COLOR[lvl]
            bar_w = int((w - 180) * pct)
            label_x = 90
            c.create_text(label_x - 4, y + bar_h // 2, text=f"{lvl:<8}",
                          fill=color, font=("Courier New", 8, "bold"), anchor="e")
            c.create_rectangle(label_x, y, w - 80, y + bar_h,
                                fill=C["border"], outline="")
            if bar_w > 0:
                c.create_rectangle(label_x, y, label_x + bar_w, y + bar_h,
                                    fill=color, outline="")
            c.create_text(w - 76, y + bar_h // 2,
                          text=f"{count:4d} ({pct*100:.0f}%)",
                          fill=C["text2"], font=("Courier New", 8), anchor="w")
            y += bar_h + 10

        # Donut-ish ring
        cx, cy, r = w - 80, h // 2, min(60, h // 4)
        start = -90
        for lvl in levels_order:
            count = dist.get(lvl, 0)
            extent = (count / total) * 360
            if extent > 0:
                c.create_arc(cx - r, cy - r, cx + r, cy + r,
                             start=start, extent=extent,
                             fill=LEVEL_COLOR[lvl], outline=C["bg"], width=2)
                start += extent
        # Inner circle (donut hole)
        r2 = r * 0.55
        c.create_oval(cx - r2, cy - r2, cx + r2, cy + r2,
                      fill=C["panel"], outline="")
        c.create_text(cx, cy, text=str(sum(dist.values())),
                      fill=C["accent"], font=("Courier New", 10, "bold"))
        c.create_text(cx, cy + 14, text="TOTAL",
                      fill=C["text3"], font=("Courier New", 7))

    def _update_top_attackers(self):
        for w in self._attacker_frame.winfo_children():
            w.destroy()

        attackers = self.scanner.get_top_attackers(8)
        if not attackers:
            tk.Label(self._attacker_frame, text="No data yet",
                     font=("Courier New", 9), fg=C["text3"],
                     bg=C["panel"]).pack(pady=20)
            return

        max_count = attackers[0][1] if attackers else 1

        for i, (ip, cnt) in enumerate(attackers):
            row = tk.Frame(self._attacker_frame, bg=C["panel"])
            row.pack(fill="x", pady=2)

            color = C["critical"] if ip in self.scanner.blocked_ips else \
                    C["medium"] if ip in self.scanner.isolated_ips else C["text"]

            tk.Label(row, text=f"{i+1}.", font=("Courier New", 8),
                     fg=C["text3"], bg=C["panel"], width=2).pack(side="left")
            tk.Label(row, text=ip, font=("Courier New", 9, "bold"),
                     fg=color, bg=C["panel"], width=16, anchor="w").pack(side="left")

            bar_frame = tk.Frame(row, bg=C["panel"])
            bar_frame.pack(side="left", fill="x", expand=True, padx=4)
            bar_bg = tk.Canvas(bar_frame, height=14, bg=C["border"],
                               highlightthickness=0)
            bar_bg.pack(fill="x")
            bar_bg.update_idletasks()
            bw = bar_bg.winfo_width() or 100
            fill_w = int(bw * cnt / max_count)
            bar_bg.create_rectangle(0, 0, fill_w, 14, fill=color, outline="")

            tk.Label(row, text=str(cnt), font=("Courier New", 8),
                     fg=C["text2"], bg=C["panel"], width=5).pack(side="right")

    def _update_ip_lists(self):
        self._blocked_list.delete(0, "end")
        for ip in sorted(self.scanner.blocked_ips):
            self._blocked_list.insert("end", f"  {ip}")
        self._blocked_list.config(fg=C["critical"])

        self._isolated_list.delete(0, "end")
        for ip in sorted(self.scanner.isolated_ips):
            self._isolated_list.insert("end", f"  {ip}")
        self._isolated_list.config(fg=C["medium"])

    def _update_threat_meter(self):
        s = self.scanner.stats
        total = s.get("total_events", 0) or 1
        critical = s.get("critical", 0)
        high = s.get("high", 0)
        pct = min(100, (critical * 4 + high * 2) / total * 25)
        self.after(10, lambda: self._draw_threat_meter(pct))

    def _update_packets_bar(self):
        s = self.scanner.stats
        pkt = s.get("packets_analyzed", 0)
        byt = s.get("bytes_analyzed", 0)
        self._packets_var.set(f"PKT: {pkt:,}  |  DATA: {human_bytes(byt)}")
        if self.scanner.running:
            self._status_bar_var.set(
                f"Monitoring active — {s.get('total_events', 0):,} events | "
                f"{len(self.scanner.blocked_ips)} blocked | {len(self.scanner.isolated_ips)} isolated"
            )

    # ─── Actions ──────────────────────────────────────────────────────────────

    def _toggle_scan(self):
        if self.scanner.running:
            self.scanner.stop_scan()
            self._scan_btn.config(text="▶  START SCAN", bg=C["green"])
        else:
            self.scanner.start_scan()
            self._scan_btn.config(text="⏹  STOP SCAN", bg=C["red"])

    def _get_selected_event(self):
        sel = self._tree.selection()
        if not sel:
            return None
        vals = self._tree.item(sel[0])["values"]
        # Find by matching timestamp and src ip
        for ev in reversed(self._all_events_cache):
            ts = ev.timestamp.strftime("%H:%M:%S.%f")[:12]
            if ts == vals[0] and ev.source_ip == vals[2]:
                return ev
        return None

    def _on_event_select(self, event):
        ev = self._get_selected_event()
        if not ev:
            return
        self._selected_event = ev
        self._selected_ip = ev.source_ip

        # Update info panel
        info = (
            f"ID: {ev.event_id}\n"
            f"Level: {ev.level}\n"
            f"Threat: {ev.threat_label}\n"
            f"Src: {ev.source_ip}:{ev.source_port}\n"
            f"Dst: {ev.dest_ip}:{ev.dest_port}\n"
            f"Proto: {ev.protocol}\n"
            f"Country: {ev.country}\n"
            f"Conf: {ev.confidence*100:.0f}%\n"
            f"MITRE: {ev.mitre_tactic}\n"
            f"Status: {ev.status}\n"
            f"Pkts: {ev.packets:,}\n"
            f"Data: {human_bytes(ev.bytes_transferred)}"
        )
        self._sel_info.config(state="normal")
        self._sel_info.delete("1.0", "end")
        self._sel_info.insert("1.0", info)
        self._sel_info.config(state="disabled")

    def _context_menu(self, event):
        ev = self._get_selected_event()
        if not ev:
            return
        menu = tk.Menu(self, tearoff=0, bg=C["panel"], fg=C["text"],
                       activebackground=C["border2"], activeforeground=C["accent"],
                       font=("Courier New", 9))
        menu.add_command(label=f"🚨 Escalate {ev.event_id}", command=self._action_escalate)
        menu.add_command(label=f"🔒 Isolate {ev.source_ip}", command=self._action_isolate)
        menu.add_command(label=f"🚫 Block {ev.source_ip}", command=self._action_block)
        menu.add_separator()
        menu.add_command(label="📋 Copy Source IP",
                         command=lambda: (self.clipboard_clear(), self.clipboard_append(ev.source_ip)))
        menu.post(event.x_root, event.y_root)

    def _action_escalate(self):
        ev = self._selected_event
        if not ev:
            messagebox.showwarning("No Selection", "Select an event first.", parent=self)
            return
        result = self.scanner.escalate_event(ev.event_id)
        if result["success"]:
            self._show_toast(f"🚨 Event {ev.event_id} escalated to IR Team")
            self._status_bar_var.set(f"ESCALATED: {ev.event_id} — {ev.threat_label}")
        else:
            messagebox.showerror("Error", result.get("error", "Unknown error"), parent=self)

    def _action_isolate(self):
        ip = self._selected_ip
        if not ip:
            messagebox.showwarning("No Selection", "Select an event to get source IP.", parent=self)
            return
        if messagebox.askyesno("Isolate IP",
                               f"Isolate {ip}?\nThis will quarantine the host from network access.",
                               parent=self):
            self.scanner.isolate_ip(ip)
            self._show_toast(f"🔒 IP Isolated: {ip}")
            self._nb.select(2)  # Switch to network tab

    def _action_block(self):
        ip = self._selected_ip
        if not ip:
            messagebox.showwarning("No Selection", "Select an event to get source IP.", parent=self)
            return
        if messagebox.askyesno("Block IP",
                               f"Block {ip}?\nAll traffic from this IP will be dropped.",
                               parent=self):
            self.scanner.block_ip(ip)
            self._show_toast(f"🚫 IP Blocked: {ip}")
            self._nb.select(2)

    def _manual_block(self):
        ip = self._manual_ip.get().strip()
        if not ip:
            return
        self.scanner.block_ip(ip)
        self._show_toast(f"🚫 IP Blocked: {ip}")
        self._manual_ip.delete(0, "end")

    def _manual_isolate(self):
        ip = self._manual_ip.get().strip()
        if not ip:
            return
        self.scanner.isolate_ip(ip)
        self._show_toast(f"🔒 IP Isolated: {ip}")
        self._manual_ip.delete(0, "end")

    def _action_unblock(self):
        ip = self._selected_ip or self._manual_ip.get().strip()
        if not ip:
            messagebox.showwarning("No IP", "Select an event or enter an IP.", parent=self)
            return
        self.scanner.unblock_ip(ip)
        self._show_toast(f"🔓 IP Unblocked: {ip}")

    def _action_report(self):
        report = self.scanner.generate_report()
        text = generate_text_report(report)
        self._report_text.config(state="normal")
        self._report_text.delete("1.0", "end")
        # Insert with basic highlighting
        for line in text.split("\n"):
            if "═" in line or "╔" in line or "╚" in line or "║" in line:
                self._report_text.insert("end", line + "\n", "HEADER")
            elif "[CRITICAL]" in line or "CRITICAL" in line.upper() and ":" in line:
                self._report_text.insert("end", line + "\n", "CRITICAL")
            elif "[HIGH]" in line:
                self._report_text.insert("end", line + "\n", "HIGH")
            elif "▶" in line:
                self._report_text.insert("end", line + "\n", "SECTION")
            else:
                self._report_text.insert("end", line + "\n")
        self._report_text.config(state="disabled")
        self._nb.select(4)
        self._show_toast("📄 Report generated")

    def _save_txt_report(self):
        report = self.scanner.generate_report()
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"sentinel_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            parent=self
        )
        if path:
            generate_text_report(report, path)
            self._show_toast(f"📄 Report saved: {os.path.basename(path)}")

    def _action_export_json(self):
        report = self.scanner.generate_report()
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"sentinel_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            parent=self
        )
        if path:
            save_json_report(report, path)
            self._show_toast(f"📊 JSON exported: {os.path.basename(path)}")

    def _action_deep_scan(self):
        if not self.scanner.running:
            messagebox.showinfo("Deep Scan", "Start the scanner first.", parent=self)
            return
        self._show_toast("🔍 Deep scan initiated — increasing sensitivity")
        self._status_bar_var.set("DEEP SCAN ACTIVE — Enhanced threat detection running")
        # Simulate increased event rate briefly
        def burst():
            for _ in range(15):
                ev = self.scanner._generate_event()
                if ev:
                    with self._queue_lock:
                        from core.scanner import ThreatEvent
                        self._event_queue.append(("NEW_EVENT", ev))
                    self.scanner.events.append(ev)
                    self.scanner._update_stats(ev)
                time.sleep(0.1)
        threading.Thread(target=burst, daemon=True).start()

    def _show_toast(self, msg):
        self._status_bar_var.set(msg)
        # Fade back after 3 seconds
        self.after(3000, lambda: self._status_bar_var.set(
            "Monitoring active — use actions panel to respond to threats"
        ))


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    app = SentinelApp()
    app.mainloop()


if __name__ == "__main__":
    main()
