import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
import threading

import monitor
from responder import kill_flagged
from utils import save_report
from dir_scanner import scan_directory
from signatures import load_signatures
from config import WEB_DASHBOARD_PORT

# ── Palette ────────────────────────────────────────────────────────────────
BG       = "#0d0f14"
PANEL    = "#13161e"
BORDER   = "#1e2330"
ACCENT   = "#00e5ff"
TEXT     = "#c8d6e5"
MUTED    = "#4a5568"
SAFE     = "#00e676"
WARN     = "#ffab00"
DANGER   = "#ff1744"
FONT_H   = ("Courier New", 11)
FONT_SM  = ("Courier New", 9)

VERDICT_COLORS = {
    "SAFE":       SAFE,
    "SUSPICIOUS": WARN,
    "MALICIOUS":  DANGER,
    "IDLE":       MUTED,
}


class Dashboard:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Cyber Sentinel AV")
        self.root.geometry("980x720")
        self.root.configure(bg=BG)
        self.root.resizable(True, True)

        self._last_result = None
        self._scan_count = 0

        self._build_ui()

    # ── UI Construction ────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Title bar ──
        title_frame = tk.Frame(self.root, bg=BG)
        title_frame.pack(fill=tk.X, padx=20, pady=(18, 6))

        tk.Label(
            title_frame, text="◈ CYBER SENTINEL", font=("Courier New", 18, "bold"),
            fg=ACCENT, bg=BG
        ).pack(side=tk.LEFT)

        tk.Label(
            title_frame,
            text=f"Dashboard → http://localhost:{WEB_DASHBOARD_PORT}",
            font=FONT_SM, fg=MUTED, bg=BG
        ).pack(side=tk.LEFT, padx=20)

        self.clock_label = tk.Label(title_frame, text="", font=FONT_SM, fg=MUTED, bg=BG)
        self.clock_label.pack(side=tk.RIGHT)
        self._tick_clock()

        # ── Status row ──
        status_frame = tk.Frame(self.root, bg=PANEL, highlightbackground=BORDER,
                                highlightthickness=1)
        status_frame.pack(fill=tk.X, padx=20, pady=6)

        inner = tk.Frame(status_frame, bg=PANEL)
        inner.pack(fill=tk.X, padx=16, pady=12)

        badge_frame = tk.Frame(inner, bg=PANEL)
        badge_frame.pack(side=tk.LEFT)
        tk.Label(badge_frame, text="VERDICT", font=("Courier New", 8), fg=MUTED, bg=PANEL).pack(anchor="w")
        self.verdict_label = tk.Label(
            badge_frame, text="● IDLE", font=("Courier New", 20, "bold"),
            fg=MUTED, bg=PANEL
        )
        self.verdict_label.pack(anchor="w")

        tk.Frame(inner, bg=PANEL, width=40).pack(side=tk.LEFT)

        gauge_frame = tk.Frame(inner, bg=PANEL)
        gauge_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        score_row = tk.Frame(gauge_frame, bg=PANEL)
        score_row.pack(fill=tk.X)
        tk.Label(score_row, text="RISK SCORE", font=("Courier New", 8), fg=MUTED, bg=PANEL).pack(side=tk.LEFT)
        self.score_num = tk.Label(score_row, text="0 / 100", font=FONT_H, fg=TEXT, bg=PANEL)
        self.score_num.pack(side=tk.RIGHT)

        self.progress = ttk.Progressbar(gauge_frame, length=400, mode='determinate', maximum=100)
        self.progress.pack(fill=tk.X, pady=(4, 0))
        self._style_progressbar(MUTED)

        stats_frame = tk.Frame(inner, bg=PANEL)
        stats_frame.pack(side=tk.RIGHT, padx=(30, 0))
        self.scans_label   = tk.Label(stats_frame, text="Scans: 0",      font=FONT_SM, fg=MUTED, bg=PANEL)
        self.procs_label   = tk.Label(stats_frame, text="Processes: —",  font=FONT_SM, fg=MUTED, bg=PANEL)
        self.flagged_label = tk.Label(stats_frame, text="Flagged: 0",    font=FONT_SM, fg=MUTED, bg=PANEL)
        for lbl in (self.scans_label, self.procs_label, self.flagged_label):
            lbl.pack(anchor="e")

        # ── Findings + Log ──
        pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, bg=BG,
                              sashwidth=4, sashrelief=tk.FLAT)
        pane.pack(fill=tk.BOTH, expand=True, padx=20, pady=6)

        left = tk.Frame(pane, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        pane.add(left, minsize=280)

        tk.Label(left, text="FINDINGS", font=("Courier New", 9, "bold"),
                 fg=ACCENT, bg=PANEL).pack(anchor="w", padx=10, pady=(8, 4))

        find_scroll = tk.Scrollbar(left, bg=PANEL)
        find_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.findings_list = tk.Listbox(
            left, bg=PANEL, fg=TEXT, font=FONT_SM,
            selectbackground=BORDER, activestyle="none",
            relief=tk.FLAT, bd=0,
            yscrollcommand=find_scroll.set,
            highlightthickness=0,
        )
        self.findings_list.pack(fill=tk.BOTH, expand=True, padx=(10, 0))
        find_scroll.config(command=self.findings_list.yview)

        right = tk.Frame(pane, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        pane.add(right, minsize=300)

        tk.Label(right, text="SCAN LOG", font=("Courier New", 9, "bold"),
                 fg=ACCENT, bg=PANEL).pack(anchor="w", padx=10, pady=(8, 4))

        log_scroll = tk.Scrollbar(right, bg=PANEL)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.log = tk.Text(
            right, bg=PANEL, fg=TEXT, font=FONT_SM,
            insertbackground=ACCENT, relief=tk.FLAT, bd=0,
            state=tk.DISABLED, yscrollcommand=log_scroll.set,
            highlightthickness=0,
        )
        self.log.pack(fill=tk.BOTH, expand=True, padx=(10, 0), pady=(0, 8))
        log_scroll.config(command=self.log.yview)

        self.log.tag_config("safe",   foreground=SAFE)
        self.log.tag_config("warn",   foreground=WARN)
        self.log.tag_config("danger", foreground=DANGER)
        self.log.tag_config("muted",  foreground=MUTED)
        self.log.tag_config("accent", foreground=ACCENT)

        # ── Button bar ──
        btn_frame = tk.Frame(self.root, bg=BG)
        btn_frame.pack(fill=tk.X, padx=20, pady=(4, 14))

        btn_cfg = dict(font=("Courier New", 9, "bold"), relief=tk.FLAT,
                       bd=0, padx=16, pady=7, cursor="hand2")

        self.start_btn = tk.Button(
            btn_frame, text="▶  START", bg=ACCENT, fg=BG,
            command=self._on_start, **btn_cfg
        )
        self.start_btn.pack(side=tk.LEFT, padx=(0, 8))

        self.stop_btn = tk.Button(
            btn_frame, text="■  STOP", bg=BORDER, fg=MUTED,
            command=self._on_stop, state=tk.DISABLED, **btn_cfg
        )
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 8))

        self.kill_btn = tk.Button(
            btn_frame, text="☠  KILL FLAGGED", bg=DANGER, fg="white",
            command=self._on_kill, state=tk.DISABLED, **btn_cfg
        )
        self.kill_btn.pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            btn_frame, text="📁  SCAN DIR", bg=BORDER, fg=TEXT,
            command=self._on_scan_dir, **btn_cfg
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            btn_frame, text="💾  SAVE REPORT", bg=BORDER, fg=TEXT,
            command=self._on_save, **btn_cfg
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            btn_frame, text="🗑  CLEAR LOG", bg=BORDER, fg=TEXT,
            command=self._clear_log, **btn_cfg
        ).pack(side=tk.LEFT)

    # ── Clock ──────────────────────────────────────────────────────────────

    def _tick_clock(self):
        self.clock_label.config(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.root.after(1000, self._tick_clock)

    # ── Progressbar colour helper ──────────────────────────────────────────

    def _style_progressbar(self, color: str):
        style = ttk.Style(self.root)
        style.theme_use("default")
        style.configure("Sentinel.Horizontal.TProgressbar",
                        troughcolor=BORDER, background=color, thickness=8)
        self.progress.configure(style="Sentinel.Horizontal.TProgressbar")

    # ── Event handlers ─────────────────────────────────────────────────────

    def _on_start(self):
        monitor.start_monitoring(self.update_ui, root=self.root)
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL, bg=WARN, fg=BG)
        self._log_line("Monitoring started.", "accent")

    def _on_stop(self):
        monitor.stop_monitoring()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED, bg=BORDER, fg=MUTED)
        self.verdict_label.config(text="● IDLE", fg=MUTED)
        self._style_progressbar(MUTED)
        self._log_line("Monitoring stopped.", "muted")

    def _on_kill(self):
        if not self._last_result:
            return
        pids = self._last_result.get("flagged_pids", [])
        if not pids:
            messagebox.showinfo("Kill Flagged", "No flagged processes to terminate.")
            return
        if messagebox.askyesno("Confirm", f"Terminate {len(pids)} flagged process(es)?"):
            killed = kill_flagged(pids)
            self._log_line(f"Terminated {len(killed)} process(es).", "danger")

    def _on_scan_dir(self):
        directory = filedialog.askdirectory(title="Select Directory to Scan")
        if not directory:
            return
        self._log_line(f"Directory scan started: {directory}", "accent")

        def run():
            sigs = load_signatures()
            known_hashes = set(sigs.get("hashes", []))
            findings = scan_directory(directory, known_hashes)
            def update():
                if findings:
                    for item in findings:
                        self._log_line(f"🚨 Hash match: {item['path']}", "danger")
                        self.findings_list.insert(tk.END, f"  🚨 {item['path']}")
                        self.findings_list.itemconfig(self.findings_list.size() - 1, fg=DANGER)
                else:
                    self._log_line("✔ Directory scan complete — no matches found.", "safe")
            self.root.after(0, update)

        threading.Thread(target=run, daemon=True).start()

    def _on_save(self):
        if self._last_result:
            save_report(self._last_result)
            self._log_line("Report saved to report.json", "accent")
        else:
            messagebox.showinfo("Save Report", "No scan data yet.")

    def _clear_log(self):
        self.log.config(state=tk.NORMAL)
        self.log.delete("1.0", tk.END)
        self.log.config(state=tk.DISABLED)

    # ── UI update ──────────────────────────────────────────────────────────

    def update_ui(self, result: dict):
        self._last_result = result
        self._scan_count += 1

        verdict  = result.get("verdict", "SAFE")
        score    = result.get("score", 0)
        findings = result.get("findings", [])
        total    = result.get("total_processes", 0)
        flagged  = len(result.get("flagged_pids", []))

        color = VERDICT_COLORS.get(verdict, TEXT)

        self.verdict_label.config(text=f"● {verdict}", fg=color)
        self.score_num.config(text=f"{score} / 100", fg=color)
        self.progress["value"] = score
        self._style_progressbar(color)

        self.scans_label.config(text=f"Scans: {self._scan_count}")
        self.procs_label.config(text=f"Processes: {total}")
        self.flagged_label.config(text=f"Flagged: {flagged}", fg=color if flagged else MUTED)

        self.kill_btn.config(state=tk.NORMAL if flagged else tk.DISABLED)

        self.findings_list.delete(0, tk.END)
        if findings:
            for f in findings:
                self.findings_list.insert(tk.END, f"  {f}")
                idx = self.findings_list.size() - 1
                row_color = DANGER if "🚨" in f else WARN
                self.findings_list.itemconfig(idx, fg=row_color)
        else:
            self.findings_list.insert(tk.END, "  ✔  No threats detected")
            self.findings_list.itemconfig(0, fg=SAFE)

        ts = datetime.now().strftime("%H:%M:%S")
        tag = {"SAFE": "safe", "SUSPICIOUS": "warn", "MALICIOUS": "danger"}.get(verdict, "muted")
        self._log_line(
            f"[{ts}] {verdict} | Score {score} | {total} procs | {flagged} flagged", tag
        )
        for f in findings:
            self._log_line(f"  {f}", "warn" if "⚠" in f else "danger")

    # ── Helpers ────────────────────────────────────────────────────────────

    def _log_line(self, text: str, tag: str = ""):
        self.log.config(state=tk.NORMAL)
        if tag:
            self.log.insert(tk.END, text + "\n", tag)
        else:
            self.log.insert(tk.END, text + "\n")
        self.log.see(tk.END)
        self.log.config(state=tk.DISABLED)

    def run(self):
        self.root.mainloop()
