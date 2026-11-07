"""
MECHCARE — Mechanical Asset Health & Maintenance Manager  (Mechanical Edition)
Single-file desktop application. CSV files are the persistent data store.

Run:
    python main.py

Optional enhancements:
    pip install matplotlib pillow
PDF export additionally supports:
    pip install reportlab

On first launch, the app creates CSV files if absent and asks you to create
the initial administrator account. Existing CSV rows are preserved; new
columns are appended only when required.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import math
import re
import os
import secrets
import shutil
import sys
import traceback
from datetime import datetime, timedelta
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

APP_NAME = "MECHCARE"
APP_VERSION = "1.0.0"
BASE_DIR = Path(__file__).resolve().parent
MACHINES_FILE = BASE_DIR / "machines.csv"
INSPECTIONS_FILE = BASE_DIR / "inspection_log.csv"
USERS_FILE = BASE_DIR / "users.csv"
AUDIT_FILE = BASE_DIR / "audit_log.csv"
MAINTENANCE_FILE = BASE_DIR / "maintenance.csv"
SETTINGS_FILE = BASE_DIR / "settings.csv"
STAFF_FILE = BASE_DIR / "staff.csv"
ATTENDANCE_FILE = BASE_DIR / "staff_attendance.csv"
PERFORMANCE_FILE = BASE_DIR / "staff_performance.csv"
BACKUP_DIR = BASE_DIR / "backups"

NAVY = "#0F1318"       # carbon black
PANEL = "#1A2027"      # gunmetal
PANEL2 = "#252C35"     # steel panel
BLUE = "#F26B1D"       # primary accent: safety orange
CYAN = "#FFB22E"       # secondary accent: hazard yellow
TEXT = "#EEF1F5"
MUTED = "#8E9AAA"
GREEN = "#3DDC84"
AMBER = "#FFC247"
RED = "#FF4D4D"
BORDER = "#38414D"
SIDEBAR = "#0B0E12"
STEEL = "#5B6675"
SELECT = "#5A3512"

MACHINE_DEFAULTS = ["ID", "Name", "Location", "Category", "Status"]
INSPECTION_DEFAULTS = [
    "Date", "Machine ID", "Temperature", "Vibration", "Hours", "Status", "Advice"
]
USER_FIELDS = ["Username", "PasswordHash", "Salt", "Role", "CreatedAt", "Active"]
AUDIT_FIELDS = ["Timestamp", "Username", "Action", "Details"]
MAINT_FIELDS = ["ID", "Machine ID", "Due Date", "Task", "Priority", "Status", "Created By"]
SETTINGS_FIELDS = ["Key", "Value"]
STAFF_FIELDS = ["Staff ID", "Name", "Department", "Designation", "Phone", "Status", "Joined Date"]
ATTENDANCE_FIELDS = ["Date", "Staff ID", "Staff Name", "Status", "Check In", "Check Out", "Notes", "Recorded By"]
PERFORMANCE_FIELDS = ["Date", "Staff ID", "Staff Name", "Metric", "Score", "Reviewer", "Comments"]


def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def safe_float(value, default=0.0):
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def ensure_csv(path: Path, headers):
    """Create a missing CSV, or append missing columns without discarding data."""
    if not path.exists() or path.stat().st_size == 0:
        with path.open("w", newline="", encoding="utf-8-sig") as f:
            csv.DictWriter(f, fieldnames=headers).writeheader()
        return
    try:
        with path.open("r", newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            old_headers = reader.fieldnames or []
            rows = list(reader)
        additions = [h for h in headers if h not in old_headers]
        if additions:
            merged = old_headers + additions
            temp = path.with_suffix(path.suffix + ".tmp")
            with temp.open("w", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=merged)
                writer.writeheader()
                for row in rows:
                    writer.writerow({k: row.get(k, "") for k in merged})
            temp.replace(path)
    except (OSError, csv.Error) as exc:
        raise RuntimeError(f"Could not prepare {path.name}: {exc}") from exc


def read_rows(path: Path):
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def write_rows(path: Path, rows, preferred_headers=None):
    """Atomic CSV write. Existing columns are retained and new keys appended."""
    old_headers = []
    if path.exists() and path.stat().st_size:
        with path.open("r", newline="", encoding="utf-8-sig") as f:
            old_headers = csv.DictReader(f).fieldnames or []
    keys = list(old_headers)
    for key in (preferred_headers or []):
        if key not in keys:
            keys.append(key)
    for row in rows:
        for key in row:
            if key not in keys:
                keys.append(key)
    if not keys:
        keys = list(preferred_headers or [])
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temp.replace(path)


def append_row(path: Path, row, headers):
    ensure_csv(path, headers)
    with path.open("a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        writer.writerow(row)


def password_hash(password: str, salt_hex=None):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
    return digest.hex(), salt.hex()


def verify_password(password, salt_hex, expected):
    actual, _ = password_hash(password, salt_hex)
    return hmac.compare_digest(actual, expected)


def analyze_machine(temperature, vibration, hours, history=None):
    """
    Transparent rule-based condition score, not an AI/ML prediction.
    Thresholds are configurable in this function for the machine type/site.
    """
    temp = safe_float(temperature)
    vib = safe_float(vibration)
    run_hours = safe_float(hours)
    score = 100.0
    reasons = []

    if temp >= 95:
        score -= 42
        reasons.append("Very high temperature")
    elif temp >= 80:
        score -= 25
        reasons.append("Elevated temperature")
    elif temp >= 70:
        score -= 10
        reasons.append("Temperature approaching alert threshold")

    if vib >= 10:
        score -= 42
        reasons.append("Severe vibration")
    elif vib >= 7:
        score -= 25
        reasons.append("High vibration")
    elif vib >= 5:
        score -= 10
        reasons.append("Vibration above normal watch level")

    if run_hours >= 10000:
        score -= 18
        reasons.append("High accumulated operating hours")
    elif run_hours >= 5000:
        score -= 8
        reasons.append("Accumulated operating hours require review")

    if history:
        recent = history[-5:]
        if len(recent) >= 2:
            temps = [safe_float(x.get("Temperature")) for x in recent]
            vibs = [safe_float(x.get("Vibration")) for x in recent]
            if temps[-1] > temps[0] + 10:
                score -= 5
                reasons.append("Temperature has increased across recent inspections")
            if vibs[-1] > vibs[0] + 2:
                score -= 5
                reasons.append("Vibration has increased across recent inspections")

    score = max(0, min(100, round(score)))
    if score >= 85:
        risk, status, priority = "LOW", "HEALTHY", "ROUTINE"
        advice = "Continue routine monitoring and follow the planned inspection interval."
    elif score >= 65:
        risk, status, priority = "MODERATE", "WATCH", "MEDIUM"
        advice = "Schedule a detailed inspection and review operating conditions."
    elif score >= 40:
        risk, status, priority = "HIGH", "WARNING", "HIGH"
        advice = "Plan maintenance promptly; inspect bearings, alignment and cooling."
    else:
        risk, status, priority = "CRITICAL", "CRITICAL", "URGENT"
        advice = "Escalate to qualified maintenance personnel and assess safe operation."
    if reasons:
        advice += " Indicators: " + "; ".join(reasons) + "."
    return {"score": score, "risk": risk, "status": status,
            "priority": priority, "advice": advice, "reasons": reasons}



# ======================================================================
# MECHANICAL UI TOOLKIT — gears, piston engine, gauge, hazard stripes, LEDs
# All artwork is drawn in code (no image files needed) and animated.
# ======================================================================
def loop(widget, ms, fn):
    """Run fn every ms while the widget exists. fn may return False to stop."""
    def run():
        try:
            if not widget.winfo_exists():
                return
            if fn() is False:
                return
            widget.after(ms, run)
        except tk.TclError:
            return
    widget.after(ms, run)


def count_up(label, text):
    m = re.fullmatch(r"(\d+)(%?)", str(text))
    if not m:
        label.configure(text=str(text)); return
    end, suffix, state, steps = int(m.group(1)), m.group(2), {"i": 0}, 18
    label.configure(text=f"0{suffix}")
    def tick():
        state["i"] += 1
        t = min(1, state["i"] / steps)
        label.configure(text=f"{round(end * (1 - (1 - t) ** 3))}{suffix}")
        return state["i"] < steps
    loop(label, 28, tick)


def gear_polygon(cx, cy, r, teeth, rot):
    pts, step = [], 2 * math.pi / teeth
    for i in range(teeth):
        a = rot + i * step
        for frac, rad in ((0.0, r * 0.82), (0.12, r), (0.50, r), (0.62, r * 0.82)):
            ang = a + frac * step
            pts.extend((cx + rad * math.cos(ang), cy + rad * math.sin(ang)))
    return pts


class Gear:
    def __init__(self, canvas, cx, cy, r, teeth, speed, fill, outline, hole):
        self.c, self.cx, self.cy, self.r = canvas, cx, cy, r
        self.teeth, self.speed, self.rot = teeth, speed, 0.0
        self.body = canvas.create_polygon(gear_polygon(cx, cy, r, teeth, 0), fill=fill, outline=outline, width=2)
        self.ring = canvas.create_oval(cx - r * .62, cy - r * .62, cx + r * .62, cy + r * .62,
                                       outline=outline, width=2)
        self.spokes = [canvas.create_line(cx, cy, cx, cy, fill=outline, width=3) for _ in range(5)]
        self.hub = canvas.create_oval(cx - r * .22, cy - r * .22, cx + r * .22, cy + r * .22,
                                      fill=outline, outline="")
        self.hole = canvas.create_oval(cx - r * .09, cy - r * .09, cx + r * .09, cy + r * .09,
                                       fill=hole, outline="")
        self.draw()

    def draw(self):
        self.c.coords(self.body, *gear_polygon(self.cx, self.cy, self.r, self.teeth, self.rot))
        for k, s in enumerate(self.spokes):
            a = self.rot + k * 2 * math.pi / 5
            self.c.coords(s, self.cx, self.cy, self.cx + self.r * .62 * math.cos(a),
                          self.cy + self.r * .62 * math.sin(a))

    def step(self, d=1):
        self.rot += self.speed * d
        self.draw()


class Engine:
    """Animated single-cylinder piston engine: flywheel, crank, rod, piston, spark."""
    def __init__(self, canvas, ex, ey, cr=24, L=72, bg=SIDEBAR):
        c = self.c = canvas
        self.ex, self.ey, self.cr, self.L, self.theta = ex, ey, cr, L, 0.0
        top = self.top = ey - cr - L - 34
        c.create_rectangle(ex - 28, top, ex + 28, ey + cr - L + 30, fill="#141A20", outline=STEEL, width=2)
        for i in range(5):
            y = top + 8 + i * 9
            c.create_line(ex - 36, y, ex - 28, y, fill=STEEL, width=3)
            c.create_line(ex + 28, y, ex + 36, y, fill=STEEL, width=3)
        self.spark = c.create_oval(ex - 9, top + 3, ex + 9, top + 21, fill=BLUE, outline=CYAN, width=2)
        self.fly = Gear(c, ex, ey, cr + 24, 12, 0, "#1E242C", BLUE, bg)
        self.rod = c.create_line(0, 0, 0, 0, fill="#AEB8C6", width=7, capstyle="round")
        self.arm = c.create_line(0, 0, 0, 0, fill=CYAN, width=5, capstyle="round")
        self.piston = c.create_rectangle(0, 0, 0, 0, fill="#7B8696", outline="#C3CBD6", width=2)
        self.pin = c.create_oval(0, 0, 0, 0, fill=CYAN, outline=bg, width=2)
        self.step(0)

    def step(self, d=1):
        self.theta += 0.13 * d
        ex, ey, cr, L, c = self.ex, self.ey, self.cr, self.L, self.c
        px, py = ex + cr * math.sin(self.theta), ey - cr * math.cos(self.theta)
        wy = py - math.sqrt(L * L - (px - ex) ** 2)
        c.coords(self.rod, ex, wy, px, py)
        c.coords(self.arm, ex, ey, px, py)
        c.coords(self.pin, px - 6, py - 6, px + 6, py + 6)
        c.coords(self.piston, ex - 22, wy - 18, ex + 22, wy + 14)
        self.fly.rot = self.theta
        self.fly.draw()
        c.itemconfigure(self.spark, state="normal" if wy < ey - L - cr + 9 else "hidden")


class EngineCanvas(tk.Canvas):
    def __init__(self, parent, bg=PANEL, width=220, height=210):
        super().__init__(parent, width=width, height=height, bg=bg, highlightthickness=0, bd=0)
        self.engine = Engine(self, width / 2, height - 60, bg=bg)
        self.create_text(width / 2, height - 10, text="◉ LIVE MECHANISM", fill=MUTED,
                         font=("Segoe UI", 8, "bold"))
        loop(self, 33, lambda: self.engine.step(1))


class SpinGear(tk.Canvas):
    def __init__(self, parent, size=56, bg=PANEL, color=BLUE, speed=0.04):
        super().__init__(parent, width=size, height=size, bg=bg, highlightthickness=0, bd=0)
        self.g = Gear(self, size / 2, size / 2, size * .46, 10, speed, "#1E242C", color, bg)
        loop(self, 40, lambda: self.g.step(1))


class HazardStripe(tk.Canvas):
    """Yellow/black marching hazard tape."""
    def __init__(self, parent, height=10, speed=1):
        super().__init__(parent, height=height, bg=CYAN, highlightthickness=0, bd=0)
        self.h, self.speed, self.band, self.moved = height, speed, height * 2, 0
        self.bind("<Configure>", self._draw)
        loop(self, 50, self._tick)

    def _draw(self, e):
        self.delete("all"); self.moved = 0
        h, band = self.h, self.band
        for i in range(-3, int(e.width / band) + 4):
            x = i * band
            self.create_polygon(x + h, 0, x + h + band / 2, 0, x + band / 2, h, x, h,
                                fill="#15181D", outline="")

    def _tick(self):
        self.move("all", self.speed, 0); self.moved += self.speed
        if self.moved >= self.band:
            self.move("all", -self.band, 0); self.moved -= self.band


class PulseLED(tk.Canvas):
    def __init__(self, parent, color, size=20, bg=PANEL, rate=0.25):
        super().__init__(parent, width=size, height=size, bg=bg, highlightthickness=0, bd=0)
        self.s, self.t, self.rate = size, 0.0, rate
        self.glow = self.create_oval(0, 0, 0, 0, outline=color, width=2)
        m = size / 2
        self.create_oval(m - 4, m - 4, m + 4, m + 4, fill=color, outline="")
        loop(self, 50, self._tick)

    def _tick(self):
        self.t += self.rate
        m, r = self.s / 2, 5 + 4 * (0.5 + 0.5 * math.sin(self.t))
        self.coords(self.glow, m - r, m - r, m + r, m + r)


class GaugeCanvas(tk.Canvas):
    """Analog gauge with animated needle. value 0-100 (None shows a dash)."""
    def __init__(self, parent, value, size=230, bg=PANEL, label="FLEET HEALTH"):
        cx, cy, r = size / 2, size * .56, size * .38
        super().__init__(parent, width=size, height=int(cy + 54), bg=bg, highlightthickness=0, bd=0)
        self.cx, self.cy, self.r = cx, cy, r
        self.target = 0 if value is None else max(0, min(100, float(value)))
        self.none, self.cur = value is None, 0.0
        for v1, v2, col in ((0, 40, RED), (40, 65, "#FF8A3D"), (65, 85, AMBER), (85, 100, GREEN)):
            self.create_arc(cx - r, cy - r, cx + r, cy + r, start=180 - v2 * 1.8, extent=(v2 - v1) * 1.8,
                            style="arc", outline=col, width=14)
        for v in range(0, 101, 10):
            a = math.radians(180 - v * 1.8)
            self.create_line(cx + (r + 12) * math.cos(a), cy - (r + 12) * math.sin(a),
                             cx + (r + 19) * math.cos(a), cy - (r + 19) * math.sin(a), fill=STEEL, width=2)
        self.needle = self.create_line(cx, cy, cx, cy, fill=TEXT, width=4, capstyle="round")
        self.create_oval(cx - 8, cy - 8, cx + 8, cy + 8, fill=PANEL2, outline=BLUE, width=3)
        self.txt = self.create_text(cx, cy + 24, text="—", fill=TEXT, font=("Segoe UI", 18, "bold"))
        self.create_text(cx, cy + 46, text=label, fill=MUTED, font=("Segoe UI", 8, "bold"))
        self._place()
        loop(self, 30, self._tick)

    def _place(self):
        a = math.radians(180 - self.cur * 1.8)
        self.coords(self.needle, self.cx, self.cy, self.cx + (self.r - 6) * math.cos(a),
                    self.cy - (self.r - 6) * math.sin(a))
        self.itemconfigure(self.txt, text="—" if self.none else f"{round(self.cur)}%")

    def _tick(self):
        diff = self.target - self.cur
        if abs(diff) < .4:
            self.cur = self.target; self._place(); return False
        self.cur += diff * .1 + (.2 if diff > 0 else -.2)
        self._place()


class HeroCanvas(tk.Canvas):
    """Full-panel artwork: blueprint grid, meshing gears, live engine, optional progress bar."""
    def __init__(self, parent, mode="login", title="", subtitle="", slogan="", tagline=""):
        super().__init__(parent, bg=SIDEBAR, highlightthickness=0, bd=0)
        self.mode, self.title_txt, self.sub_txt = mode, title, subtitle
        self.slogan, self.tagline = slogan, tagline
        self.gears, self.engine, self._size = [], None, None
        self.bar_fill = self.bar_txt = self.pct_txt = None
        self.progress, self.status = 0, ""
        self.bind("<Configure>", self._build)
        loop(self, 33, self._tick)

    def _pair(self, x, y, r, ang, speed, orange=False):
        a = Gear(self, x, y, r, 16, speed, "#171C22", BLUE if orange else "#3E4857", SIDEBAR)
        r2, teeth2 = r * 10 / 16, 10
        d = (r + r2) * .93
        b = Gear(self, x + d * math.cos(math.radians(ang)), y + d * math.sin(math.radians(ang)),
                 r2, teeth2, -speed * 16 / 10, "#171C22", "#3E4857" if orange else BLUE, SIDEBAR)
        self.gears += [a, b]

    def _build(self, e):
        w, h = e.width, e.height
        if w < 60 or (w, h) == self._size:
            return
        self._size = (w, h)
        self.delete("all"); self.gears = []
        for x in range(0, w, 40): self.create_line(x, 0, x, h, fill="#141920")
        for y in range(0, h, 40): self.create_line(0, y, w, y, fill="#141920")
        if self.mode == "splash":
            self._pair(70, h * .3, 110, 55, .02, True)
            self._pair(w - 70, h * .3, 110, 125, -.02)
            cx = w / 2
            self.create_text(cx, h * .14, text="⚙  " + self.title_txt + "  ⚙", fill=CYAN, font=("Segoe UI", 44, "bold"))
            self.create_text(cx, h * .14 + 52, text=self.sub_txt, fill=MUTED, font=("Segoe UI", 12, "bold"))
            self.engine = Engine(self, cx, h * .55, bg=SIDEBAR)
            x0, x1, y = cx - 220, cx + 220, h * .85
            self.create_rectangle(x0, y, x1, y + 14, outline=STEEL, width=2)
            self.bar_fill = self.create_rectangle(x0 + 2, y + 2, x0 + 2, y + 12, fill=BLUE, outline="")
            self.bar_txt = self.create_text(cx, y + 34, text=self.status, fill=MUTED, font=("Segoe UI", 10))
            self.pct_txt = self.create_text(x1 + 34, y + 7, text="0%", fill=CYAN, font=("Segoe UI", 11, "bold"))
            self.bar_geom = (x0 + 2, x1 - 2, y + 2, y + 12)
        else:
            self._pair(w - 20, 120, 95, 112, .02, True)
            self._pair(-10, h * .52, 80, 20, .015)
            self.create_text(55, 95, text="⚙ " + self.title_txt, anchor="w", fill=CYAN, font=("Segoe UI", 32, "bold"))
            self.create_text(57, 142, text=self.sub_txt, anchor="w", fill=MUTED, font=("Segoe UI", 11, "bold"))
            self.create_text(55, 205, text=self.slogan, anchor="nw", fill=TEXT, font=("Segoe UI", 24, "bold"))
            self.engine = Engine(self, w * .5, h - 150, bg=SIDEBAR)
            self.create_text(57, h - 28, text=self.tagline, anchor="w", fill=MUTED, font=("Segoe UI", 8))
        if self.bar_fill:
            self.set_progress(self.progress, self.status)

    def set_progress(self, p, msg):
        self.progress, self.status = p, msg
        if self.bar_fill and self._size:
            x0, x1, y0, y1 = self.bar_geom
            self.coords(self.bar_fill, x0, y0, x0 + (x1 - x0) * p / 100, y1)
            self.itemconfigure(self.bar_txt, text=msg)
            self.itemconfigure(self.pct_txt, text=f"{int(p)}%")

    def _tick(self):
        if not self._size:
            return
        for g in self.gears: g.step(1)
        if self.engine: self.engine.step(1)


class DataStore:
    def __init__(self):
        ensure_csv(MACHINES_FILE, MACHINE_DEFAULTS)
        ensure_csv(INSPECTIONS_FILE, INSPECTION_DEFAULTS)
        ensure_csv(USERS_FILE, USER_FIELDS)
        ensure_csv(AUDIT_FILE, AUDIT_FIELDS)
        ensure_csv(MAINTENANCE_FILE, MAINT_FIELDS)
        ensure_csv(SETTINGS_FILE, SETTINGS_FIELDS)
        ensure_csv(STAFF_FILE, STAFF_FIELDS)
        ensure_csv(ATTENDANCE_FILE, ATTENDANCE_FIELDS)
        ensure_csv(PERFORMANCE_FILE, PERFORMANCE_FIELDS)

    def machines(self):
        return read_rows(MACHINES_FILE)

    def inspections(self):
        return read_rows(INSPECTIONS_FILE)

    def users(self):
        return read_rows(USERS_FILE)

    def staff(self):
        return read_rows(STAFF_FILE)

    def attendance(self):
        return read_rows(ATTENDANCE_FILE)

    def performance(self):
        return read_rows(PERFORMANCE_FILE)

    def audit(self, username, action, details=""):
        append_row(AUDIT_FILE, {"Timestamp": now_text(), "Username": username,
                                "Action": action, "Details": details}, AUDIT_FIELDS)

    def save_machines(self, rows):
        write_rows(MACHINES_FILE, rows, MACHINE_DEFAULTS)

    def save_inspections(self, rows):
        write_rows(INSPECTIONS_FILE, rows, INSPECTION_DEFAULTS)

    def add_user(self, username, password, role):
        username = username.strip()
        if not username or len(password) < 8:
            raise ValueError("Username is required and password must be at least 8 characters.")
        if any(u.get("Username", "").lower() == username.lower() for u in self.users()):
            raise ValueError("That username already exists.")
        hashed, salt = password_hash(password)
        append_row(USERS_FILE, {"Username": username, "PasswordHash": hashed,
                    "Salt": salt, "Role": role, "CreatedAt": now_text(), "Active": "1"},
                    USER_FIELDS)

    def authenticate(self, username, password):
        for user in self.users():
            if (user.get("Username", "").lower() == username.strip().lower()
                    and user.get("Active", "1") != "0"):
                if verify_password(password, user.get("Salt", ""), user.get("PasswordHash", "")):
                    return user
        return None

    def update_user(self, username, role=None, active=None, password=None):
        rows = self.users()
        found = False
        for user in rows:
            if user.get("Username", "").lower() == username.lower():
                found = True
                if role is not None:
                    user["Role"] = role
                if active is not None:
                    user["Active"] = "1" if active else "0"
                if password:
                    hashed, salt = password_hash(password)
                    user["PasswordHash"], user["Salt"] = hashed, salt
        if not found:
            raise ValueError("User not found.")
        if sum(1 for u in rows if u.get("Role") == "ADMIN" and u.get("Active", "1") != "0") < 1:
            raise ValueError("At least one active administrator must remain.")
        write_rows(USERS_FILE, rows, USER_FIELDS)

    def add_maintenance(self, row):
        append_row(MAINTENANCE_FILE, row, MAINT_FIELDS)

    def maintenance(self):
        return read_rows(MAINTENANCE_FILE)

    def backup(self):
        BACKUP_DIR.mkdir(exist_ok=True)
        folder = BACKUP_DIR / datetime.now().strftime("backup_%Y%m%d_%H%M%S")
        folder.mkdir()
        for path in [MACHINES_FILE, INSPECTIONS_FILE, USERS_FILE, AUDIT_FILE,
                     MAINTENANCE_FILE, SETTINGS_FILE, STAFF_FILE,
                     ATTENDANCE_FILE, PERFORMANCE_FILE]:
            if path.exists():
                shutil.copy2(path, folder / path.name)
        return folder


class MechCareApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.store = DataStore()
        self.user = None
        self.current_page = None
        self.configure(bg=NAVY)
        self.title(f"{APP_NAME} | Mechanical Asset Intelligence")
        self.nav_items, self.nav_active = {}, None
        self.geometry("1440x900")
        self.minsize(1050, 680)
        self._style()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.show_splash(self.show_first_admin if not self.store.users() else self.show_login)

    def show_splash(self, then):
        self.clear()
        wrap = tk.Frame(self, bg=SIDEBAR); wrap.pack(fill="both", expand=True)
        HazardStripe(wrap, 14).pack(side="top", fill="x")
        HazardStripe(wrap, 14).pack(side="bottom", fill="x")
        hero = HeroCanvas(wrap, mode="splash", title=APP_NAME,
                          subtitle="MECHANICAL ASSET INTELLIGENCE  •  PRECISION  •  POWER  •  PREDICTIVE CARE")
        hero.pack(fill="both", expand=True)
        msgs = ["Calibrating vibration sensors…", "Loading machine registry…",
                "Reading inspection logs…", "Engaging maintenance planner…", "All systems online ✔"]
        state = {"p": 0}
        def tick():
            state["p"] += 2
            hero.set_progress(min(100, state["p"]), msgs[min(len(msgs) - 1, state["p"] // 21)])
            if state["p"] >= 100:
                self.after(350, then)
                return False
        loop(hero, 35, tick)

    def _style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", font=("Segoe UI", 10))
        style.configure("Treeview", background=PANEL, foreground=TEXT,
                        fieldbackground=PANEL, rowheight=30, borderwidth=0)
        style.configure("Treeview.Heading", background=PANEL2, foreground=CYAN,
                        font=("Segoe UI Semibold", 9), relief="flat")
        style.map("Treeview", background=[("selected", SELECT)],
                  foreground=[("selected", TEXT)])
        style.configure("TCombobox", fieldbackground=PANEL2, background=PANEL2,
                        foreground=TEXT, arrowcolor=CYAN)
        style.configure("TEntry", fieldbackground=PANEL2, foreground=TEXT)
        style.configure("Vertical.TScrollbar", background=PANEL2)

    def clear(self):
        for child in self.winfo_children():
            child.destroy()

    def panel(self, parent, **kwargs):
        return tk.Frame(parent, bg=kwargs.pop("bg", PANEL),
                        highlightbackground=BORDER, highlightthickness=1, **kwargs)

    def label(self, parent, text, size=10, color=TEXT, bold=False, **kwargs):
        return tk.Label(parent, text=text, bg=kwargs.pop("bg", parent.cget("bg")),
                        fg=color, font=("Segoe UI", size, "bold" if bold else "normal"),
                        **kwargs)

    def button(self, parent, text, command, primary=False, **kwargs):
        bg = BLUE if primary else PANEL2
        fg = "#FFFFFF" if primary else TEXT
        hover = "#FF8A3D" if primary else "#36404D"
        btn = tk.Button(parent, text=text, command=command, bg=bg, fg=fg,
                        activebackground=CYAN, activeforeground=NAVY,
                        relief="flat", bd=0, padx=15, pady=9,
                        font=("Segoe UI Semibold", 9), cursor="hand2", **kwargs)
        btn.bind("<Enter>", lambda e: btn.configure(bg=hover))
        btn.bind("<Leave>", lambda e: btn.configure(bg=bg))
        return btn

    def entry(self, parent, show=None, width=28):
        e = tk.Entry(parent, width=width, bg=PANEL2, fg=TEXT, insertbackground=CYAN,
                     relief="flat", highlightthickness=1, highlightbackground=BORDER,
                     highlightcolor=BLUE, font=("Segoe UI", 10), show=show)
        return e

    def show_first_admin(self):
        self.clear()
        outer = tk.Frame(self, bg=NAVY)
        outer.place(relx=.5, rely=.5, anchor="center")
        SpinGear(outer, 80, bg=NAVY).pack()
        self.label(outer, "MECHCARE", 25, CYAN, True, bg=NAVY).pack(pady=(0, 5))
        self.label(outer, "INITIAL ADMINISTRATOR SETUP", 10, MUTED, True, bg=NAVY).pack(pady=(0, 24))
        card = self.panel(outer, padx=30, pady=28)
        card.pack()
        self.label(card, "Create your administrator account", 15, TEXT, True).pack(anchor="w", pady=(0, 18))
        self.label(card, "Username", 9, MUTED).pack(anchor="w")
        username = self.entry(card, width=34); username.pack(pady=(5, 14))
        self.label(card, "Password (minimum 8 characters)", 9, MUTED).pack(anchor="w")
        password = self.entry(card, show="•", width=34); password.pack(pady=(5, 14))
        self.label(card, "Confirm password", 9, MUTED).pack(anchor="w")
        confirm = self.entry(card, show="•", width=34); confirm.pack(pady=(5, 20))
        def create():
            if password.get() != confirm.get():
                messagebox.showerror("Setup", "Passwords do not match."); return
            try:
                self.store.add_user(username.get(), password.get(), "ADMIN")
                self.store.audit(username.get(), "INITIAL_ADMIN_CREATED")
                messagebox.showinfo("MechCare", "Administrator account created. Please sign in.")
                self.show_login()
            except Exception as exc:
                messagebox.showerror("Setup", str(exc))
        self.button(card, "CREATE ADMINISTRATOR", create, True).pack(fill="x")
        self.label(outer, "Your data remains in local CSV files on this computer.", 9, MUTED, bg=NAVY).pack(pady=16)

    def show_login(self):
        self.clear()
        root = tk.Frame(self, bg=NAVY)
        root.pack(fill="both", expand=True)
        left = tk.Frame(root, bg=SIDEBAR, width=560)
        left.pack(side="left", fill="both")
        left.pack_propagate(False)
        HazardStripe(left, 10).pack(side="top", fill="x")
        HazardStripe(left, 10).pack(side="bottom", fill="x")
        HeroCanvas(left, mode="login", title=APP_NAME, subtitle="MECHANICAL ASSET INTELLIGENCE",
                   slogan="Precision.\nPower.\nPredictive care.",
                   tagline="⚙  RULE-BASED CONDITION MONITORING  •  CSV DATA ENGINE").pack(fill="both", expand=True)
        right = tk.Frame(root, bg=NAVY)
        right.pack(side="left", fill="both", expand=True)
        card = self.panel(right, padx=42, pady=36)
        card.place(relx=.5, rely=.5, anchor="center")
        top = tk.Frame(card, bg=PANEL); top.pack(fill="x")
        SpinGear(top, 58, bg=PANEL).pack(side="left", padx=(0, 14))
        tb = tk.Frame(top, bg=PANEL); tb.pack(side="left")
        self.label(tb, "Welcome back", 22, TEXT, True).pack(anchor="w")
        self.label(tb, "Sign in to your maintenance workshop", 10, MUTED).pack(anchor="w", pady=(4, 0))
        HazardStripe(card, 6).pack(fill="x", pady=(18, 18))
        self.label(card, "⚙  USERNAME", 8, MUTED, True).pack(anchor="w")
        user = self.entry(card, width=35); user.pack(pady=(7, 18))
        self.label(card, "⚿  PASSWORD", 8, MUTED, True).pack(anchor="w")
        pw = self.entry(card, show="•", width=35); pw.pack(pady=(7, 8))
        show_var = tk.BooleanVar(value=False)
        def toggle():
            pw.configure(show="" if show_var.get() else "•")
        tk.Checkbutton(card, text="Show password", variable=show_var, command=toggle,
                       bg=PANEL, fg=MUTED, selectcolor=PANEL2, activebackground=PANEL,
                       activeforeground=TEXT).pack(anchor="w", pady=(0, 18))
        def login(event=None):
            account = self.store.authenticate(user.get(), pw.get())
            if not account:
                messagebox.showerror("Sign in failed", "Username or password is incorrect, or the account is inactive.")
                return
            self.user = account
            self.store.audit(account["Username"], "LOGIN")
            self.show_shell()
        self.button(card, "⚡  START ENGINE  (SIGN IN)", login, True).pack(fill="x")
        pw.bind("<Return>", login)
        self.label(card, f"MECHCARE  v{APP_VERSION}  •  MECHANICAL EDITION", 8, MUTED).pack(pady=(22, 0))
        user.focus_set()

    def show_shell(self):
        self.clear()
        shell = tk.Frame(self, bg=NAVY)
        shell.pack(fill="both", expand=True)
        self.nav_items, self.nav_active = {}, None
        sidebar = tk.Frame(shell, bg=SIDEBAR, width=245)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        HazardStripe(sidebar, 8).pack(fill="x")
        brand = tk.Frame(sidebar, bg=SIDEBAR); brand.pack(fill="x", padx=16, pady=(16, 4))
        SpinGear(brand, 54, bg=SIDEBAR).pack(side="left")
        tbox = tk.Frame(brand, bg=SIDEBAR); tbox.pack(side="left", padx=10)
        self.label(tbox, "MECHCARE", 17, CYAN, True, bg=SIDEBAR).pack(anchor="w")
        self.label(tbox, "MECHANICAL CONTROL", 7, MUTED, True, bg=SIDEBAR).pack(anchor="w")
        ubox = tk.Frame(sidebar, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        ubox.pack(fill="x", padx=14, pady=(12, 12))
        tk.Label(ubox, text="☻", bg=BLUE, fg="white", font=("Segoe UI Symbol", 16), width=2).pack(side="left", padx=(8, 10), pady=8)
        utext = tk.Frame(ubox, bg=PANEL); utext.pack(side="left")
        self.label(utext, self.user["Username"].upper(), 9, TEXT, True).pack(anchor="w")
        self.label(utext, "◆ " + self.user["Role"], 8, CYAN).pack(anchor="w")
        nav = [
            ("Overview", "⌂", self.page_dashboard), ("Machines", "⚙", self.page_machines),
            ("Inspections", "☑", self.page_inspections), ("Analytics", "⚡", self.page_analytics),
            ("Compare", "⚖", self.page_compare), ("Maintenance", "⚒", self.page_maintenance),
            ("Reports & Backup", "▤", self.page_reports)
        ]
        if self.user.get("Role") == "ADMIN":
            nav.extend([("Staff Directory", "☻", self.page_staff),
                        ("Staff Attendance", "✔", self.page_staff_attendance),
                        ("Staff Performance", "★", self.page_staff_performance),
                        ("User Management", "⚿", self.page_users)])
        for title, icon, command in nav:
            self.nav_button(sidebar, title, icon, command)
        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", padx=15, pady=10)
        self.nav_button(sidebar, "Logout", "✖", self.logout, track=False)
        HazardStripe(sidebar, 8).pack(side="bottom", fill="x")
        self.label(sidebar, "LOCAL CSV MODE  •  OFFLINE", 7, MUTED, bg=SIDEBAR).pack(side="bottom", pady=8)
        # Scrollable main workspace: every page can be viewed even when its
        # content is taller than the laptop screen.
        workspace = tk.Frame(shell, bg=NAVY)
        workspace.pack(side="left", fill="both", expand=True)
        self.content_canvas = tk.Canvas(
            workspace, bg=NAVY, highlightthickness=0, bd=0
        )
        self.content_scrollbar = ttk.Scrollbar(
            workspace, orient="vertical", command=self.content_canvas.yview
        )
        self.content_canvas.configure(yscrollcommand=self.content_scrollbar.set)
        self.content_scrollbar.pack(side="right", fill="y")
        self.content_canvas.pack(side="left", fill="both", expand=True)
        self.content = tk.Frame(self.content_canvas, bg=NAVY)
        self._content_window = self.content_canvas.create_window(
            (0, 0), window=self.content, anchor="nw"
        )
        self.content.bind("<Configure>", self._update_scroll_region)
        self.content_canvas.bind("<Configure>", self._resize_content_window)
        self.content_canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.content_canvas.bind_all("<Button-4>", self._on_mousewheel_linux)
        self.content_canvas.bind_all("<Button-5>", self._on_mousewheel_linux)
        self.set_nav("Overview")
        self.page_dashboard()

    def nav_button(self, parent, title, icon, command, track=True):
        row = tk.Frame(parent, bg=SIDEBAR); row.pack(fill="x", padx=(0, 10), pady=1)
        strip = tk.Frame(row, bg=SIDEBAR, width=4); strip.pack(side="left", fill="y")
        btn = tk.Label(row, text=f"  {icon}   {title}", anchor="w", bg=SIDEBAR, fg=MUTED,
                       font=("Segoe UI Semibold", 10), padx=10, pady=7, cursor="hand2")
        btn.pack(side="left", fill="x", expand=True)
        def go(_e=None):
            if track: self.set_nav(title)
            command()
        def enter(_e):
            if self.nav_active != title:
                btn.configure(bg=PANEL2, fg=TEXT); strip.configure(bg=STEEL)
        def leave(_e):
            if self.nav_active != title:
                btn.configure(bg=SIDEBAR, fg=MUTED); strip.configure(bg=SIDEBAR)
        for w in (btn, strip):
            w.bind("<Button-1>", go); w.bind("<Enter>", enter); w.bind("<Leave>", leave)
        if track:
            self.nav_items[title] = (btn, strip)

    def set_nav(self, title):
        self.nav_active = title
        for t, (btn, strip) in self.nav_items.items():
            on = t == title
            btn.configure(bg=PANEL2 if on else SIDEBAR, fg=CYAN if on else MUTED)
            strip.configure(bg=BLUE if on else SIDEBAR)

    def _update_scroll_region(self, _event=None):
        if hasattr(self, "content_canvas") and self.content_canvas.winfo_exists():
            self.content_canvas.configure(
                scrollregion=self.content_canvas.bbox("all")
            )

    def _resize_content_window(self, event):
        if hasattr(self, "_content_window"):
            self.content_canvas.itemconfigure(self._content_window, width=event.width)

    def _on_mousewheel(self, event):
        if hasattr(self, "content_canvas") and self.content_canvas.winfo_exists():
            self.content_canvas.yview_scroll(int(-event.delta / 120), "units")

    def _on_mousewheel_linux(self, event):
        if hasattr(self, "content_canvas") and self.content_canvas.winfo_exists():
            self.content_canvas.yview_scroll(-1 if event.num == 4 else 1, "units")

    def logout(self):
        self.store.audit(self.user["Username"], "LOGOUT")
        self.user = None
        self.show_login()

    def _on_close(self):
        if self.user:
            self.store.audit(self.user["Username"], "APP_CLOSED")
        self.destroy()

    PAGE_ICONS = {"Operations overview": "⌂", "Machine registry": "⚙", "Inspection management": "☑",
                  "Condition analytics": "⚡", "Machine comparison": "⚖", "Maintenance planner": "⚒",
                  "Reports & data protection": "▤", "Staff directory": "☻", "Staff attendance": "✔",
                  "Staff performance": "★", "User administration": "⚿"}

    def page_header(self, title, subtitle):
        self.clear_content()
        head = tk.Frame(self.content, bg=NAVY)
        head.pack(fill="x", padx=28, pady=(24, 8))
        left = tk.Frame(head, bg=NAVY); left.pack(side="left")
        tk.Label(left, text=self.PAGE_ICONS.get(title, "⚙"), bg=BLUE, fg="white",
                 font=("Segoe UI Symbol", 18, "bold"), width=3, pady=6).pack(side="left", padx=(0, 14))
        titles = tk.Frame(left, bg=NAVY); titles.pack(side="left")
        self.label(titles, title, 22, TEXT, True, bg=NAVY).pack(anchor="w")
        self.label(titles, subtitle, 9, MUTED, bg=NAVY).pack(anchor="w", pady=(4, 0))
        HazardStripe(self.content, 6).pack(fill="x", padx=28, pady=(0, 16))
        return head

    def clear_content(self):
        for child in self.content.winfo_children():
            child.destroy()

    METRIC_ICONS = {"Total assets": "⚙", "Active assets": "⚡", "Needs attention": "⚠",
                    "Critical assets": "☢", "Fleet health": "♥"}

    def card_metric(self, parent, title, value, note, accent=BLUE):
        card = self.panel(parent, padx=0, pady=0)
        tk.Frame(card, bg=accent, height=4).pack(fill="x")
        inner = tk.Frame(card, bg=PANEL, padx=18, pady=14); inner.pack(fill="both", expand=True)
        top = tk.Frame(inner, bg=PANEL); top.pack(fill="x")
        self.label(top, title.upper(), 8, MUTED, True).pack(side="left")
        tk.Label(top, text=self.METRIC_ICONS.get(title, "⚙"), bg=PANEL, fg=accent,
                 font=("Segoe UI Symbol", 15)).pack(side="right")
        val = self.label(inner, "", 25, accent, True); val.pack(anchor="w", pady=(8, 1))
        count_up(val, value)
        self.label(inner, note, 8, MUTED).pack(anchor="w")
        return card

    def machine_analysis(self, machine):
        rows = [r for r in self.store.inspections() if r.get("Machine ID") == machine.get("ID")]
        rows.sort(key=lambda x: x.get("Date", ""))
        if not rows:
            return analyze_machine(0, 0, 0), rows
        latest = rows[-1]
        return analyze_machine(latest.get("Temperature"), latest.get("Vibration"),
                               latest.get("Hours"), rows), rows

    def page_dashboard(self):
        self.page_header("Operations overview", "Live summary calculated from your local machine and inspection records.")
        machines = self.store.machines()
        inspections = self.store.inspections()
        analyses = [(m, self.machine_analysis(m)[0]) for m in machines]
        critical = sum(a["risk"] == "CRITICAL" for _, a in analyses)
        warning = sum(a["risk"] in ("HIGH", "MODERATE") for _, a in analyses)
        healthy = sum(a["risk"] == "LOW" for _, a in analyses)
        active = sum(m.get("Status", "ACTIVE").upper() == "ACTIVE" for m in machines)
        avg = round(sum(a["score"] for _, a in analyses) / len(analyses)) if analyses else 0
        banner = self.panel(self.content, padx=18, pady=10)
        banner.pack(fill="x", padx=28, pady=(0, 16))
        GaugeCanvas(banner, avg if machines else None, size=250).pack(side="left")
        EngineCanvas(banner, bg=PANEL).pack(side="left", padx=20)
        live = tk.Frame(banner, bg=PANEL); live.pack(side="left", fill="both", expand=True, padx=(20, 0))
        self.label(live, "◈ LIVE SYSTEM STATUS", 10, CYAN, True).pack(anchor="w", pady=(10, 8))
        clock = self.label(live, "", 20, TEXT, True); clock.pack(anchor="w", pady=(0, 6))
        def tick_clock():
            clock.configure(text="⏱  " + datetime.now().strftime("%H:%M:%S"))
        tick_clock(); loop(clock, 1000, tick_clock)
        today = datetime.now().strftime("%Y-%m-%d")
        orders = [r for r in self.store.maintenance() if r.get("Status", "").upper() == "OPEN"]
        overdue = sum(1 for r in orders if r.get("Due Date", "9999") < today)
        for text, color, rate in [("Monitoring engine online", GREEN, .18),
                                  (f"{len(orders)} open work orders", AMBER if orders else GREEN, .22),
                                  (f"{overdue} overdue tasks", RED if overdue else GREEN, .5 if overdue else .15),
                                  (f"{critical} critical machines", RED if critical else GREEN, .6 if critical else .15)]:
            row = tk.Frame(live, bg=PANEL); row.pack(anchor="w", pady=4)
            PulseLED(row, color, rate=rate).pack(side="left")
            self.label(row, text, 10, TEXT).pack(side="left", padx=8)
        metrics = tk.Frame(self.content, bg=NAVY)
        metrics.pack(fill="x", padx=28)
        items = [
            ("Total assets", len(machines), "Registered machines", CYAN),
            ("Active assets", active, "Operating status", GREEN),
            ("Needs attention", warning, "Moderate / high risk", AMBER),
            ("Critical assets", critical, "Urgent review", RED),
            ("Fleet health", f"{avg}%" if machines else "—", "Average rule-based score", BLUE)
        ]
        for i, item in enumerate(items):
            metrics.columnconfigure(i, weight=1)
            self.card_metric(metrics, *item).grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
        lower = tk.Frame(self.content, bg=NAVY)
        lower.pack(fill="both", expand=True, padx=28, pady=20)
        left = self.panel(lower, padx=18, pady=16)
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))
        self.label(left, "MACHINE HEALTH REGISTER", 10, CYAN, True).pack(anchor="w", pady=(0, 12))
        tree = self.make_tree(left, ("id", "name", "score", "risk", "status"),
                              ("Machine ID", "Machine", "Health", "Risk", "Operating status"))
        for m, a in analyses:
            tree.insert("", "end", values=(m.get("ID"), m.get("Name"), f'{a["score"]}/100',
                                           a["risk"], m.get("Status", "ACTIVE")), tags=(a["risk"],))
        right = self.panel(lower, width=310, padx=18, pady=16)
        right.pack(side="right", fill="y")
        self.label(right, "FLEET DISTRIBUTION", 10, CYAN, True).pack(anchor="w", pady=(0, 15))
        for name, count, color in [("Healthy", healthy, GREEN), ("Watch / Warning", warning, AMBER),
                                   ("Critical", critical, RED)]:
            row = tk.Frame(right, bg=PANEL); row.pack(fill="x", pady=8)
            self.label(row, name, 9, TEXT, True).pack(side="left")
            self.label(row, count, 12, color, True).pack(side="right")
        self.label(right, "RECENT INSPECTIONS", 9, CYAN, True).pack(anchor="w", pady=(24, 8))
        for r in sorted(inspections, key=lambda x: x.get("Date", ""), reverse=True)[:6]:
            self.label(right, f'{r.get("Date","")}  •  {r.get("Machine ID","")}',
                       8, MUTED).pack(anchor="w", pady=3)
        if not inspections:
            self.label(right, "No inspections recorded yet.", 8, MUTED).pack(anchor="w")

    def make_tree(self, parent, columns, headings):
        wrap = tk.Frame(parent, bg=PANEL)
        wrap.pack(fill="both", expand=True)
        tree = ttk.Treeview(wrap, columns=columns, show="headings")
        for tag, colour in {"LOW": GREEN, "HEALTHY": GREEN, "MODERATE": AMBER, "WATCH": AMBER,
                            "HIGH": "#FF8A3D", "WARNING": "#FF8A3D", "CRITICAL": RED}.items():
            tree.tag_configure(tag, foreground=colour)
        for col, heading in zip(columns, headings):
            tree.heading(col, text=heading)
            tree.column(col, width=130, minwidth=75, anchor="w")
        sy = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        sx = ttk.Scrollbar(wrap, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        tree.grid(row=0, column=0, sticky="nsew")
        sy.grid(row=0, column=1, sticky="ns")
        sx.grid(row=1, column=0, sticky="ew")
        wrap.rowconfigure(0, weight=1); wrap.columnconfigure(0, weight=1)
        return tree

    def page_machines(self):
        head = self.page_header("Machine registry", "Manage industrial assets and review their latest condition assessment.")
        if self.user["Role"] in ("ADMIN", "ENGINEER"):
            self.button(head, "+ Add machine", self.machine_form, True).pack(side="right")
        body = tk.Frame(self.content, bg=NAVY); body.pack(fill="both", expand=True, padx=28, pady=(0, 24))
        toolbar = tk.Frame(body, bg=NAVY); toolbar.pack(fill="x", pady=(0, 12))
        search = self.entry(toolbar, width=35); search.pack(side="left")
        self.label(toolbar, "Search by ID, name or location", 8, MUTED, bg=NAVY).pack(side="left", padx=10)
        tree = self.make_tree(body, ("id", "name", "location", "category", "status", "health", "risk"),
                              ("ID", "Machine", "Location", "Category", "Operating status", "Health", "Risk"))
        def refresh(*_):
            tree.delete(*tree.get_children())
            term = search.get().lower()
            for m in self.store.machines():
                a, _ = self.machine_analysis(m)
                vals = [m.get("ID"), m.get("Name"), m.get("Location"), m.get("Category"),
                        m.get("Status", "ACTIVE"), f'{a["score"]}/100', a["risk"]]
                if term in " ".join(str(v) for v in vals).lower():
                    tree.insert("", "end", values=vals, tags=(vals[-1],))
        search.bind("<KeyRelease>", refresh); refresh()
        actions = tk.Frame(body, bg=NAVY); actions.pack(fill="x", pady=12)
        def selected_id():
            sel = tree.selection()
            return tree.item(sel[0], "values")[0] if sel else None
        self.button(actions, "View details", lambda: self.machine_details(selected_id())).pack(side="left", padx=(0, 8))
        if self.user["Role"] in ("ADMIN", "ENGINEER"):
            self.button(actions, "Edit selected", lambda: self.machine_form(selected_id())).pack(side="left", padx=8)
        if self.user["Role"] == "ADMIN":
            self.button(actions, "Delete selected", lambda: self.delete_machine(selected_id())).pack(side="left", padx=8)
        tree.bind("<Double-1>", lambda e: self.machine_details(selected_id()))

    def machine_form(self, machine_id=None):
        existing = next((m for m in self.store.machines() if m.get("ID") == machine_id), {}) if machine_id else {}
        win = tk.Toplevel(self); win.title("Machine record"); win.configure(bg=NAVY); win.geometry("470x540")
        win.transient(self); win.grab_set()
        self.label(win, "EDIT MACHINE" if machine_id else "REGISTER MACHINE", 16, CYAN, True, bg=NAVY).pack(anchor="w", padx=25, pady=22)
        fields = {}
        for key, default in [("ID", ""), ("Name", ""), ("Location", ""), ("Category", "General"), ("Status", "ACTIVE")]:
            self.label(win, key.upper(), 8, MUTED, True, bg=NAVY).pack(anchor="w", padx=25)
            ent = self.entry(win, width=42); ent.pack(padx=25, pady=(5, 13), fill="x")
            ent.insert(0, existing.get(key, default))
            if machine_id and key == "ID":
                ent.configure(state="disabled")
            fields[key] = ent
        def save():
            values = {k: v.get().strip() for k, v in fields.items()}
            if not values["ID"] or not values["Name"]:
                messagebox.showerror("Validation", "Machine ID and name are required.", parent=win); return
            rows = self.store.machines()
            if not machine_id and any(r.get("ID", "").lower() == values["ID"].lower() for r in rows):
                messagebox.showerror("Validation", "Machine ID already exists.", parent=win); return
            if machine_id:
                for r in rows:
                    if r.get("ID") == machine_id:
                        r.update(values)
            else:
                rows.append(values)
            self.store.save_machines(rows)
            self.store.audit(self.user["Username"], "MACHINE_SAVED", values["ID"])
            win.destroy(); self.page_machines()
        self.button(win, "SAVE MACHINE", save, True).pack(fill="x", padx=25, pady=18)

    def delete_machine(self, machine_id):
        if not machine_id:
            messagebox.showwarning("Select machine", "Select a machine first."); return
        if not messagebox.askyesno("Confirm deletion",
                f"Delete machine {machine_id}? Inspection history will be retained."):
            return
        rows = [m for m in self.store.machines() if m.get("ID") != machine_id]
        self.store.save_machines(rows)
        self.store.audit(self.user["Username"], "MACHINE_DELETED", machine_id)
        self.page_machines()

    def machine_details(self, machine_id):
        if not machine_id:
            messagebox.showwarning("Select machine", "Select a machine first."); return
        m = next((x for x in self.store.machines() if x.get("ID") == machine_id), None)
        if not m: return
        a, history = self.machine_analysis(m)
        win = tk.Toplevel(self); win.title("Machine details"); win.configure(bg=NAVY); win.geometry("680x760")
        self.label(win, m.get("Name", "Machine"), 20, CYAN, True, bg=NAVY).pack(anchor="w", padx=24, pady=(22, 4))
        self.label(win, f'{m.get("ID")}  •  {m.get("Location")}  •  {m.get("Category")}', 9, MUTED, bg=NAVY).pack(anchor="w", padx=24)
        self.label(win, f'HEALTH SCORE   {a["score"]}/100       RISK   {a["risk"]}', 15,
                   RED if a["risk"] == "CRITICAL" else AMBER if a["risk"] in ("HIGH","MODERATE") else GREEN,
                   True, bg=NAVY).pack(anchor="w", padx=24, pady=22)
        GaugeCanvas(win, a["score"], size=210, bg=NAVY, label="MACHINE HEALTH").pack(anchor="w", padx=24, pady=(0, 10))
        self.label(win, a["advice"], 10, TEXT, wraplength=580, justify="left", bg=NAVY).pack(anchor="w", padx=24)
        self.label(win, "INSPECTION HISTORY", 9, CYAN, True, bg=NAVY).pack(anchor="w", padx=24, pady=(25, 8))
        tree = self.make_tree(win, ("date", "temp", "vib", "hours", "status"),
                              ("Date", "Temperature", "Vibration", "Hours", "Status"))
        for r in history[-100:]:
            tree.insert("", "end", values=(r.get("Date"), r.get("Temperature"),
                r.get("Vibration"), r.get("Hours"), r.get("Status")))

    def page_inspections(self):
        head = self.page_header("Inspection management", "Record condition readings; status and maintenance advice are calculated automatically.")
        if self.user["Role"] in ("ADMIN", "ENGINEER"):
            self.button(head, "+ New inspection", self.inspection_form, True).pack(side="right")
        body = tk.Frame(self.content, bg=NAVY); body.pack(fill="both", expand=True, padx=28, pady=(0, 24))
        search = self.entry(body, width=35); search.pack(anchor="w", pady=(0, 12))
        self.label(body, "Search machine ID, date or status", 8, MUTED, bg=NAVY).pack(anchor="w", pady=(0, 8))
        tree = self.make_tree(body, ("date", "id", "temp", "vib", "hours", "status", "advice"),
                              ("Date", "Machine ID", "Temperature", "Vibration", "Hours", "Status", "Advice"))
        def refresh(*_):
            tree.delete(*tree.get_children())
            term = search.get().lower()
            for r in sorted(self.store.inspections(), key=lambda x: x.get("Date", ""), reverse=True):
                vals = [r.get(k, "") for k in INSPECTION_DEFAULTS]
                if term in " ".join(vals).lower():
                    tree.insert("", "end", values=vals, tags=(vals[5],))
        search.bind("<KeyRelease>", refresh); refresh()

    def inspection_form(self):
        machines = self.store.machines()
        if not machines:
            messagebox.showinfo("No machines", "Register a machine before recording an inspection."); return
        win = tk.Toplevel(self); win.title("New inspection"); win.configure(bg=NAVY); win.geometry("480x590")
        win.transient(self); win.grab_set()
        self.label(win, "NEW CONDITION INSPECTION", 15, CYAN, True, bg=NAVY).pack(anchor="w", padx=25, pady=22)
        fields = {}
        choices = [m.get("ID") for m in machines]
        for key, default in [("Machine ID", choices[0]), ("Temperature", ""), ("Vibration", ""), ("Hours", "")]:
            self.label(win, key.upper(), 8, MUTED, True, bg=NAVY).pack(anchor="w", padx=25)
            if key == "Machine ID":
                widget = ttk.Combobox(win, values=choices, state="readonly")
                widget.set(default)
            else:
                widget = self.entry(win, width=40)
                if key == "Hours": widget.insert(0, "0")
            widget.pack(fill="x", padx=25, pady=(5, 14))
            fields[key] = widget
        result_label = self.label(win, "Enter readings to calculate condition.", 9, MUTED, wraplength=410, justify="left", bg=NAVY)
        result_label.pack(anchor="w", padx=25, pady=8)
        def preview(*_):
            vals = {k: v.get() for k, v in fields.items()}
            a = analyze_machine(vals["Temperature"], vals["Vibration"], vals["Hours"])
            result_label.configure(text=f'Assessment: {a["status"]}  |  Health: {a["score"]}/100\\n{a["advice"]}')
        for k in ("Temperature", "Vibration", "Hours"):
            fields[k].bind("<KeyRelease>", preview)
        def save():
            try:
                temp = float(fields["Temperature"].get())
                vib = float(fields["Vibration"].get())
                hours = float(fields["Hours"].get())
                if min(temp, vib, hours) < 0: raise ValueError()
            except ValueError:
                messagebox.showerror("Invalid readings", "Enter valid non-negative numeric readings.", parent=win); return
            mid = fields["Machine ID"].get()
            history = [r for r in self.store.inspections() if r.get("Machine ID") == mid]
            history.sort(key=lambda x: x.get("Date", ""))
            a = analyze_machine(temp, vib, hours, history)
            row = {"Date": now_text(), "Machine ID": mid, "Temperature": temp,
                   "Vibration": vib, "Hours": hours, "Status": a["status"], "Advice": a["advice"]}
            append_row(INSPECTIONS_FILE, row, INSPECTION_DEFAULTS)
            self.store.audit(self.user["Username"], "INSPECTION_ADDED", mid)
            win.destroy(); self.page_inspections()
            messagebox.showinfo("Inspection saved", f'{a["status"]} — health score {a["score"]}/100')
        self.button(win, "SAVE INSPECTION", save, True).pack(fill="x", padx=25, pady=18)

    def page_analytics(self):
        self.page_header("Condition analytics", "Trend charts use inspection records; Matplotlib is optional.")
        body = tk.Frame(self.content, bg=NAVY); body.pack(fill="both", expand=True, padx=28, pady=8)
        rows = sorted(self.store.inspections(), key=lambda x: x.get("Date", ""))
        if not rows:
            self.label(body, "No inspection data available. Add inspections to unlock trend analysis.",
                       11, MUTED, bg=NAVY).pack(anchor="w", pady=20); return
        try:
            from matplotlib.figure import Figure
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            fig = Figure(figsize=(10, 5.5), dpi=100, facecolor=PANEL)
            ax = fig.add_subplot(111)
            ax.set_facecolor(PANEL)
            dates = [r.get("Date", "")[-8:] for r in rows[-40:]]
            temps = [safe_float(r.get("Temperature")) for r in rows[-40:]]
            vibs = [safe_float(r.get("Vibration")) for r in rows[-40:]]
            ax.plot(dates, temps, marker="o", color=BLUE, label="Temperature")
            ax.plot(dates, vibs, marker="s", color=CYAN, label="Vibration")
            ax.tick_params(axis="x", rotation=45, colors=MUTED, labelsize=8)
            ax.tick_params(axis="y", colors=MUTED)
            ax.set_title("Inspection parameter trends", color=TEXT, pad=15)
            ax.grid(alpha=.2); ax.legend(facecolor=PANEL2, labelcolor=TEXT)
            for spine in ax.spines.values(): spine.set_color(BORDER)
            fig.tight_layout()
            canvas = FigureCanvasTkAgg(fig, master=body)
            canvas.draw(); canvas.get_tk_widget().pack(fill="both", expand=True)
        except ImportError:
            self.label(body, "Install Matplotlib to display charts:  pip install matplotlib",
                       11, AMBER, bg=NAVY).pack(anchor="w", pady=20)
        except Exception as exc:
            self.label(body, f"Chart could not be rendered: {exc}", 10, RED, bg=NAVY).pack(anchor="w")

    def page_compare(self):
        self.page_header("Machine comparison", "Compare the latest available inspection readings across selected assets.")
        body = tk.Frame(self.content, bg=NAVY); body.pack(fill="both", expand=True, padx=28, pady=10)
        machines = self.store.machines()
        if not machines:
            self.label(body, "No machines registered.", 10, MUTED, bg=NAVY).pack(anchor="w"); return
        self.label(body, "Select machines (Ctrl-click for multiple selection)", 9, MUTED, bg=NAVY).pack(anchor="w")
        lb = tk.Listbox(body, selectmode="extended", bg=PANEL, fg=TEXT, selectbackground=SELECT,
                        height=7, relief="flat", font=("Segoe UI", 10), exportselection=False)
        lb.pack(fill="x", pady=10)
        for m in machines: lb.insert("end", f'{m.get("ID")} — {m.get("Name")}')
        tree = self.make_tree(body, ("id", "name", "temp", "vib", "hours", "health", "risk"),
                              ("ID", "Machine", "Temperature", "Vibration", "Hours", "Health", "Risk"))
        def compare():
            tree.delete(*tree.get_children())
            selected = lb.curselection()
            if not selected:
                messagebox.showinfo("Select assets", "Select at least one machine."); return
            for idx in selected:
                m = machines[idx]; a, hist = self.machine_analysis(m)
                latest = hist[-1] if hist else {}
                tree.insert("", "end", values=(m.get("ID"), m.get("Name"),
                    latest.get("Temperature", "—"), latest.get("Vibration", "—"),
                    latest.get("Hours", "—"), f'{a["score"]}/100', a["risk"]))
        self.button(body, "COMPARE SELECTED", compare, True).pack(anchor="w", pady=(0, 12))

    def page_maintenance(self):
        head = self.page_header("Maintenance planner", "Schedule and track maintenance work orders.")
        if self.user["Role"] in ("ADMIN", "ENGINEER"):
            self.button(head, "+ Schedule task", self.maintenance_form, True).pack(side="right")
        body = tk.Frame(self.content, bg=NAVY); body.pack(fill="both", expand=True, padx=28, pady=10)
        tree = self.make_tree(body, ("id", "machine", "due", "task", "priority", "status"),
                              ("Work order", "Machine ID", "Due date", "Task", "Priority", "Status"))
        for r in self.store.maintenance():
            tree.insert("", "end", values=tuple(r.get(k, "") for k in MAINT_FIELDS[:6]))
        if self.user["Role"] in ("ADMIN", "ENGINEER"):
            def complete():
                sel = tree.selection()
                if not sel:
                    messagebox.showinfo("Select task", "Select a work order."); return
                work_id = tree.item(sel[0], "values")[0]
                rows = self.store.maintenance()
                for r in rows:
                    if r.get("ID") == work_id: r["Status"] = "COMPLETED"
                write_rows(MAINTENANCE_FILE, rows, MAINT_FIELDS)
                self.store.audit(self.user["Username"], "WORK_ORDER_COMPLETED", work_id)
                self.page_maintenance()
            self.button(body, "Mark selected completed", complete).pack(anchor="w", pady=10)

    def maintenance_form(self):
        machines = self.store.machines()
        if not machines:
            messagebox.showinfo("No machines", "Register a machine first."); return
        win = tk.Toplevel(self); win.title("Schedule maintenance"); win.configure(bg=NAVY); win.geometry("450x440")
        self.label(win, "CREATE WORK ORDER", 15, CYAN, True, bg=NAVY).pack(anchor="w", padx=24, pady=20)
        def field(title, default=""):
            self.label(win, title.upper(), 8, MUTED, True, bg=NAVY).pack(anchor="w", padx=24)
            e = self.entry(win, width=40); e.pack(fill="x", padx=24, pady=(5, 12)); e.insert(0, default); return e
        mid = ttk.Combobox(win, values=[m.get("ID") for m in machines], state="readonly")
        self.label(win, "MACHINE ID", 8, MUTED, True, bg=NAVY).pack(anchor="w", padx=24)
        mid.pack(fill="x", padx=24, pady=(5, 12)); mid.set(machines[0].get("ID"))
        due = field("Due date (YYYY-MM-DD)", (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d"))
        task = field("Maintenance task")
        priority = ttk.Combobox(win, values=["ROUTINE", "MEDIUM", "HIGH", "URGENT"], state="readonly")
        self.label(win, "PRIORITY", 8, MUTED, True, bg=NAVY).pack(anchor="w", padx=24)
        priority.pack(fill="x", padx=24, pady=(5, 12)); priority.set("MEDIUM")
        def save():
            try: datetime.strptime(due.get().strip(), "%Y-%m-%d")
            except ValueError:
                messagebox.showerror("Date format", "Use YYYY-MM-DD.", parent=win); return
            if not task.get().strip():
                messagebox.showerror("Validation", "Enter a maintenance task.", parent=win); return
            rows = self.store.maintenance()
            next_id = f"WO-{len(rows)+1:04d}"
            self.store.add_maintenance({"ID": next_id, "Machine ID": mid.get(),
                "Due Date": due.get().strip(), "Task": task.get().strip(),
                "Priority": priority.get(), "Status": "OPEN", "Created By": self.user["Username"]})
            self.store.audit(self.user["Username"], "WORK_ORDER_CREATED", next_id)
            win.destroy(); self.page_maintenance()
        self.button(win, "SAVE WORK ORDER", save, True).pack(fill="x", padx=24, pady=15)

    def page_reports(self):
        self.page_header("Reports & data protection", "Export operational records and create a local backup of application data.")
        body = tk.Frame(self.content, bg=NAVY); body.pack(fill="both", expand=True, padx=28, pady=10)
        card = self.panel(body, padx=22, pady=22); card.pack(fill="x", pady=10)
        self.label(card, "DATA EXPORT", 11, CYAN, True).pack(anchor="w")
        self.label(card, "Export machine register and inspection history as CSV files.", 9, MUTED).pack(anchor="w", pady=8)
        self.button(card, "Export machines CSV", lambda: self.export_csv(MACHINES_FILE, "machines_export.csv")).pack(anchor="w", pady=5)
        self.button(card, "Export inspections CSV", lambda: self.export_csv(INSPECTIONS_FILE, "inspections_export.csv")).pack(anchor="w", pady=5)
        self.button(card, "Generate machine health PDF", self.export_pdf).pack(anchor="w", pady=5)
        backup = self.panel(body, padx=22, pady=22); backup.pack(fill="x", pady=10)
        self.label(backup, "BACKUP", 11, CYAN, True).pack(anchor="w")
        self.label(backup, "Copies CSV data files into a timestamped local backup folder.", 9, MUTED).pack(anchor="w", pady=8)
        self.button(backup, "Create backup now", self.create_backup, True).pack(anchor="w")

    def export_csv(self, source, suggested):
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=suggested,
                                            filetypes=[("CSV files", "*.csv")])
        if not path: return
        try:
            shutil.copy2(source, path)
            self.store.audit(self.user["Username"], "CSV_EXPORTED", Path(path).name)
            messagebox.showinfo("Export complete", f"Saved: {path}")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    def export_pdf(self):
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4, landscape
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        except ImportError:
            messagebox.showwarning("PDF dependency", "Install PDF support with: pip install reportlab"); return
        path = filedialog.asksaveasfilename(defaultextension=".pdf", initialfile="MechCare_Health_Report.pdf",
                                            filetypes=[("PDF files", "*.pdf")])
        if not path: return
        styles = getSampleStyleSheet()
        title = ParagraphStyle("MCtitle", parent=styles["Title"], textColor=colors.HexColor("#2A2F36"))
        story = [Paragraph("MECHCARE — MACHINE HEALTH REPORT", title),
                 Paragraph(f"Generated: {now_text()} | Prepared by: {self.user['Username']}", styles["Normal"]),
                 Spacer(1, 16)]
        data = [["ID", "Machine", "Location", "Health", "Risk", "Latest temperature", "Latest vibration", "Recommendation"]]
        for m in self.store.machines():
            a, hist = self.machine_analysis(m); last = hist[-1] if hist else {}
            data.append([m.get("ID", ""), m.get("Name", ""), m.get("Location", ""),
                         str(a["score"]), a["risk"], last.get("Temperature", "—"),
                         last.get("Vibration", "—"), a["advice"][:110]])
        table = Table(data, repeatRows=1, colWidths=[45, 85, 85, 42, 55, 65, 65, 170])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#2A2F36")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("GRID", (0,0), (-1,-1), .35, colors.HexColor("#B8C6D8")),
            ("FONTSIZE", (0,0), (-1,-1), 7),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#EDF4FA")]),
        ]))
        story.append(table)
        try:
            SimpleDocTemplate(path, pagesize=landscape(A4), rightMargin=25, leftMargin=25).build(story)
            self.store.audit(self.user["Username"], "PDF_REPORT_EXPORTED", Path(path).name)
            messagebox.showinfo("Report generated", f"Saved: {path}")
        except Exception as exc:
            messagebox.showerror("PDF failed", str(exc))

    def create_backup(self):
        try:
            folder = self.store.backup()
            self.store.audit(self.user["Username"], "BACKUP_CREATED", str(folder.name))
            messagebox.showinfo("Backup complete", f"Backup saved in:\\n{folder}")
        except Exception as exc:
            messagebox.showerror("Backup failed", str(exc))

    # ------------------------------------------------------------------
    # STAFF MANAGEMENT — separate from application login accounts.
    # All staff records are stored in their own CSV files.
    # ------------------------------------------------------------------
    def _admin_only(self):
        if not self.user or self.user.get("Role") != "ADMIN":
            messagebox.showerror("Access denied", "Administrator access is required.")
            return False
        return True

    def page_staff(self):
        if not self._admin_only(): return
        head = self.page_header("Staff directory", "Register and maintain employee records. This is separate from app login accounts.")
        self.button(head, "+ Add staff member", self.staff_form, True).pack(side="right")
        body = tk.Frame(self.content, bg=NAVY); body.pack(fill="both", expand=True, padx=28, pady=10)
        rows = self.store.staff()
        active = sum(1 for r in rows if r.get("Status", "ACTIVE").upper() == "ACTIVE")
        self.label(body, f"TOTAL STAFF: {len(rows)}     ACTIVE: {active}", 10, CYAN, True, bg=NAVY).pack(anchor="w", pady=(0, 10))
        tree = self.make_tree(body, ("id", "name", "dept", "designation", "phone", "status", "joined"),
            ("Staff ID", "Name", "Department", "Designation", "Phone", "Status", "Joined date"))
        for r in rows:
            tree.insert("", "end", values=tuple(r.get(k, "") for k in STAFF_FIELDS))
        def change_status():
            sel = tree.selection()
            if not sel:
                messagebox.showinfo("Select staff", "Select a staff member first."); return
            staff_id = tree.item(sel[0], "values")[0]
            data = self.store.staff()
            for r in data:
                if r.get("Staff ID") == staff_id:
                    r["Status"] = "INACTIVE" if r.get("Status", "ACTIVE") == "ACTIVE" else "ACTIVE"
            write_rows(STAFF_FILE, data, STAFF_FIELDS)
            self.store.audit(self.user["Username"], "STAFF_STATUS_CHANGED", staff_id)
            self.page_staff()
        self.button(body, "Activate / deactivate selected", change_status).pack(anchor="w", pady=10)

    def staff_form(self):
        if not self._admin_only(): return
        win = tk.Toplevel(self); win.title("Add staff member"); win.configure(bg=NAVY); win.geometry("470x650")
        win.transient(self); win.grab_set()
        self.label(win, "REGISTER STAFF MEMBER", 15, CYAN, True, bg=NAVY).pack(anchor="w", padx=24, pady=20)
        fields = {}
        for key, default in [("Staff ID", ""), ("Name", ""), ("Department", "Mechanical"),
                             ("Designation", ""), ("Phone", ""),
                             ("Joined Date", datetime.now().strftime("%Y-%m-%d"))]:
            self.label(win, key.upper(), 8, MUTED, True, bg=NAVY).pack(anchor="w", padx=24)
            e = self.entry(win, width=40); e.pack(fill="x", padx=24, pady=(5, 12))
            e.insert(0, default); fields[key] = e
        def save():
            values = {k: v.get().strip() for k, v in fields.items()}
            if not values["Staff ID"] or not values["Name"]:
                messagebox.showerror("Required fields", "Staff ID and Name are required.", parent=win); return
            if any(r.get("Staff ID", "").lower() == values["Staff ID"].lower() for r in self.store.staff()):
                messagebox.showerror("Duplicate ID", "That Staff ID already exists.", parent=win); return
            try: datetime.strptime(values["Joined Date"], "%Y-%m-%d")
            except ValueError:
                messagebox.showerror("Date format", "Joined Date must use YYYY-MM-DD.", parent=win); return
            values["Status"] = "ACTIVE"
            append_row(STAFF_FILE, values, STAFF_FIELDS)
            self.store.audit(self.user["Username"], "STAFF_ADDED", values["Staff ID"])
            win.destroy(); self.page_staff()
        self.button(win, "SAVE STAFF MEMBER", save, True).pack(fill="x", padx=24, pady=18)

    def page_staff_attendance(self):
        if not self._admin_only(): return
        head = self.page_header("Staff attendance", "Record daily attendance and review check-in / check-out history.")
        self.button(head, "+ Mark attendance", self.attendance_form, True).pack(side="right")
        body = tk.Frame(self.content, bg=NAVY); body.pack(fill="both", expand=True, padx=28, pady=10)
        rows = sorted(self.store.attendance(), key=lambda r: (r.get("Date", ""), r.get("Staff ID", "")), reverse=True)
        today = datetime.now().strftime("%Y-%m-%d")
        todays = [r for r in rows if r.get("Date") == today]
        present = sum(1 for r in todays if r.get("Status") in ("PRESENT", "LATE"))
        self.label(body, f"TODAY {today}     RECORDED: {len(todays)}     PRESENT / LATE: {present}", 10, CYAN, True, bg=NAVY).pack(anchor="w", pady=(0, 10))
        tree = self.make_tree(body, ("date", "id", "name", "status", "in", "out", "notes", "by"),
            ("Date", "Staff ID", "Staff name", "Status", "Check in", "Check out", "Notes", "Recorded by"))
        for r in rows:
            tree.insert("", "end", values=tuple(r.get(k, "") for k in ATTENDANCE_FIELDS))
        self.button(body, "Export attendance CSV", lambda: self.export_csv(ATTENDANCE_FILE, "staff_attendance.csv")).pack(anchor="w", pady=10)

    def attendance_form(self):
        if not self._admin_only(): return
        staff = [r for r in self.store.staff() if r.get("Status", "ACTIVE").upper() == "ACTIVE"]
        if not staff:
            messagebox.showinfo("No active staff", "Add an active staff member first."); return
        win = tk.Toplevel(self); win.title("Mark attendance"); win.configure(bg=NAVY); win.geometry("470x560")
        win.transient(self); win.grab_set()
        self.label(win, "DAILY ATTENDANCE", 15, CYAN, True, bg=NAVY).pack(anchor="w", padx=24, pady=20)
        ids = [f'{r["Staff ID"]} — {r["Name"]}' for r in staff]
        self.label(win, "STAFF MEMBER", 8, MUTED, True, bg=NAVY).pack(anchor="w", padx=24)
        who = ttk.Combobox(win, values=ids, state="readonly"); who.pack(fill="x", padx=24, pady=(5, 14)); who.current(0)
        def field(title, default):
            self.label(win, title.upper(), 8, MUTED, True, bg=NAVY).pack(anchor="w", padx=24)
            e = self.entry(win, width=40); e.pack(fill="x", padx=24, pady=(5, 12)); e.insert(0, default); return e
        date_e = field("Date (YYYY-MM-DD)", datetime.now().strftime("%Y-%m-%d"))
        status = ttk.Combobox(win, values=["PRESENT", "LATE", "ABSENT", "LEAVE"], state="readonly")
        self.label(win, "STATUS", 8, MUTED, True, bg=NAVY).pack(anchor="w", padx=24)
        status.pack(fill="x", padx=24, pady=(5, 12)); status.set("PRESENT")
        time_now = datetime.now().strftime("%H:%M")
        check_in = field("Check in (HH:MM)", time_now)
        check_out = field("Check out (HH:MM)", "")
        notes = field("Notes (optional)", "")
        def save():
            try: datetime.strptime(date_e.get().strip(), "%Y-%m-%d")
            except ValueError:
                messagebox.showerror("Date format", "Use YYYY-MM-DD.", parent=win); return
            selected_id = who.get().split(" — ", 1)[0]
            person = next(r for r in staff if r.get("Staff ID") == selected_id)
            if any(r.get("Date") == date_e.get().strip() and r.get("Staff ID") == selected_id for r in self.store.attendance()):
                messagebox.showerror("Already recorded", "Attendance for this staff member and date already exists.", parent=win); return
            ci, co = check_in.get().strip(), check_out.get().strip()
            for val in (ci, co):
                if val:
                    try: datetime.strptime(val, "%H:%M")
                    except ValueError:
                        messagebox.showerror("Time format", "Use 24-hour HH:MM format.", parent=win); return
            st = status.get()
            if st in ("ABSENT", "LEAVE"): ci = co = ""
            row = {"Date": date_e.get().strip(), "Staff ID": selected_id, "Staff Name": person.get("Name", ""),
                   "Status": st, "Check In": ci, "Check Out": co, "Notes": notes.get().strip(), "Recorded By": self.user["Username"]}
            append_row(ATTENDANCE_FILE, row, ATTENDANCE_FIELDS)
            self.store.audit(self.user["Username"], "STAFF_ATTENDANCE_RECORDED", f"{selected_id} {st} {row['Date']}")
            win.destroy(); self.page_staff_attendance()
        self.button(win, "SAVE ATTENDANCE", save, True).pack(fill="x", padx=24, pady=15)

    def page_staff_performance(self):
        if not self._admin_only(): return
        head = self.page_header("Staff performance", "Record review scores and comments. Scores are manager-entered assessments, not automatic judgments.")
        self.button(head, "+ Add performance review", self.performance_form, True).pack(side="right")
        body = tk.Frame(self.content, bg=NAVY); body.pack(fill="both", expand=True, padx=28, pady=10)
        reviews = sorted(self.store.performance(), key=lambda r: r.get("Date", ""), reverse=True)
        tree = self.make_tree(body, ("date", "id", "name", "metric", "score", "reviewer", "comments"),
            ("Date", "Staff ID", "Staff name", "Review area", "Score / 100", "Reviewer", "Comments"))
        for r in reviews:
            tree.insert("", "end", values=tuple(r.get(k, "") for k in PERFORMANCE_FIELDS))
        scores = {}
        for r in reviews:
            scores.setdefault(r.get("Staff ID", ""), []).append(safe_float(r.get("Score")))
        if scores:
            summary = "     ".join(f"{sid}: {sum(v)/len(v):.1f}/100 avg" for sid, v in sorted(scores.items()))
            self.label(body, "AVERAGE REVIEW SCORES  |  " + summary, 9, CYAN, True, bg=NAVY, wraplength=1000, justify="left").pack(anchor="w", pady=10)
        self.button(body, "Export performance CSV", lambda: self.export_csv(PERFORMANCE_FILE, "staff_performance.csv")).pack(anchor="w", pady=5)

    def performance_form(self):
        if not self._admin_only(): return
        staff = [r for r in self.store.staff() if r.get("Status", "ACTIVE").upper() == "ACTIVE"]
        if not staff:
            messagebox.showinfo("No active staff", "Add an active staff member first."); return
        win = tk.Toplevel(self); win.title("Performance review"); win.configure(bg=NAVY); win.geometry("470x620")
        win.transient(self); win.grab_set()
        self.label(win, "STAFF PERFORMANCE REVIEW", 15, CYAN, True, bg=NAVY).pack(anchor="w", padx=24, pady=20)
        self.label(win, "STAFF MEMBER", 8, MUTED, True, bg=NAVY).pack(anchor="w", padx=24)
        who = ttk.Combobox(win, values=[f'{r["Staff ID"]} — {r["Name"]}' for r in staff], state="readonly")
        who.pack(fill="x", padx=24, pady=(5, 12)); who.current(0)
        def field(title, default=""):
            self.label(win, title.upper(), 8, MUTED, True, bg=NAVY).pack(anchor="w", padx=24)
            e = self.entry(win, width=40); e.pack(fill="x", padx=24, pady=(5, 12)); e.insert(0, default); return e
        date_e = field("Review date (YYYY-MM-DD)", datetime.now().strftime("%Y-%m-%d"))
        metric = field("Review area (e.g. Work quality / Safety / Teamwork)", "Work quality")
        score = field("Score (0–100)", "80")
        reviewer = field("Reviewer", self.user["Username"])
        comments = field("Comments", "")
        def save():
            try:
                datetime.strptime(date_e.get().strip(), "%Y-%m-%d")
                val = float(score.get().strip())
                if not 0 <= val <= 100: raise ValueError
            except ValueError:
                messagebox.showerror("Invalid review", "Enter a valid date and a score from 0 to 100.", parent=win); return
            if not metric.get().strip() or not reviewer.get().strip():
                messagebox.showerror("Required fields", "Review area and reviewer are required.", parent=win); return
            selected_id = who.get().split(" — ", 1)[0]
            person = next(r for r in staff if r.get("Staff ID") == selected_id)
            row = {"Date": date_e.get().strip(), "Staff ID": selected_id, "Staff Name": person.get("Name", ""),
                   "Metric": metric.get().strip(), "Score": f"{val:g}", "Reviewer": reviewer.get().strip(),
                   "Comments": comments.get().strip()}
            append_row(PERFORMANCE_FILE, row, PERFORMANCE_FIELDS)
            self.store.audit(self.user["Username"], "STAFF_PERFORMANCE_RECORDED", f"{selected_id} {val:g}/100")
            win.destroy(); self.page_staff_performance()
        self.button(win, "SAVE PERFORMANCE REVIEW", save, True).pack(fill="x", padx=24, pady=15)

    def page_users(self):
        if self.user["Role"] != "ADMIN":
            messagebox.showerror("Access denied", "Administrator access is required."); return
        head = self.page_header("User administration", "Manage local application accounts and role access.")
        self.button(head, "+ Add user", self.user_form, True).pack(side="right")
        body = tk.Frame(self.content, bg=NAVY); body.pack(fill="both", expand=True, padx=28, pady=10)
        tree = self.make_tree(body, ("username", "role", "active", "created"),
                              ("Username", "Role", "Active", "Created"))
        for u in self.store.users():
            tree.insert("", "end", values=(u.get("Username"), u.get("Role"),
                "Yes" if u.get("Active", "1") != "0" else "No", u.get("CreatedAt")))
        def toggle():
            sel = tree.selection()
            if not sel:
                messagebox.showinfo("Select user", "Select a user."); return
            username = tree.item(sel[0], "values")[0]
            if username == self.user["Username"]:
                messagebox.showwarning("Not allowed", "You cannot deactivate your own active session."); return
            user = next(u for u in self.store.users() if u.get("Username") == username)
            self.store.update_user(username, active=user.get("Active", "1") == "0")
            self.store.audit(self.user["Username"], "USER_STATUS_CHANGED", username)
            self.page_users()
        self.button(body, "Activate / deactivate selected", toggle).pack(anchor="w", pady=10)

    def user_form(self):
        win = tk.Toplevel(self); win.title("Add user"); win.configure(bg=NAVY); win.geometry("420x420")
        self.label(win, "CREATE USER ACCOUNT", 15, CYAN, True, bg=NAVY).pack(anchor="w", padx=24, pady=22)
        fields = {}
        for key, secret in [("Username", False), ("Password", True)]:
            self.label(win, key.upper(), 8, MUTED, True, bg=NAVY).pack(anchor="w", padx=24)
            e = self.entry(win, show="•" if secret else None, width=38)
            e.pack(fill="x", padx=24, pady=(5, 14)); fields[key] = e
        self.label(win, "ROLE", 8, MUTED, True, bg=NAVY).pack(anchor="w", padx=24)
        role = ttk.Combobox(win, values=["ADMIN", "ENGINEER", "VIEWER"], state="readonly")
        role.pack(fill="x", padx=24, pady=(5, 18)); role.set("VIEWER")
        def save():
            try:
                self.store.add_user(fields["Username"].get(), fields["Password"].get(), role.get())
                self.store.audit(self.user["Username"], "USER_CREATED", fields["Username"].get())
                win.destroy(); self.page_users()
            except Exception as exc:
                messagebox.showerror("Could not create user", str(exc), parent=win)
        self.button(win, "CREATE ACCOUNT", save, True).pack(fill="x", padx=24, pady=10)


def main():
    try:
        app = MechCareApp()
        app.mainloop()
    except Exception as exc:
        traceback.print_exc()
        try:
            messagebox.showerror("MechCare startup error", f"{exc}\\n\\nSee terminal output for details.")
        except Exception:
            pass
        raise


if __name__ == "__main__":
    main()
