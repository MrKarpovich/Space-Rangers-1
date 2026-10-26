# -*- coding: utf-8 -*-
"""
Космические Рейнджеры 1 — Трейнер предметов
Пошаговый поиск по цене + авто/ручные правки.

Запуск: python SR1_Trainer.py
Windows + Rangers.exe, желательно от администратора.
"""

import ctypes
import ctypes.wintypes as wt
import struct
import tkinter as tk
from tkinter import ttk, messagebox

# ═══════════════════════════════════════════════════════════
# WinAPI
# ═══════════════════════════════════════════════════════════

PROCESS_ALL = 0x1F0FFF
MEM_COMMIT = 0x1000
PAGE_READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}

kernel32 = ctypes.windll.kernel32
TH32CS_SNAPPROCESS = 0x2


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


def find_pid(substr="Rangers"):
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap in (0, -1, 0xFFFFFFFF):
        return None
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(pe)
    pid = None
    ok = kernel32.Process32FirstW(snap, ctypes.byref(pe))
    while ok:
        if substr.lower() in pe.szExeFile.lower():
            pid = int(pe.th32ProcessID)
            break
        ok = kernel32.Process32NextW(snap, ctypes.byref(pe))
    kernel32.CloseHandle(snap)
    return pid


def rpm(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if not kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(n)):
        return None
    return buf.raw[: n.value]


def wpm(h, addr, data: bytes):
    n = ctypes.c_size_t(0)
    return bool(
        kernel32.WriteProcessMemory(
            h, ctypes.c_void_p(addr), data, len(data), ctypes.byref(n)
        )
    )


def read_i32(h, a):
    b = rpm(h, a, 4)
    return struct.unpack("<i", b)[0] if b and len(b) == 4 else None


def read_u8(h, a):
    b = rpm(h, a, 1)
    return b[0] if b else None


def read_f32(h, a):
    b = rpm(h, a, 4)
    return struct.unpack("<f", b)[0] if b and len(b) == 4 else None


def write_i32(h, a, v):
    return wpm(h, a, struct.pack("<i", int(v)))


def write_u8(h, a, v):
    return wpm(h, a, struct.pack("<B", int(v) & 0xFF))


def write_f32(h, a, v):
    return wpm(h, a, struct.pack("<f", float(v)))


def scan_value_i32(h, value, candidates=None):
    target = struct.pack("<i", int(value))
    out = []
    if candidates is not None:
        for a in candidates:
            b = rpm(h, a, 4)
            if b == target:
                out.append(a)
        return out

    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    while addr < 0x7FFF0000:
        if kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize or 0
        if size == 0:
            break
        prot = mbi.Protect & 0xFF
        if mbi.State == MEM_COMMIT and prot in PAGE_READABLE and 0 < size <= 32 * 1024 * 1024:
            data = rpm(h, base, size)
            if data:
                start = 0
                while True:
                    i = data.find(target, start)
                    if i < 0:
                        break
                    if i % 4 == 0:
                        out.append(base + i)
                    start = i + 4
                    if len(out) > 800000:
                        return out
        nxt = base + size
        if nxt <= addr:
            break
        addr = nxt
    return out


def scan_changed(h, snapshot):
    out = []
    for a, old in snapshot:
        b = rpm(h, a, 4)
        if b is not None and b != old:
            out.append(a)
    return out


def snapshot_values(h, addrs):
    res = []
    for a in addrs:
        b = rpm(h, a, 4)
        if b is not None and len(b) == 4:
            res.append((a, b))
    return res


# ═══════════════════════════════════════════════════════════
# Данные: расы, лимиты, смещения, авто-значения
# ═══════════════════════════════════════════════════════════

RACES = {
    0: "Малоки",
    1: "Пеленги",
    2: "Люди",
    3: "Фэй",
    4: "Гаал",
    5: "Клисаны",
}

# Известные ID моделей оружия (можно дополнять)
WEAPON_MODELS = {
    4424: "Адская волна",
    3104: "Промышленный лазер",
}

# Лимиты (чтобы не крашило)
LIMITS = {
    "race": (0, 5),
    "level": (1, 8),
    "type": (33, 47),          # TWeapon диапазон
    "wpn_id": (0, 999999),
    "weight": (0, 9999),
    "price": (0, 999999999),
    "range": (0, 99999),
    "min_dmg": (0, 255),
    "max_dmg": (0, 255),
    "speed": (0, 99999),
    "warp": (0, 255),
    "volume": (0, 255),
    "filled": (0, 255),
    "regen": (0, 255),
    "power": (0, 99999),
    "prot": (0.0, 1.0),        # float множитель урона
    "radar_range": (0, 999999),
    "scan_power": (0, 255),
}

# preset-списки для выпадашек в ручном режиме
PRESETS = {
    "race": [(i, f"{i} — {RACES[i]}") for i in range(6)],
    "level": [(i, f"{i}") for i in range(1, 9)],
    "type": [(i, f"{i}") for i in range(33, 48)],
    "wpn_id": [
        (4424, "4424 — Адская волна"),
        (3104, "3104 — Промышленный лазер"),
    ],
    "weight": [(1, "1"), (10, "10"), (20, "20"), (50, "50")],
    "price": [(730000, "730000"), (1000, "1000"), (500, "500")],
    "range": [(9999, "9999"), (5000, "5000"), (1000, "1000")],
    "min_dmg": [(255, "255"), (100, "100"), (50, "50")],
    "max_dmg": [(255, "255"), (100, "100"), (50, "50")],
    "speed": [(2600, "2600"), (1000, "1000")],
    "warp": [(255, "255"), (50, "50")],
    "volume": [(255, "255"), (40, "40")],
    "filled": [(255, "255"), (40, "40")],
    "regen": [(255, "255"), (60, "60")],
    "power": [(9999, "9999"), (500, "500")],
    "prot": [
        (0.95, "0.95 → 5%"),
        (0.60, "0.60 → 40%"),
        (0.50, "0.50 → 50%"),
        (0.20, "0.20 → 80%"),
        (0.10, "0.10 → 90%"),
        (0.01, "0.01 → 99%"),
        (0.00, "0.00 → 100%"),
    ],
    "radar_range": [(30000, "30000"), (5000, "5000")],
    "scan_power": [(255, "255"), (41, "41")],
}

# off = смещение от адреса ЦЕНЫ
# price всегда offset 0 (сам якорь)
ITEM_DEFS = {
    "Оружие": {
        "fields": [
            # key, offset, type, label
            ("price", 0, "i32", "Цена"),
            ("weight", -0x08, "i32", "Вес"),
            ("race", -0x04, "i32", "Раса"),
            ("type", -0x14, "i32", "Type оружия (33-47)"),
            ("wpn_id", -0x18, "i32", "ID модели"),
            ("level", +0x28, "i32", "Уровень (1-8)"),
            ("range", +0x2C, "i32", "Дальность"),
            ("min_dmg", +0x30, "u8", "Мин. урон"),
            ("max_dmg", +0x31, "u8", "Макс. урон"),
        ],
        # Авто: всё как ты просил
        "auto": [
            ("price", 730000),
            ("weight", 1),
            ("race", 5),
            ("type", 46),
            ("wpn_id", 4424),
            ("level", 8),
            ("range", 9999),
            ("min_dmg", 255),
            ("max_dmg", 255),
        ],
    },
    "Двигатель": {
        "fields": [
            ("price", 0, "i32", "Цена"),
            ("weight", -0x08, "i32", "Вес"),
            ("race", -0x04, "i32", "Раса"),
            ("level", +0x28, "i32", "Уровень (1-8)"),
            ("speed", +0x2C, "i32", "Скорость"),
            ("warp", +0x30, "u8", "Варп"),
        ],
        "auto": [
            ("price", 730000),
            ("weight", 1),
            ("race", 5),
            ("level", 8),
            ("speed", 2600),
            ("warp", 255),
        ],
    },
    "Топливный бак": {
        "fields": [
            ("price", 0, "i32", "Цена"),
            ("weight", -0x08, "i32", "Вес"),
            ("race", -0x04, "i32", "Раса"),
            ("level", +0x28, "i32", "Уровень (1-8)"),
            ("volume", +0x2C, "u8", "Объём"),
            ("filled", +0x30, "u8", "Залито"),
        ],
        "auto": [
            ("price", 730000),
            ("weight", 1),
            ("race", 5),
            ("level", 8),
            ("volume", 255),
            ("filled", 255),
        ],
    },
    "Дрон": {
        "fields": [
            ("price", 0, "i32", "Цена"),
            ("weight", -0x08, "i32", "Вес"),
            ("race", -0x04, "i32", "Раса"),
            ("level", +0x28, "u8", "Уровень (1-8)"),
            ("regen", +0x29, "u8", "Регенерация"),
        ],
        "auto": [
            ("price", 730000),
            ("weight", 1),
            ("race", 5),
            ("level", 8),
            ("regen", 255),
        ],
    },
    "Захват": {
        "fields": [
            ("price", 0, "i32", "Цена"),
            ("weight", -0x08, "i32", "Вес"),
            ("race", -0x04, "i32", "Раса"),
            ("level", +0x28, "u8", "Уровень (1-8)"),
            ("power", +0x2C, "i32", "Сила захвата"),
        ],
        "auto": [
            ("price", 730000),
            ("weight", 1),
            ("race", 5),
            ("level", 8),
            ("power", 9999),
        ],
    },
    "Защита (щит)": {
        "fields": [
            ("price", 0, "i32", "Цена"),
            ("weight", -0x08, "i32", "Вес"),
            ("race", -0x04, "i32", "Раса"),
            ("level", +0x28, "u8", "Уровень (1-8)"),
            ("prot", +0x2C, "f32", "Защита float"),
        ],
        "auto": [
            ("price", 730000),
            ("weight", 1),
            ("race", 5),
            ("level", 8),
            ("prot", 0.10),
        ],
    },
    "Радар": {
        "fields": [
            ("price", 0, "i32", "Цена"),
            ("weight", -0x08, "i32", "Вес"),
            ("race", -0x04, "i32", "Раса"),
            ("level", +0x28, "u8", "Уровень (1-8)"),
            ("radar_range", +0x2C, "i32", "Дальность радара"),
        ],
        "auto": [
            ("price", 730000),
            ("weight", 1),
            ("race", 5),
            ("level", 8),
            ("radar_range", 30000),
        ],
    },
    "Сканер": {
        "fields": [
            ("price", 0, "i32", "Цена"),
            ("weight", -0x08, "i32", "Вес"),
            ("race", -0x04, "i32", "Раса"),
            ("level", +0x28, "u8", "Уровень (1-8)"),
            ("scan_power", +0x29, "u8", "Мощность"),
        ],
        "auto": [
            ("price", 730000),
            ("weight", 1),
            ("race", 5),
            ("level", 8),
            ("scan_power", 255),
        ],
    },
}


def format_value(key, v):
    if v is None:
        return "—"
    if key == "race" and isinstance(v, int) and v in RACES:
        return f"{v} ({RACES[v]})"
    if key == "wpn_id" and v in WEAPON_MODELS:
        return f"{v} ({WEAPON_MODELS[v]})"
    if key == "prot" and isinstance(v, float):
        return f"{v:.4f}  (~{(1.0 - v) * 100:.0f}% защиты)"
    if isinstance(v, float):
        return f"{v:.6g}"
    return str(v)


def clamp_ok(key, val):
    """Проверка лимитов. Возвращает (ok, message)."""
    if key not in LIMITS:
        return True, ""
    lo, hi = LIMITS[key]
    try:
        if key == "prot":
            fv = float(val)
            if not (lo <= fv <= hi):
                return False, f"Защита float только {lo}…{hi} (0.95=5%, 0.10=90%)"
        else:
            iv = int(val)
            if not (lo <= iv <= hi):
                return False, f"{key}: допустимо {lo}…{hi}"
    except (TypeError, ValueError):
        return False, "Неверное число"
    return True, ""


# ═══════════════════════════════════════════════════════════
# UI
# ═══════════════════════════════════════════════════════════

class App:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SR1 Trainer — Космические Рейнджеры 1")
        self.root.geometry("700x780")
        self.root.minsize(620, 680)

        self.hproc = None
        self.pid = None
        self.addrs = []
        self.snapshot = []
        self.price_addr = None

        self._build()
        self._set_phase_idle()

    def log(self, msg):
        self.txt_log.insert(tk.END, msg + "\n")
        self.txt_log.see(tk.END)

    def set_hint(self, text):
        self.lbl_hint.config(text=text)

    def set_status(self, text):
        self.lbl_status.config(text=text)

    def _build(self):
        pad = {"padx": 8, "pady": 3}
        top = ttk.Frame(self.root, padding=8)
        top.pack(fill=tk.BOTH, expand=True)

        # 1. Игра
        f = ttk.LabelFrame(top, text="1. Игра", padding=6)
        f.pack(fill=tk.X, **pad)
        ttk.Button(f, text="Подключить к Rangers.exe", command=self.connect).pack(side=tk.LEFT)
        self.lbl_proc = ttk.Label(f, text="не подключено")
        self.lbl_proc.pack(side=tk.LEFT, padx=10)

        # 2. Что ищем
        f = ttk.LabelFrame(top, text="2. Что ищем", padding=6)
        f.pack(fill=tk.X, **pad)
        row = ttk.Frame(f)
        row.pack(fill=tk.X)
        ttk.Label(row, text="Тип предмета:").pack(side=tk.LEFT)
        self.cmb_type = ttk.Combobox(
            row, values=list(ITEM_DEFS.keys()), state="readonly", width=22
        )
        self.cmb_type.set("Оружие")
        self.cmb_type.pack(side=tk.LEFT, padx=6)
        self.cmb_type.bind("<<ComboboxSelected>>", lambda e: self._on_type_changed())

        row = ttk.Frame(f)
        row.pack(fill=tk.X, pady=4)
        ttk.Label(row, text="Цена (когда предмет В РУКЕ):").pack(side=tk.LEFT)
        self.ent_price = ttk.Entry(row, width=12)
        self.ent_price.insert(0, "500")
        self.ent_price.pack(side=tk.LEFT, padx=6)

        # 3. Поиск
        f = ttk.LabelFrame(top, text="3. Поиск — читай подсказку", padding=6)
        f.pack(fill=tk.X, **pad)
        self.lbl_hint = ttk.Label(
            f, text="", wraplength=660, justify=tk.LEFT, font=("Segoe UI", 10)
        )
        self.lbl_hint.pack(fill=tk.X, anchor=tk.W)

        row = ttk.Frame(f)
        row.pack(fill=tk.X, pady=6)
        ttk.Button(
            row, text="Предмет СЕЙЧАС В РУКЕ — искать", command=self.on_in_hand
        ).pack(side=tk.LEFT, padx=3)
        ttk.Button(
            row, text="Предмет НЕ в руках — искать", command=self.on_not_hand
        ).pack(side=tk.LEFT, padx=3)
        ttk.Button(row, text="Новый поиск", command=self.on_new_search).pack(
            side=tk.LEFT, padx=10
        )

        self.lbl_status = ttk.Label(f, text="Кандидатов: —", font=("Segoe UI", 10, "bold"))
        self.lbl_status.pack(anchor=tk.W)

        # 4. Характеристики — таблица
        f = ttk.LabelFrame(top, text="4. Комплектация / характеристики предмета", padding=6)
        f.pack(fill=tk.BOTH, expand=False, **pad)

        cols = ("param", "value", "offset")
        self.tree = ttk.Treeview(f, columns=cols, show="headings", height=9)
        self.tree.heading("param", text="Параметр")
        self.tree.heading("value", text="Значение")
        self.tree.heading("offset", text="Смещение")
        self.tree.column("param", width=220, anchor=tk.W)
        self.tree.column("value", width=280, anchor=tk.W)
        self.tree.column("offset", width=100, anchor=tk.CENTER)
        self.tree.pack(fill=tk.BOTH, expand=True)

        row = ttk.Frame(f)
        row.pack(fill=tk.X, pady=4)
        ttk.Button(row, text="Авто-прокачка", command=self.do_auto).pack(side=tk.LEFT, padx=2)
        ttk.Button(row, text="Обновить чтение", command=self.refresh).pack(side=tk.LEFT, padx=2)

        # 5. Ручное
        f = ttk.LabelFrame(top, text="5. Ручное изменение", padding=6)
        f.pack(fill=tk.X, **pad)

        row = ttk.Frame(f)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Параметр:").pack(side=tk.LEFT)
        self.cmb_field = ttk.Combobox(row, width=36, state="readonly")
        self.cmb_field.pack(side=tk.LEFT, padx=4)
        self.cmb_field.bind("<<ComboboxSelected>>", lambda e: self._on_field_chosen())

        row = ttk.Frame(f)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Значение:").pack(side=tk.LEFT)
        self.cmb_preset = ttk.Combobox(row, width=36)
        self.cmb_preset.pack(side=tk.LEFT, padx=4)
        ttk.Label(row, text="или своё:").pack(side=tk.LEFT, padx=(8, 0))
        self.ent_val = ttk.Entry(row, width=12)
        self.ent_val.pack(side=tk.LEFT, padx=4)
        ttk.Button(row, text="Записать", command=self.do_manual).pack(side=tk.LEFT, padx=4)

        self.lbl_limit = ttk.Label(f, text="", foreground="#555")
        self.lbl_limit.pack(anchor=tk.W)

        # Лог
        f = ttk.LabelFrame(top, text="Лог", padding=4)
        f.pack(fill=tk.BOTH, expand=True, **pad)
        self.txt_log = tk.Text(f, height=7, font=("Consolas", 9))
        self.txt_log.pack(fill=tk.BOTH, expand=True)

        self._on_type_changed()

    def _on_type_changed(self):
        defn = ITEM_DEFS[self.cmb_type.get()]
        labels = [lab for _k, _o, _t, lab in defn["fields"]]
        self.cmb_field["values"] = labels
        if labels:
            self.cmb_field.current(0)
            self._on_field_chosen()
        if self.price_addr:
            self.refresh()

    def _current_field_meta(self):
        defn = ITEM_DEFS[self.cmb_type.get()]
        idx = self.cmb_field.current()
        if idx < 0:
            return None
        return defn["fields"][idx]  # key, off, typ, lab

    def _on_field_chosen(self):
        meta = self._current_field_meta()
        if not meta:
            return
        key, off, typ, lab = meta
        presets = PRESETS.get(key, [])
        self.cmb_preset["values"] = [p[1] for p in presets]
        self._preset_map = {p[1]: p[0] for p in presets}
        if presets:
            self.cmb_preset.current(0)
            self.ent_val.delete(0, tk.END)
            self.ent_val.insert(0, str(presets[0][0]))
        else:
            self.cmb_preset.set("")
            self.ent_val.delete(0, tk.END)
        lo_hi = LIMITS.get(key)
        if lo_hi:
            self.lbl_limit.config(text=f"Допустимо: {lo_hi[0]} … {lo_hi[1]}")
        else:
            self.lbl_limit.config(text="")

        def on_preset(_e=None):
            label = self.cmb_preset.get()
            if label in self._preset_map:
                self.ent_val.delete(0, tk.END)
                self.ent_val.insert(0, str(self._preset_map[label]))

        self.cmb_preset.bind("<<ComboboxSelected>>", on_preset)

    def _set_phase_idle(self):
        self.addrs = []
        self.snapshot = []
        self.price_addr = None
        self.set_status("Кандидатов: —")
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.set_hint(
            "1) Подключись к игре.\n"
            "2) Выбери тип и впиши цену предмета.\n"
            "3) Возьми предмет В РУКУ.\n"
            "4) «Предмет СЕЙЧАС В РУКЕ — искать»."
        )

    def _set_phase_searching(self):
        n = len(self.addrs)
        self.set_status(f"Кандидатов: {n}")
        if n == 0:
            self.set_hint("Адресов не осталось. «Новый поиск».")
        elif n == 1:
            self._accept(self.addrs[0])
        else:
            self.set_hint(
                f"Кандидатов: {n}.\n"
                "• В РУКЕ, цена как в поле → снова «В РУКЕ — искать».\n"
                "• Убрал с руки → «НЕ в руках — искать».\n"
                "Можно жать одну кнопку несколько раз. Чередуй, пока не останется 1."
            )

    def _accept(self, addr):
        self.price_addr = addr
        self.addrs = [addr]
        self.set_status(f"Найден 1 адрес цены: {hex(addr)}")
        self.set_hint(
            "Предмет найден! Смотри таблицу характеристик.\n"
            "«Авто-прокачка» — все поля как в пресете (цена 730000, вес 1, клисаны, …).\n"
            "Или ручное изменение. После записи переложи предмет в игре."
        )
        self.log(f"OK адрес цены = {hex(addr)}")
        self.refresh()

    def connect(self):
        pid = find_pid("Rangers")
        if not pid:
            messagebox.showerror("Ошибка", "Rangers.exe не найден.")
            return
        h = kernel32.OpenProcess(PROCESS_ALL, False, pid)
        if not h:
            messagebox.showerror("Ошибка", "Открой трейнер от администратора.")
            return
        if self.hproc:
            kernel32.CloseHandle(self.hproc)
        self.hproc = h
        self.pid = pid
        self.lbl_proc.config(text=f"PID {pid} — ОК")
        self.log(f"Подключено PID={pid}")

    def _need(self):
        if not self.hproc:
            messagebox.showwarning("!", "Сначала подключись к игре.")
            return False
        return True

    def _price_input(self):
        try:
            return int(self.ent_price.get().strip())
        except ValueError:
            messagebox.showerror("!", "Цена — целое число.")
            return None

    def on_new_search(self):
        self._set_phase_idle()
        self.log("—— Новый поиск ——")

    def on_in_hand(self):
        if not self._need():
            return
        price = self._price_input()
        if price is None:
            return
        self.root.config(cursor="watch")
        self.root.update()
        try:
            if not self.addrs:
                self.log(f"Полный скан (В РУКЕ), цена={price}…")
                self.addrs = scan_value_i32(self.hproc, price, None)
                self.log(f"Найдено: {len(self.addrs)}")
            else:
                self.log(f"Фильтр В РУКЕ, цена={price}, было {len(self.addrs)}…")
                self.addrs = scan_value_i32(self.hproc, price, self.addrs)
                self.log(f"Осталось: {len(self.addrs)}")
            self.snapshot = snapshot_values(self.hproc, self.addrs)
            self._set_phase_searching()
        finally:
            self.root.config(cursor="")

    def on_not_hand(self):
        if not self._need():
            return
        if not self.addrs and not self.snapshot:
            messagebox.showinfo("!", "Сначала «В РУКЕ — искать».")
            return
        self.root.config(cursor="watch")
        self.root.update()
        try:
            if not self.snapshot:
                self.snapshot = snapshot_values(self.hproc, self.addrs)
            self.log(f"Фильтр НЕ в руках, было {len(self.snapshot)}…")
            self.addrs = scan_changed(self.hproc, self.snapshot)
            self.log(f"Осталось: {len(self.addrs)}")
            self.snapshot = snapshot_values(self.hproc, self.addrs)
            self._set_phase_searching()
        finally:
            self.root.config(cursor="")

    def _read_field(self, off, typ):
        a = self.price_addr + off
        if typ == "i32":
            return read_i32(self.hproc, a)
        if typ == "u8":
            return read_u8(self.hproc, a)
        return read_f32(self.hproc, a)

    def _write_field(self, off, typ, val):
        a = self.price_addr + off
        if typ == "i32":
            return write_i32(self.hproc, a, val)
        if typ == "u8":
            return write_u8(self.hproc, a, val)
        return write_f32(self.hproc, a, val)

    def refresh(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        if not self.price_addr or not self.hproc:
            return
        defn = ITEM_DEFS[self.cmb_type.get()]
        for key, off, typ, lab in defn["fields"]:
            v = self._read_field(off, typ)
            self.tree.insert(
                "",
                tk.END,
                values=(lab, format_value(key, v), f"{off:+#x}"),
            )

    def do_auto(self):
        if not self.price_addr:
            messagebox.showinfo("!", "Сначала найди предмет.")
            return
        defn = ITEM_DEFS[self.cmb_type.get()]
        fmap = {k: (o, t) for k, o, t, _ in defn["fields"]}
        errors = []
        for key, val in defn["auto"]:
            if key not in fmap:
                continue
            ok, msg = clamp_ok(key, val)
            if not ok:
                errors.append(msg)
                continue
            off, typ = fmap[key]
            if self._write_field(off, typ, val):
                self.log(f"AUTO {key} = {val}")
            else:
                errors.append(f"не записалось: {key}")
        self.refresh()
        if errors:
            messagebox.showwarning("Частично", "\n".join(errors))
        else:
            messagebox.showinfo(
                "Готово",
                "Авто-прокачка:\n"
                "цена 730000, вес 1, раса Клисаны (5),\n"
                "уровень 8, макс. характеристики"
                + (", Type 46, ID 4424 (Адская волна)" if self.cmb_type.get() == "Оружие" else "")
                + "\n\nПереложи предмет в игре.",
            )

    def do_manual(self):
        if not self.price_addr:
            messagebox.showinfo("!", "Сначала найди предмет.")
            return
        meta = self._current_field_meta()
        if not meta:
            return
        key, off, typ, lab = meta
        raw = self.ent_val.get().strip().replace(",", ".")
        # если выбран пресет — берём число из карты
        label = self.cmb_preset.get()
        if hasattr(self, "_preset_map") and label in self._preset_map and not raw:
            val = self._preset_map[label]
        else:
            try:
                val = float(raw) if typ == "f32" else int(raw, 0)
            except ValueError:
                messagebox.showerror("!", "Неверное число")
                return

        ok, msg = clamp_ok(key, val)
        if not ok:
            messagebox.showwarning("Лимит", msg + "\nИначе возможен краш.")
            return

        if self._write_field(off, typ, val):
            self.log(f"Записано: {lab} = {val}")
            self.refresh()
        else:
            messagebox.showerror("!", "Ошибка записи")

    def run(self):
        self.root.mainloop()
        if self.hproc:
            kernel32.CloseHandle(self.hproc)


if __name__ == "__main__":
    App().run()
