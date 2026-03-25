from __future__ import annotations

import os
import secrets
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional

from flask import g
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "app.db")

DEFAULT_OWNER_USERNAME = "owner"
DEFAULT_OWNER_EMAIL = ""

UKR_SLUG_MAP = {
    "а": "a",
    "б": "b",
    "в": "v",
    "г": "h",
    "ґ": "g",
    "д": "d",
    "е": "e",
    "є": "ye",
    "ж": "zh",
    "з": "z",
    "и": "y",
    "і": "i",
    "ї": "yi",
    "й": "i",
    "к": "k",
    "л": "l",
    "м": "m",
    "н": "n",
    "о": "o",
    "п": "p",
    "р": "r",
    "с": "s",
    "т": "t",
    "у": "u",
    "ф": "f",
    "х": "kh",
    "ц": "ts",
    "ч": "ch",
    "ш": "sh",
    "щ": "shch",
    "ю": "yu",
    "я": "ya",
    "ь": "",
    "’": "",
    "'": "",
}


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        os.makedirs(DATA_DIR, exist_ok=True)
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def close_db(exception: Optional[BaseException]) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def slugify_uk(text: str) -> str:
    text = text.strip().lower()
    result = []
    for ch in text:
        if ch.isalnum():
            result.append(UKR_SLUG_MAP.get(ch, ch))
        elif ch.isspace() or ch in {"-", "_"}:
            result.append("-")
    slug = "".join(result)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-")


def ensure_menu_urls(cursor) -> None:
    cursor.execute("SELECT id, parent_id, title, url FROM menu_items")
    rows = cursor.fetchall()

    if not rows:
        return

    children_map: Dict[int, List[int]] = {}
    student_root_id: Optional[int] = None

    for row in rows:
        parent_id = row["parent_id"]
        if parent_id is not None:
            children_map.setdefault(parent_id, []).append(row["id"])
        if row["parent_id"] is None and row["title"].strip().lower() == "студенту":
            student_root_id = row["id"]

    student_ids: List[int] = []
    if student_root_id is not None:
        stack = [student_root_id]
        while stack:
            current = stack.pop()
            student_ids.append(current)
            stack.extend(children_map.get(current, []))

    student_ids_set = set(student_ids)

    for row in rows:
        item_id = row["id"]
        url = (row["url"] or "").strip()

        if item_id in student_ids_set:
            if not url or url == "#" or url.startswith("/page/"):
                cursor.execute(
                    "UPDATE menu_items SET url = ? WHERE id = ?",
                    (f"/section/{item_id}", item_id),
                )
            continue

        if not url or url == "#":
            cursor.execute(
                "UPDATE menu_items SET url = ? WHERE id = ?",
                (f"/section/{item_id}", item_id),
            )


def init_db() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    cursor = conn.cursor()

    def exec_db(query: str, args: tuple = ()) -> None:
        cursor.execute(query, args)

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          email TEXT,
          role TEXT NOT NULL,
          last_name TEXT,
          first_name TEXT,
          middle_name TEXT,
          position TEXT,
          profile_text TEXT,
          created_at TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS menu_items (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          parent_id INTEGER,
          title TEXT NOT NULL,
          url TEXT NOT NULL,
          sort_order INTEGER NOT NULL DEFAULT 0,
          FOREIGN KEY(parent_id) REFERENCES menu_items(id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS articles (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL,
          summary TEXT NOT NULL,
          content TEXT NOT NULL,
          category TEXT NOT NULL,
          section_id INTEGER,
          published_date TEXT NOT NULL,
          event_date TEXT,
          external_link TEXT,
          featured_image TEXT,
          image_gallery TEXT,
          author_id INTEGER,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          FOREIGN KEY(author_id) REFERENCES users(id),
          FOREIGN KEY(section_id) REFERENCES menu_items(id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS course_applications (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          full_name TEXT NOT NULL,
          previous_school TEXT NOT NULL,
          study_years TEXT NOT NULL,
          phone TEXT NOT NULL,
          telegram_username TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'Нова',
          created_at TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS admission_questions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          full_name TEXT NOT NULL,
          phone TEXT,
          email TEXT,
          question TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'Нове',
          created_at TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS home_promos (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL,
          description TEXT,
          image_path TEXT,
          block_size TEXT NOT NULL DEFAULT 'md',
          button_text TEXT,
          button_url TEXT NOT NULL DEFAULT '#',
          button_size TEXT NOT NULL DEFAULT 'md',
          button_bg_color TEXT NOT NULL DEFAULT '#0b5ed7',
          button_text_color TEXT NOT NULL DEFAULT '#ffffff',
          button_position TEXT NOT NULL DEFAULT 'center',
          sort_order INTEGER NOT NULL DEFAULT 0,
          is_active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS site_settings (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )
        """
    )

    def column_exists(table_name: str, column_name: str) -> bool:
        cursor.execute(f"PRAGMA table_info({table_name})")
        return any(row["name"] == column_name for row in cursor.fetchall())

    if not column_exists("users", "last_name"):
        cursor.execute("ALTER TABLE users ADD COLUMN last_name TEXT")
    if not column_exists("users", "email"):
        cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")
    if not column_exists("users", "first_name"):
        cursor.execute("ALTER TABLE users ADD COLUMN first_name TEXT")
    if not column_exists("users", "middle_name"):
        cursor.execute("ALTER TABLE users ADD COLUMN middle_name TEXT")
    if not column_exists("users", "position"):
        cursor.execute("ALTER TABLE users ADD COLUMN position TEXT")
    if not column_exists("users", "profile_text"):
        cursor.execute("ALTER TABLE users ADD COLUMN profile_text TEXT")

    if not column_exists("articles", "featured_image"):
        cursor.execute("ALTER TABLE articles ADD COLUMN featured_image TEXT")
    if not column_exists("articles", "image_gallery"):
        cursor.execute("ALTER TABLE articles ADD COLUMN image_gallery TEXT")
    if not column_exists("articles", "author_id"):
        cursor.execute("ALTER TABLE articles ADD COLUMN author_id INTEGER")

    if not column_exists("home_promos", "block_size"):
        cursor.execute("ALTER TABLE home_promos ADD COLUMN block_size TEXT NOT NULL DEFAULT 'md'")
    if not column_exists("course_applications", "status"):
        cursor.execute("ALTER TABLE course_applications ADD COLUMN status TEXT NOT NULL DEFAULT 'Нова'")
    if not column_exists("admission_questions", "status"):
        cursor.execute("ALTER TABLE admission_questions ADD COLUMN status TEXT NOT NULL DEFAULT 'Нове'")

    cursor.execute(
        """
        UPDATE articles
        SET summary = ''
        WHERE LOWER(TRIM(COALESCE(summary, ''))) = 'none'
        """
    )
    cursor.execute(
        """
        UPDATE articles
        SET event_date = NULL
        WHERE LOWER(TRIM(COALESCE(event_date, ''))) = 'none'
        """
    )
    cursor.execute(
        """
        UPDATE articles
        SET external_link = NULL
        WHERE LOWER(TRIM(COALESCE(external_link, ''))) = 'none'
        """
    )
    cursor.execute(
        """
        UPDATE home_promos
        SET description = NULL
        WHERE LOWER(TRIM(COALESCE(description, ''))) = 'none'
        """
    )
    cursor.execute(
        """
        UPDATE home_promos
        SET button_text = NULL
        WHERE LOWER(TRIM(COALESCE(button_text, ''))) = 'none'
        """
    )
    cursor.execute(
        """
        UPDATE home_promos
        SET button_url = '#'
        WHERE LOWER(TRIM(COALESCE(button_url, ''))) = 'none'
        """
    )
    cursor.execute(
        """
        UPDATE course_applications
        SET status = 'Нова'
        WHERE status IS NULL OR TRIM(status) = '' OR LOWER(TRIM(status)) = 'none'
        """
    )
    cursor.execute(
        """
        UPDATE admission_questions
        SET status = 'Нове'
        WHERE status IS NULL OR TRIM(status) = '' OR LOWER(TRIM(status)) = 'none'
        """
    )

    cursor.execute("SELECT COUNT(*) AS total FROM users")
    row = cursor.fetchone()
    if row and row["total"] == 0:
        owner_password = secrets.token_urlsafe(12)
        exec_db(
            """
            INSERT INTO users (username, password_hash, email, role, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                DEFAULT_OWNER_USERNAME,
                generate_password_hash(owner_password),
                DEFAULT_OWNER_EMAIL or None,
                "owner",
                datetime.utcnow().isoformat(),
            ),
        )
        print(f"[init] Owner username: {DEFAULT_OWNER_USERNAME}")
        print(f"[init] Generated owner password: {owner_password}")

    cursor.execute("SELECT COUNT(*) AS total FROM menu_items")
    row = cursor.fetchone()
    if row and row["total"] == 0:
        top_items = [
            ("Головна", "/", 1),
            ("Коледж", "#", 2),
            ("Абітурієнту", "/admissions-2026", 3),
            ("Студенту", "#", 4),
            ("Діяльність", "#", 5),
            ("Електронна бібліотека", "#", 6),
            ("Публічна інформація", "#", 7),
            ("Інше", "#", 8),
        ]

        top_ids: Dict[str, int] = {}
        for title, url, sort_order in top_items:
            exec_db(
                """
                INSERT INTO menu_items (parent_id, title, url, sort_order)
                VALUES (?, ?, ?, ?)
                """,
                (None, title, url, sort_order),
            )
            top_ids[title] = cursor.lastrowid

        def add_children(parent_title: str, items: List[str]) -> None:
            parent_id = top_ids[parent_title]
            for idx, label in enumerate(items, start=1):
                exec_db(
                    """
                    INSERT INTO menu_items (parent_id, title, url, sort_order)
                    VALUES (?, ?, ?, ?)
                    """,
                    (parent_id, label, "#", idx),
                )

        add_children(
            "Коледж",
            [
                "Структура та органи правління",
                "Історія",
                "Освітньо-професійні програми",
                "Публічна інформація*",
                "Нормативно-правова база",
                "Матеріально-технічна база",
                "Співпраця",
                "Вакантні посади",
                "Галерея",
                "Контакти",
                "About VPAC",
            ],
        )

        add_children(
            "Студенту",
            [
                "Розклад занять",
                "Рейтинги та стипендія",
                "Соціальна стипендія",
                "Плата за навчання та гуртожиток",
                "Графік освітнього процесу",
                "Графік предметних консультацій",
                "Навчальні плани",
                "Вибіркові освітні компоненти",
                "Неформальна освіта",
                "Психологічна служба",
                "Студентське самоврядування",
                "Правила поведінки здобувачів освіти",
                "Обхідний лист",
            ],
        )

        add_children(
            "Діяльність",
            [
                "Річні плани роботи коледжу",
                "Інноваційна",
                "Волонтерська",
                "Методична",
                "Навчальна",
                "Організаційна",
                "Практична підготовка",
                "Психологічна служба",
                "Проектна",
                "Фінансова",
                "Міжнародна співпраця",
            ],
        )

        add_children(
            "Електронна бібліотека",
            [
                "Допомога з електронними ресурсами",
                "Електронна бібліотека",
            ],
        )

        add_children(
            "Інше",
            [
                "Блоги",
                "Вибори директора",
                "Антикорупційні заходи",
                "Кваліфікаційний центр",
            ],
        )

    ensure_menu_urls(cursor)
    conn.commit()
    conn.close()


def query_db(query: str, args: tuple = (), one: bool = False):
    db = get_db()
    cursor = db.execute(query, args)
    rows = [dict(row) for row in cursor.fetchall()]
    if one:
        return rows[0] if rows else None
    return rows


def execute_db(query: str, args: tuple = ()) -> int:
    db = get_db()
    cursor = db.execute(query, args)
    db.commit()
    return cursor.lastrowid


def get_site_setting(key: str, default: str = "") -> str:
    row = query_db("SELECT value FROM site_settings WHERE key = ?", (key,), one=True)
    if row and row["value"] is not None:
        return str(row["value"])
    return default


def set_site_setting(key: str, value: str) -> None:
    timestamp = datetime.now().isoformat()
    execute_db(
        """
        INSERT INTO site_settings (key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """,
        (key, value, timestamp),
    )
