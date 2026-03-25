from __future__ import annotations

import os
from sqlite3 import IntegrityError
import html
import re
from datetime import datetime
from functools import wraps
from typing import Dict, List, Optional
from html.parser import HTMLParser
from urllib.parse import urlparse

from flask import (
  Flask,
  abort,
  flash,
  jsonify,
  g,
  redirect,
  render_template,
  request,
  send_from_directory,
  session,
  url_for,
)
from werkzeug.utils import secure_filename
from PIL import Image
import json
import uuid
from werkzeug.security import check_password_hash, generate_password_hash

from data.db import close_db, execute_db, get_db, get_site_setting, init_db, query_db, set_site_setting

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARTICLE_CATEGORIES = ["Оголошення", "Подія", "Новина", "Інше"]
COURSE_APPLICATION_STATUSES = [
    "Нова",
    "Зателефоновано",
    "В роботі",
    "Зараховано",
    "Відхилено",
]
ADMISSION_QUESTION_STATUSES = [
    "Нове",
    "В роботі",
    "Відповіли",
    "Закрито",
]
AUTHOR_FULL_NAME_SQL = """
TRIM(
    CASE WHEN COALESCE(users.last_name, '') <> '' THEN users.last_name || ' ' ELSE '' END ||
    CASE WHEN COALESCE(users.first_name, '') <> '' THEN users.first_name || ' ' ELSE '' END ||
    COALESCE(users.middle_name, '')
)
"""


app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"), static_folder=os.path.join(BASE_DIR, "static"))
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-secret")

# File upload configuration
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

_ALLOWED_HTML_TAGS = [
    "a",
    "b",
    "br",
    "div",
    "em",
    "font",
    "h1",
    "h2",
    "h3",
    "h4",
    "i",
    "li",
    "ol",
    "p",
    "span",
    "strong",
    "u",
    "ul",
]

def _is_safe_href(href: str) -> bool:
    href = href.strip()
    if not href:
        return False
    if href.startswith("/"):
        return True
    parsed = urlparse(href)
    return parsed.scheme in {"http", "https", "mailto"}


class _SafeHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._out: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        tag = tag.lower()
        if tag not in _ALLOWED_HTML_TAGS:
            return

        safe_attrs: list[tuple[str, str]] = []
        attrs_dict = {k.lower(): (v if v is not None else "") for k, v in attrs}

        if tag == "a":
            href = attrs_dict.get("href", "")
            if _is_safe_href(href):
                safe_attrs.append(("href", href))
                safe_attrs.append(("target", "_blank"))
                safe_attrs.append(("rel", "noopener noreferrer"))
        elif tag == "font":
            face = attrs_dict.get("face", "").strip()
            size = attrs_dict.get("size", "").strip()
            color = attrs_dict.get("color", "").strip()
            if face and len(face) <= 50:
                safe_attrs.append(("face", face))
            if size.isdigit() and 1 <= int(size) <= 7:
                safe_attrs.append(("size", size))
            if color and len(color) <= 32:
                safe_attrs.append(("color", color))

        if safe_attrs:
            attrs_html = " ".join(f'{k}="{html.escape(v, quote=True)}"' for k, v in safe_attrs)
            self._out.append(f"<{tag} {attrs_html}>")
        else:
            self._out.append(f"<{tag}>")

    def handle_endtag(self, tag: str):
        tag = tag.lower()
        if tag in _ALLOWED_HTML_TAGS and tag != "br":
            self._out.append(f"</{tag}>")

    def handle_startendtag(self, tag: str, attrs):
        tag = tag.lower()
        if tag == "br":
            self._out.append("<br>")

    def handle_data(self, data: str):
        self._out.append(html.escape(data))

    def get_html(self) -> str:
        return "".join(self._out)


def sanitize_html(value: str | None) -> str:
    if not value:
        return ""
    # If older versions stored escaped HTML, restore it once.
    if "&lt;" in value and "<" not in value:
        value = html.unescape(value)
    parser = _SafeHTML()
    parser.feed(value)
    parser.close()
    return parser.get_html()


@app.template_filter("sanitize_html")
def sanitize_html_filter(value: str | None) -> str:
    return sanitize_html(value)


@app.template_filter("clean_text")
def clean_text_filter(value):
    if value is None:
        return ""
    if isinstance(value, str) and value.strip().lower() == "none":
        return ""
    return value


def _upload_folder_posix() -> str:
    return UPLOAD_FOLDER.replace("\\", "/").strip("/")


def normalize_upload_ref(path: str | None) -> str | None:
    if not path:
        return None
    posix = str(path).replace("\\", "/")
    marker = _upload_folder_posix() + "/"
    if posix.startswith(marker):
        return posix[len(marker):].lstrip("/")
    if marker in posix:
        return posix.split(marker, 1)[1].lstrip("/")
    return posix.lstrip("/")


def upload_fs_path(path: str | None) -> str | None:
    if not path:
        return None
    if os.path.isabs(path):
        return path
    rel = normalize_upload_ref(path) or ""
    return os.path.join(BASE_DIR, UPLOAD_FOLDER, *rel.split("/"))


def uploads_url(path: str | None) -> str:
    rel = normalize_upload_ref(path)
    if not rel:
        return ""
    return url_for("uploaded_files", filename=rel)


app.jinja_env.globals["uploads_url"] = uploads_url

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def allowed_pdf(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() == "pdf"


def normalize_hex_color(value: str | None, default: str) -> str:
    if not value:
        return default
    candidate = value.strip()
    if re.fullmatch(r"#[0-9a-fA-F]{6}", candidate):
        return candidate.lower()
    if re.fullmatch(r"#[0-9a-fA-F]{3}", candidate):
        return candidate.lower()
    return default


def normalize_button_url(value: str | None) -> str:
    if not value:
        return "#"
    candidate = value.strip()
    if candidate.startswith(("/", "#")):
        return candidate
    parsed = urlparse(candidate)
    if parsed.scheme in {"http", "https", "mailto", "tel"}:
        return candidate
    return "#"


def normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if cleaned.lower() == "none":
        return None
    return cleaned


def user_display_name(row: dict | None) -> str:
    if not row:
        return ""
    last_name = (row.get("last_name") if isinstance(row, dict) else row["last_name"]) or ""
    first_name = (row.get("first_name") if isinstance(row, dict) else row["first_name"]) or ""
    middle_name = (row.get("middle_name") if isinstance(row, dict) else row["middle_name"]) or ""
    username = (row.get("username") if isinstance(row, dict) else row["username"]) or ""
    full = " ".join(part for part in [last_name, first_name, middle_name] if part).strip()
    return full or username


def humanize_membership(created_at: str | None) -> str:
    if not created_at:
        return ""
    try:
        joined = datetime.fromisoformat(created_at.replace("Z", ""))
    except ValueError:
        return ""
    now = datetime.utcnow()
    if now < joined:
        return "менше місяця"
    years = now.year - joined.year - ((now.month, now.day) < (joined.month, joined.day))
    month_delta = (now.year - joined.year) * 12 + (now.month - joined.month)
    if now.day < joined.day:
        month_delta -= 1
    months_only = max(0, month_delta - years * 12)

    year_word = "років"
    if years % 10 == 1 and years % 100 != 11:
        year_word = "рік"
    elif years % 10 in (2, 3, 4) and years % 100 not in (12, 13, 14):
        year_word = "роки"

    month_word = "місяців"
    if months_only % 10 == 1 and months_only % 100 != 11:
        month_word = "місяць"
    elif months_only % 10 in (2, 3, 4) and months_only % 100 not in (12, 13, 14):
        month_word = "місяці"

    if years > 0 and months_only > 0:
        return f"{years} {year_word} {months_only} {month_word}"
    if years > 0:
        return f"{years} {year_word}"
    return f"{months_only} {month_word}"

def resize_image(image_path, max_width=1200, max_height=800):
    """Resize image to fit within specified dimensions while maintaining aspect ratio"""
    try:
        with Image.open(image_path) as img:
            img.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
            img.save(image_path, optimize=True, quality=85)
        return True
    except Exception as e:
        print(f"Error resizing image: {e}")
        return False

@app.template_filter('from_json')
def from_json(value):
    """Parse JSON string to Python object"""
    if value:
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return []
    return []


app.teardown_appcontext(close_db)

init_db()


def build_menu_tree(rows: List[dict]) -> List[dict]:
    items: Dict[int, dict] = {}
    roots: List[dict] = []

    for row in rows:
        items[row["id"]] = {
            "id": row["id"],
            "parent_id": row["parent_id"],
            "title": row["title"],
            "url": row["url"],
            "sort_order": row["sort_order"],
            "children": [],
        }

    for item in items.values():
        parent_id = item["parent_id"]
        if parent_id and parent_id in items:
            items[parent_id]["children"].append(item)
        else:
            roots.append(item)

    def sort_items(nodes: List[dict]) -> List[dict]:
        nodes.sort(key=lambda n: (n["sort_order"], n["title"]))
        for node in nodes:
            node["children"] = sort_items(node["children"])
        return nodes

    return sort_items(roots)


def get_menu_tree() -> List[dict]:
    rows = query_db("SELECT * FROM menu_items ORDER BY sort_order, title")
    return build_menu_tree(rows)


def get_menu_flat() -> List[dict]:
    tree = get_menu_tree()
    flat: List[dict] = []

    def walk(nodes: List[dict], level: int = 0) -> None:
        for node in nodes:
            flat.append({**node, "level": level})
            walk(node["children"], level + 1)

    walk(tree)
    return flat


def find_menu_item(nodes: List[dict], item_id: int) -> Optional[dict]:
    for node in nodes:
        if node["id"] == item_id:
            return node
        found = find_menu_item(node["children"], item_id)
        if found:
            return found
    return None


def get_descendant_ids(section_id: int) -> List[int]:
    rows = query_db("SELECT id, parent_id FROM menu_items")
    children_map: Dict[int, List[int]] = {}
    for row in rows:
        parent = row["parent_id"]
        if parent is not None:
            children_map.setdefault(parent, []).append(row["id"])

    result: List[int] = []

    def walk(node_id: int) -> None:
        result.append(node_id)
        for child_id in children_map.get(node_id, []):
            walk(child_id)

    walk(section_id)
    return result


@app.context_processor
def inject_globals():
    return {
        "menu_items": get_menu_tree(),
        "current_user": g.get("user"),
    }


@app.before_request
def load_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id:
        user = query_db("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
        if user:
            g.user = user


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("login"))
            if g.user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def get_database_tables() -> List[str]:
    rows = query_db(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name NOT LIKE 'sqlite_%'
        ORDER BY name
        """
    )
    return [row["name"] for row in rows]


def get_table_columns(table_name: str) -> List[str]:
    cursor = get_db().execute(f'PRAGMA table_info("{table_name}")')
    return [row["name"] for row in cursor.fetchall()]


def get_table_preview(table_name: str, limit: int = 50) -> List[dict]:
    cursor = get_db().execute(f'SELECT * FROM "{table_name}" ORDER BY 1 DESC LIMIT ?', (limit,))
    return [dict(row) for row in cursor.fetchall()]


def creatable_roles(user_role: str) -> List[str]:
    if user_role == "owner":
        return ["admin", "editor"]
    if user_role == "admin":
        return ["editor"]
    return []


def can_manage_user(actor: dict, target: dict) -> bool:
    if actor["role"] == "owner":
        return True
    if actor["role"] == "admin" and target["role"] == "editor":
        return True
    return False


