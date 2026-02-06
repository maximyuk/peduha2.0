
from __future__ import annotations

import os
import sqlite3
import html
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

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "app.db")

DEFAULT_OWNER_USERNAME = "owner"
DEFAULT_OWNER_PASSWORD = "owner1234"

ARTICLE_CATEGORIES = ["Оголошення", "Подія", "Новина", "Інше"]
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


app = Flask(__name__, template_folder="templates", static_folder="static")
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


def _upload_folder_posix() -> str:
    return UPLOAD_FOLDER.replace("\\", "/").strip("/")


def normalize_upload_ref(path: str | None) -> str | None:
    """
    Normalize stored upload references to a URL-safe relative path under UPLOAD_FOLDER.

    Accepts values like:
    - articles/featured/file.jpg
    - static/uploads/articles/featured/file.jpg
    - static\\uploads\\articles\\featured\\file.jpg
    """
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


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exception: Optional[BaseException]) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL,
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
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          FOREIGN KEY(section_id) REFERENCES menu_items(id)
        )
        """
    )

    # Add new columns if they don't exist (for existing databases)
    cursor.execute("PRAGMA table_info(articles)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if 'featured_image' not in columns:
        cursor.execute("ALTER TABLE articles ADD COLUMN featured_image TEXT")
    
    if 'image_gallery' not in columns:
        cursor.execute("ALTER TABLE articles ADD COLUMN image_gallery TEXT")

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            """
            INSERT INTO users (username, password_hash, role, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                DEFAULT_OWNER_USERNAME,
                generate_password_hash(DEFAULT_OWNER_PASSWORD),
                "owner",
                datetime.utcnow().isoformat(),
            ),
        )

    cursor.execute("SELECT COUNT(*) FROM menu_items")
    if cursor.fetchone()[0] == 0:
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
            cursor.execute(
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
                cursor.execute(
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
            ["Допомога з електронними ресурсами", "Електронна бібліотека"],
        )

        add_children(
            "Інше",
            ["Блоги", "Вибори директора", "Антикорупційні заходи", "Кваліфікаційний центр"],
        )

    ensure_menu_urls(cursor)

    conn.commit()
    conn.close()


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


def ensure_menu_urls(cursor: sqlite3.Cursor) -> None:
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
        title = row["title"]
        url = (row["url"] or "").strip()

        # Студенту розділи повинні бути розділами зі статтями (/section/...), а не сторінками
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


init_db()


def query_db(query: str, args: tuple = (), one: bool = False):
    db = get_db()
    cursor = db.execute(query, args)
    rows = cursor.fetchall()
    cursor.close()
    if one:
        return rows[0] if rows else None
    return rows


def execute_db(query: str, args: tuple = ()) -> int:
    db = get_db()
    cursor = db.execute(query, args)
    db.commit()
    last_id = cursor.lastrowid
    cursor.close()
    return last_id


def build_menu_tree(rows: List[sqlite3.Row]) -> List[dict]:
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


def creatable_roles(user_role: str) -> List[str]:
    if user_role == "owner":
        return ["admin", "editor"]
    if user_role == "admin":
        return ["editor"]
    return []


def can_manage_user(actor: sqlite3.Row, target: sqlite3.Row) -> bool:
    if actor["role"] == "owner":
        return True
    if actor["role"] == "admin" and target["role"] == "editor":
        return True
    return False


@app.route("/")
def index():
    articles = query_db(
        """
        SELECT articles.*, menu_items.title AS section_title
        FROM articles
        LEFT JOIN menu_items ON menu_items.id = articles.section_id
        WHERE articles.section_id IS NULL
        ORDER BY articles.published_date DESC
        LIMIT 3
        """
    )
    return render_template("index.html", active_title="Головна", articles=articles)


@app.route("/admissions-2026")
def admissions():
    return render_template("admissions-2026.html", active_title="Абітурієнту")


@app.route("/page/<slug>")
def page(slug: str):
    if "/" in slug or ".." in slug:
        abort(404)
    file_path = os.path.join(BASE_DIR, "pages", f"{slug}.html")
    content = None
    if os.path.isfile(file_path):
        with open(file_path, "r", encoding="utf-8") as handle:
            content = handle.read()
    menu_item = query_db("SELECT title FROM menu_items WHERE url = ?", (f"/page/{slug}",), one=True)
    page_title = menu_item["title"] if menu_item else slug.replace("-", " ").title()
    return render_template(
        "page.html",
        page_title=page_title,
        content=content,
        active_title=page_title,
    )


@app.route("/section/<int:section_id>")
def section(section_id: int):
    menu_tree = get_menu_tree()
    section_item = find_menu_item(menu_tree, section_id)
    if not section_item:
        abort(404)

    section_ids = get_descendant_ids(section_id)
    placeholders = ",".join("?" * len(section_ids))
    articles = query_db(
        f"""
        SELECT articles.*, menu_items.title AS section_title
        FROM articles
        LEFT JOIN menu_items ON menu_items.id = articles.section_id
        WHERE articles.section_id IN ({placeholders})
        ORDER BY articles.published_date DESC
        """,
        tuple(section_ids),
    )
    return render_template(
        "section.html",
        section_item=section_item,
        articles=articles,
        active_title=section_item["title"],
    )


@app.route("/articles")
def articles():
    category = request.args.get("category", "").strip()
    section_id = request.args.get("section_id", "").strip()

    query = """
        SELECT articles.*, menu_items.title AS section_title
        FROM articles
        LEFT JOIN menu_items ON menu_items.id = articles.section_id
        WHERE 1 = 1
    """
    params: List = []
    if category:
        query += " AND articles.category = ?"
        params.append(category)
    if section_id:
        query += " AND articles.section_id = ?"
        params.append(section_id)

    query += " ORDER BY articles.published_date DESC"
    articles_list = query_db(query, tuple(params))

    categories_to_show = ARTICLE_CATEGORIES
    if category:
        categories_to_show = [category]

    articles_by_category: Dict[str, List[sqlite3.Row]] = {cat: [] for cat in categories_to_show}
    for item in articles_list:
        if item["category"] in articles_by_category:
            articles_by_category[item["category"]].append(item)

    return render_template(
        "articles.html",
        articles_by_category=articles_by_category,
        categories=ARTICLE_CATEGORIES,
        sections=get_menu_flat(),
        selected_category=category,
        selected_section=section_id,
        active_title="",
    )


@app.route("/articles/<int:article_id>")
def article_detail(article_id: int):
    article = query_db(
        """
        SELECT articles.*, menu_items.title AS section_title
        FROM articles
        LEFT JOIN menu_items ON menu_items.id = articles.section_id
        WHERE articles.id = ?
        """,
        (article_id,),
        one=True,
    )
    if not article:
        abort(404)
    return render_template("article_detail.html", article=article, active_title="")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = query_db("SELECT * FROM users WHERE username = ?", (username,), one=True)
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            flash("Вхід успішний.", "success")
            return redirect(url_for("admin_dashboard"))
        flash("Невірний логін або пароль.", "error")
    return render_template("login.html", active_title="")


@app.route("/images/<path:filename>")
def legacy_images(filename: str):
    images_dir = os.path.join(BASE_DIR, "images")
    return send_from_directory(images_dir, filename)


@app.route("/uploads/<path:filename>")
def uploaded_files(filename: str):
    uploads_dir = os.path.join(BASE_DIR, UPLOAD_FOLDER)
    return send_from_directory(uploads_dir, filename)


@app.route("/admin/uploads/pdf", methods=["POST"])
@role_required("owner", "admin", "editor")
def admin_upload_pdf():
    file = request.files.get("pdf")
    if not file or not file.filename:
        return jsonify({"error": "PDF file missing"}), 400
    if not allowed_pdf(file.filename):
        return jsonify({"error": "Only .pdf allowed"}), 400

    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4().hex}_{filename}"
    rel_path = f"articles/pdfs/{unique_filename}"
    upload_path = upload_fs_path(rel_path)
    if not upload_path:
        return jsonify({"error": "Upload path error"}), 500

    os.makedirs(os.path.dirname(upload_path), exist_ok=True)
    file.save(upload_path)
    return jsonify({"url": uploads_url(rel_path), "name": filename, "path": rel_path})


@app.route("/logout")
def logout():
    session.clear()
    flash("Ви вийшли з акаунта.", "success")
    return redirect(url_for("login"))


@app.route("/admin")
@login_required
def admin_dashboard():
    return render_template("admin/dashboard.html", active_title="")


@app.route("/admin/users")
@role_required("owner", "admin")
def admin_users():
    users = query_db("SELECT * FROM users ORDER BY created_at DESC")
    return render_template("admin/users.html", users=users, active_title="")


@app.route("/admin/users/new", methods=["GET", "POST"])
@role_required("owner", "admin")
def admin_user_new():
    roles = creatable_roles(g.user["role"])
    if not roles:
        abort(403)
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role")
        if role not in roles:
            flash("Недоступна роль для створення.", "error")
        elif not username or not password:
            flash("Заповніть логін і пароль.", "error")
        else:
            try:
                execute_db(
                    """
                    INSERT INTO users (username, password_hash, role, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (username, generate_password_hash(password), role, datetime.utcnow().isoformat()),
                )
                flash("Користувача створено.", "success")
                return redirect(url_for("admin_users"))
            except sqlite3.IntegrityError:
                flash("Такий логін уже існує.", "error")
    return render_template("admin/user_form.html", roles=roles, user=None, active_title="")


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@role_required("owner", "admin")
def admin_user_edit(user_id: int):
    user = query_db("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if not user:
        abort(404)
    if not can_manage_user(g.user, user) and g.user["id"] != user["id"]:
        abort(403)

    roles = creatable_roles(g.user["role"])
    if g.user["id"] == user["id"]:
        roles = [user["role"]]
    if g.user["role"] == "admin" and user["role"] != "editor" and g.user["id"] != user["id"]:
        abort(403)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        role = request.form.get("role", user["role"])
        password = request.form.get("password", "")
        if not username:
            flash("Логін не може бути порожнім.", "error")
        else:
            if role not in roles and g.user["id"] != user["id"]:
                role = user["role"]
            execute_db(
                "UPDATE users SET username = ?, role = ? WHERE id = ?",
                (username, role, user_id),
            )
            if password:
                execute_db(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (generate_password_hash(password), user_id),
                )
            flash("Дані користувача оновлено.", "success")
            return redirect(url_for("admin_users"))

    return render_template("admin/user_form.html", roles=roles, user=user, active_title="")


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@role_required("owner", "admin")
def admin_user_delete(user_id: int):
    user = query_db("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if not user:
        abort(404)
    if user["id"] == g.user["id"]:
        flash("Неможливо видалити власний акаунт.", "error")
        return redirect(url_for("admin_users"))
    if not can_manage_user(g.user, user):
        abort(403)
    execute_db("DELETE FROM users WHERE id = ?", (user_id,))
    flash("Користувача видалено.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/menu")
@role_required("owner", "admin", "editor")
def admin_menu():
    items = get_menu_flat()
    return render_template("admin/menu.html", items=items, active_title="")


@app.route("/admin/menu/new", methods=["GET", "POST"])
@role_required("owner", "admin", "editor")
def admin_menu_new():
    parents = get_menu_flat()
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        url_value = request.form.get("url", "").strip() or "#"
        parent_id = request.form.get("parent_id") or None
        parent_id = int(parent_id) if parent_id else None
        sort_order = int(request.form.get("sort_order") or 0)
        if not title:
            flash("Назва обов'язкова.", "error")
        else:
            execute_db(
                """
                INSERT INTO menu_items (parent_id, title, url, sort_order)
                VALUES (?, ?, ?, ?)
                """,
                (parent_id, title, url_value, sort_order),
            )
            flash("Пункт меню створено.", "success")
            return redirect(url_for("admin_menu"))
    return render_template("admin/menu_form.html", item=None, parents=parents, active_title="")


@app.route("/admin/menu/<int:item_id>/edit", methods=["GET", "POST"])
@role_required("owner", "admin", "editor")
def admin_menu_edit(item_id: int):
    item = query_db("SELECT * FROM menu_items WHERE id = ?", (item_id,), one=True)
    if not item:
        abort(404)
    parents = [row for row in get_menu_flat() if row["id"] != item_id]
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        url_value = request.form.get("url", "").strip() or "#"
        parent_id = request.form.get("parent_id") or None
        parent_id = int(parent_id) if parent_id else None
        sort_order = int(request.form.get("sort_order") or 0)
        if not title:
            flash("Назва обов'язкова.", "error")
        else:
            execute_db(
                """
                UPDATE menu_items
                SET parent_id = ?, title = ?, url = ?, sort_order = ?
                WHERE id = ?
                """,
                (parent_id, title, url_value, sort_order, item_id),
            )
            flash("Пункт меню оновлено.", "success")
            return redirect(url_for("admin_menu"))
    return render_template("admin/menu_form.html", item=item, parents=parents, active_title="")


@app.route("/admin/menu/<int:item_id>/delete", methods=["POST"])
@role_required("owner", "admin", "editor")
def admin_menu_delete(item_id: int):
    item = query_db("SELECT * FROM menu_items WHERE id = ?", (item_id,), one=True)
    if not item:
        abort(404)
    execute_db("DELETE FROM menu_items WHERE id = ? OR parent_id = ?", (item_id, item_id))
    flash("Пункт меню видалено.", "success")
    return redirect(url_for("admin_menu"))


@app.route("/admin/articles")
@role_required("owner", "admin", "editor")
def admin_articles():
    articles = query_db(
        """
        SELECT articles.*, menu_items.title AS section_title
        FROM articles
        LEFT JOIN menu_items ON menu_items.id = articles.section_id
        ORDER BY published_date DESC
        """
    )
    return render_template(
        "admin/articles.html",
        articles=articles,
        categories=ARTICLE_CATEGORIES,
        active_title="",
    )


@app.route("/admin/articles/new", methods=["GET", "POST"])
@role_required("owner", "admin", "editor")
def admin_article_new():
    sections = get_menu_flat()
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        summary = request.form.get("summary", "").strip()
        content = request.form.get("content", "").strip()
        category = request.form.get("category", ARTICLE_CATEGORIES[0])
        section_id = request.form.get("section_id") or None
        section_id = int(section_id) if section_id else None
        published_date = request.form.get("published_date") or datetime.utcnow().date().isoformat()
        event_date = request.form.get("event_date") or None
        external_link = request.form.get("external_link", "").strip() or None

        # Handle file uploads
        featured_image = None
        image_gallery = []
        
        # Handle featured image
        if 'featured_image' in request.files:
            file = request.files['featured_image']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                rel_path = f"articles/featured/{unique_filename}"
                upload_path = upload_fs_path(rel_path)
                os.makedirs(os.path.dirname(upload_path), exist_ok=True)
                file.save(upload_path)
                resize_image(upload_path)
                featured_image = rel_path

        # Handle gallery images
        if 'gallery_images' in request.files:
            files = request.files.getlist('gallery_images')
            for file in files:
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    unique_filename = f"{uuid.uuid4().hex}_{filename}"
                    rel_path = f"articles/gallery/{unique_filename}"
                    upload_path = upload_fs_path(rel_path)
                    os.makedirs(os.path.dirname(upload_path), exist_ok=True)
                    file.save(upload_path)
                    resize_image(upload_path)
                    image_gallery.append(rel_path)

        if not title or not content:
            flash("Заповніть назву та текст статті.", "error")
        else:
            execute_db(
                """
                INSERT INTO articles
                (title, summary, content, category, section_id, published_date, event_date, external_link, featured_image, image_gallery, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    title,
                    summary,
                    content,
                    category,
                    section_id,
                    published_date,
                    event_date,
                    external_link,
                    featured_image,
                    json.dumps(image_gallery) if image_gallery else None,
                    datetime.utcnow().isoformat(),
                    datetime.utcnow().isoformat(),
                ),
            )
            flash("Статтю створено.", "success")
            return redirect(url_for("admin_articles"))

    return render_template(
        "admin/article_form.html",
        article=None,
        sections=sections,
        categories=ARTICLE_CATEGORIES,
        active_title="",
    )


@app.route("/admin/articles/<int:article_id>/edit", methods=["GET", "POST"])
@role_required("owner", "admin", "editor")
def admin_article_edit(article_id: int):
    article = query_db("SELECT * FROM articles WHERE id = ?", (article_id,), one=True)
    if not article:
        abort(404)
    sections = get_menu_flat()
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        summary = request.form.get("summary", "").strip()
        content = request.form.get("content", "").strip()
        category = request.form.get("category", ARTICLE_CATEGORIES[0])
        section_id = request.form.get("section_id") or None
        section_id = int(section_id) if section_id else None
        published_date = request.form.get("published_date") or datetime.utcnow().date().isoformat()
        event_date = request.form.get("event_date") or None
        external_link = request.form.get("external_link", "").strip() or None

        # Handle file uploads
        featured_image_raw = article["featured_image"]
        featured_image = normalize_upload_ref(featured_image_raw)
        image_gallery_raw = json.loads(article["image_gallery"]) if article["image_gallery"] else []
        image_gallery = [normalize_upload_ref(p) for p in image_gallery_raw if normalize_upload_ref(p)]

        remove_featured_image = request.form.get("remove_featured_image") == "1"
        remove_gallery_images_raw = request.form.get("remove_gallery_images", "[]")
        try:
            remove_gallery_images = json.loads(remove_gallery_images_raw) if remove_gallery_images_raw else []
            if not isinstance(remove_gallery_images, list):
                remove_gallery_images = []
        except (ValueError, TypeError):
            remove_gallery_images = []
        remove_gallery_images_norm = [normalize_upload_ref(p) for p in remove_gallery_images if normalize_upload_ref(p)]
        remove_gallery_images_norm_set = set(remove_gallery_images_norm)
        
        # Remove featured image if requested
        if remove_featured_image and featured_image_raw:
            old_path = upload_fs_path(featured_image_raw)
            if old_path and os.path.exists(old_path):
                os.remove(old_path)
            featured_image = None
            featured_image_raw = None

        # Remove gallery images if requested
        if remove_gallery_images_norm_set:
            remaining = []
            for p in image_gallery:
                if p in remove_gallery_images_norm_set:
                    old_path = upload_fs_path(p)
                    if old_path and os.path.exists(old_path):
                        os.remove(old_path)
                else:
                    remaining.append(p)
            image_gallery = remaining
        
        # Handle featured image update
        if 'featured_image' in request.files:
            file = request.files['featured_image']
            if file and file.filename and allowed_file(file.filename):
                # Delete old image if exists
                if featured_image_raw:
                    old_path = upload_fs_path(featured_image_raw)
                    if old_path and os.path.exists(old_path):
                        os.remove(old_path)
                
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                rel_path = f"articles/featured/{unique_filename}"
                upload_path = upload_fs_path(rel_path)
                os.makedirs(os.path.dirname(upload_path), exist_ok=True)
                file.save(upload_path)
                resize_image(upload_path)
                featured_image = rel_path
                featured_image_raw = rel_path

        # Handle gallery images update
        if 'gallery_images' in request.files:
            files = request.files.getlist('gallery_images')
            for file in files:
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    unique_filename = f"{uuid.uuid4().hex}_{filename}"
                    rel_path = f"articles/gallery/{unique_filename}"
                    upload_path = upload_fs_path(rel_path)
                    os.makedirs(os.path.dirname(upload_path), exist_ok=True)
                    file.save(upload_path)
                    resize_image(upload_path)
                    image_gallery.append(rel_path)

        if not title or not content:
            flash("Заповніть назву та текст статті.", "error")
        else:
            execute_db(
                """
                UPDATE articles
                SET title = ?, summary = ?, content = ?, category = ?, section_id = ?,
                    published_date = ?, event_date = ?, external_link = ?, featured_image = ?, 
                    image_gallery = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    title,
                    summary,
                    content,
                    category,
                    section_id,
                    published_date,
                    event_date,
                    external_link,
                    featured_image,
                    json.dumps(image_gallery) if image_gallery else None,
                    datetime.utcnow().isoformat(),
                    article_id,
                ),
            )
            flash("Статтю оновлено.", "success")
            return redirect(url_for("admin_articles"))

    return render_template(
        "admin/article_form.html",
        article=article,
        sections=sections,
        categories=ARTICLE_CATEGORIES,
        active_title="",
    )


@app.route("/admin/articles/<int:article_id>/delete", methods=["POST"])
@role_required("owner", "admin", "editor")
def admin_article_delete(article_id: int):
    article = query_db("SELECT * FROM articles WHERE id = ?", (article_id,), one=True)
    if not article:
        abort(404)
    execute_db("DELETE FROM articles WHERE id = ?", (article_id,))
    flash("Статтю видалено.", "success")
    return redirect(url_for("admin_articles"))


if __name__ == "__main__":
    app.run(debug=True)
