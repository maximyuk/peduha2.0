from __future__ import annotations

from datetime import datetime
import os
import uuid

from flask import abort, flash, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

from app.core import (
    AUTHOR_FULL_NAME_SQL,
    ARTICLE_CATEGORIES,
    BASE_DIR,
    UPLOAD_FOLDER,
    app,
    allowed_file,
    allowed_pdf,
    execute_db,
    get_descendant_ids,
    find_menu_item,
    get_menu_tree,
    get_site_setting,
    humanize_membership,
    normalize_optional_text,
    query_db,
    role_required,
    upload_fs_path,
    uploads_url,
    user_display_name,
)

@app.route("/")
def index():
    promos = query_db(
        """
        SELECT *
        FROM home_promos
        WHERE is_active = 1
        ORDER BY sort_order ASC, id ASC
        """
    )
    articles = query_db(
        f"""
        SELECT articles.*, menu_items.title AS section_title,
               users.username AS author_username,
               {AUTHOR_FULL_NAME_SQL} AS author_full_name
        FROM articles
        LEFT JOIN menu_items ON menu_items.id = articles.section_id
        LEFT JOIN users ON users.id = articles.author_id
        WHERE articles.section_id IS NULL
        ORDER BY articles.created_at DESC, articles.id DESC
        LIMIT 3
        """
    )
    return render_template("index.html", active_title="Головна", articles=articles, promos=promos)


@app.route("/admissions-2026")
def admissions():
    template_path = get_site_setting("admissions_template_path", "")
    template_url = uploads_url(template_path) if template_path else ""
    if not template_url:
        template_url = get_site_setting("admissions_template_url", "#")

    admissions_settings = {
        "step1_text": get_site_setting("admissions_step1_text", "Переглянути освітні програми"),
        "step1_url": get_site_setting("admissions_step1_url", url_for("courses")),
        "step2_text": get_site_setting("admissions_step2_text", "Переглянути перелік"),
        "step2_url": get_site_setting("admissions_step2_url", "#documents"),
        "step3_text": get_site_setting("admissions_step3_text", "Зв'язатися з комісією"),
        "step3_url": get_site_setting("admissions_step3_url", "#contacts"),
        "template_text": get_site_setting("admissions_template_text", "Шаблон"),
        "template_url": template_url,
    }

    return render_template(
        "admissions-2026.html",
        active_title="Абітурієнту",
        admissions=admissions_settings,
    )


@app.route("/courses")
def courses():
    return render_template("courses.html", active_title="")


@app.route("/courses/apply", methods=["GET", "POST"])
def courses_apply():
    form_data = {
        "full_name": "",
        "previous_school": "",
        "study_years": "",
        "phone": "",
        "telegram_username": "",
    }

    if request.method == "POST":
        form_data["full_name"] = request.form.get("full_name", "").strip()
        form_data["previous_school"] = request.form.get("previous_school", "").strip()
        form_data["study_years"] = request.form.get("study_years", "").strip()
        form_data["phone"] = request.form.get("phone", "").strip()
        form_data["telegram_username"] = request.form.get("telegram_username", "").strip()

        if not all(form_data.values()):
            flash("Заповніть усі поля форми.", "error")
        else:
            execute_db(
                """
                INSERT INTO course_applications
                (full_name, previous_school, study_years, phone, telegram_username, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    form_data["full_name"],
                    form_data["previous_school"],
                    form_data["study_years"],
                    form_data["phone"],
                    form_data["telegram_username"],
                    "Нова",
                    datetime.utcnow().isoformat(),
                ),
            )
            flash("Заявку на курси надіслано. Ми зв'яжемося з вами.", "success")
            return redirect(url_for("courses_apply"))

    return render_template("courses_apply.html", active_title="", form_data=form_data)


@app.route("/admissions/question", methods=["GET", "POST"])
def admissions_question():
    form_data = {
        "full_name": "",
        "phone": "",
        "email": "",
        "question": "",
    }

    if request.method == "POST":
        form_data["full_name"] = request.form.get("full_name", "").strip()
        form_data["phone"] = request.form.get("phone", "").strip()
        form_data["email"] = request.form.get("email", "").strip()
        form_data["question"] = request.form.get("question", "").strip()

        if not form_data["full_name"] or not form_data["question"]:
            flash("Заповніть ім'я та текст запитання.", "error")
        elif not form_data["phone"] and not form_data["email"]:
            flash("Залиште телефон або email для відповіді.", "error")
        else:
            execute_db(
                """
                INSERT INTO admission_questions (full_name, phone, email, question, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    form_data["full_name"],
                    normalize_optional_text(form_data["phone"]),
                    normalize_optional_text(form_data["email"]),
                    form_data["question"],
                    "Нове",
                    datetime.utcnow().isoformat(),
                ),
            )
            flash("Запитання надіслано. Ми зв'яжемося з вами найближчим часом.", "success")
            return redirect(url_for("admissions_question"))

    return render_template("admissions_question.html", active_title="Вступ", form_data=form_data)


@app.route("/users/<username>")
def user_profile(username: str):
    user = query_db("SELECT * FROM users WHERE username = ?", (username,), one=True)
    if not user:
        abort(404)
    display_name = user_display_name(user)
    member_for = humanize_membership(user["created_at"])
    return render_template(
        "user_profile.html",
        profile_user=user,
        display_name=display_name,
        member_for=member_for,
        active_title="",
    )


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

    # If a section has exactly one direct article with external link and no sub-sections,
    # open the link immediately instead of showing section listing.
    direct_count_row = query_db(
        "SELECT COUNT(*) AS total FROM articles WHERE section_id = ?",
        (section_id,),
        one=True,
    )
    direct_count = int(direct_count_row["total"]) if direct_count_row else 0
    if direct_count == 1 and not section_item["children"]:
        direct_article = query_db(
            """
            SELECT external_link
            FROM articles
            WHERE section_id = ? AND external_link IS NOT NULL AND TRIM(external_link) <> ''
            LIMIT 1
            """,
            (section_id,),
            one=True,
        )
        if direct_article and direct_article["external_link"]:
            return redirect(direct_article["external_link"])

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

    query = f"""
        SELECT articles.*, menu_items.title AS section_title,
               users.username AS author_username,
               {AUTHOR_FULL_NAME_SQL} AS author_full_name
        FROM articles
        LEFT JOIN menu_items ON menu_items.id = articles.section_id
        LEFT JOIN users ON users.id = articles.author_id
        WHERE articles.section_id IS NULL
    """
    params: List = []
    if category:
        query += " AND articles.category = ?"
        params.append(category)

    page_raw = request.args.get("page", "1").strip()
    page = int(page_raw) if page_raw.isdigit() and int(page_raw) > 0 else 1
    per_page = 6
    offset = (page - 1) * per_page

    count_row = query_db(
        f"SELECT COUNT(*) AS total FROM ({query}) counted",
        tuple(params),
        one=True,
    )
    total = int(count_row["total"]) if count_row else 0
    total_pages = max(1, (total + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages
        offset = (page - 1) * per_page

    query += " ORDER BY articles.created_at DESC, articles.id DESC LIMIT ? OFFSET ?"
    articles_list = query_db(query, tuple(params + [per_page, offset]))

    page_numbers = list(range(1, total_pages + 1))

    return render_template(
        "articles.html",
        articles=articles_list,
        categories=ARTICLE_CATEGORIES,
        selected_category=category,
        current_page=page,
        total_pages=total_pages,
        page_numbers=page_numbers,
        active_title="",
    )


@app.route("/search")
def search():
    raw_query = request.args.get("q", "")
    search_query = raw_query.strip()

    page_raw = request.args.get("page", "1").strip()
    page = int(page_raw) if page_raw.isdigit() and int(page_raw) > 0 else 1
    per_page = 6
    offset = (page - 1) * per_page

    base_query = f"""
        SELECT articles.*, menu_items.title AS section_title,
               users.username AS author_username,
               {AUTHOR_FULL_NAME_SQL} AS author_full_name
        FROM articles
        LEFT JOIN menu_items ON menu_items.id = articles.section_id
        LEFT JOIN users ON users.id = articles.author_id
        WHERE articles.section_id IS NULL
    """

    params: List = []
    if search_query:
        like_value = f"%{search_query}%"
        base_query += """
            AND (
                articles.title LIKE ?
                OR articles.summary LIKE ?
                OR articles.content LIKE ?
                OR articles.category LIKE ?
            )
        """
        params.extend([like_value, like_value, like_value, like_value])

    count_row = query_db(
        f"SELECT COUNT(*) AS total FROM ({base_query}) counted",
        tuple(params),
        one=True,
    )
    total = int(count_row["total"]) if count_row else 0
    total_pages = max(1, (total + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages
        offset = (page - 1) * per_page

    query = base_query + " ORDER BY articles.created_at DESC, articles.id DESC LIMIT ? OFFSET ?"
    results = query_db(query, tuple(params + [per_page, offset]))
    page_numbers = list(range(1, total_pages + 1))

    return render_template(
        "search.html",
        query=search_query,
        articles=results,
        current_page=page,
        total_pages=total_pages,
        page_numbers=page_numbers,
        active_title="",
    )


@app.route("/articles/<int:article_id>")
def article_detail(article_id: int):
    article = query_db(
        f"""
        SELECT articles.*, menu_items.title AS section_title,
               users.username AS author_username,
               {AUTHOR_FULL_NAME_SQL} AS author_full_name
        FROM articles
        LEFT JOIN menu_items ON menu_items.id = articles.section_id
        LEFT JOIN users ON users.id = articles.author_id
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
