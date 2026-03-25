from __future__ import annotations

from datetime import datetime
import json
import os
import uuid
from sqlite3 import IntegrityError
from typing import List, Optional

from flask import abort, flash, g, redirect, render_template, request, url_for
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from app.core import (
    ADMISSION_QUESTION_STATUSES,
    ARTICLE_CATEGORIES,
    COURSE_APPLICATION_STATUSES,
    allowed_file,
    app,
    can_manage_user,
    creatable_roles,
    execute_db,
    get_database_tables,
    get_menu_flat,
    get_site_setting,
    get_table_columns,
    get_table_preview,
    login_required,
    normalize_button_url,
    normalize_hex_color,
    normalize_optional_text,
    normalize_upload_ref,
    query_db,
    resize_image,
    role_required,
    set_site_setting,
    upload_fs_path,
    uploads_url,
)

@app.route("/admin")
@login_required
def admin_dashboard():
    return render_template("admin/dashboard.html", active_title="")


@app.route("/admin/database")
@app.route("/admin/database/<table_name>")
@role_required("owner", "admin")
def admin_database(table_name: Optional[str] = None):
    tables = get_database_tables()
    selected_table = table_name or (tables[0] if tables else None)

    if selected_table and selected_table not in tables:
        abort(404)

    columns: List[str] = []
    rows: List[dict] = []
    if selected_table:
        columns = get_table_columns(selected_table)
        rows = get_table_preview(selected_table)

    return render_template(
        "admin/database.html",
        tables=tables,
        selected_table=selected_table,
        columns=columns,
        rows=rows,
        preview_limit=50,
        active_title="",
    )


@app.route("/admin/admissions-settings", methods=["GET", "POST"])
@role_required("owner", "admin", "editor")
def admin_admissions_settings():
    def normalized(value: Optional[str], fallback: str) -> str:
        if value is None:
            return fallback
        stripped = value.strip()
        return stripped if stripped else fallback

    if request.method == "POST":
        step1_text = normalized(request.form.get("step1_text"), "Переглянути освітні програми")
        step1_url = normalized(request.form.get("step1_url"), url_for("courses"))
        step2_text = normalized(request.form.get("step2_text"), "Переглянути перелік")
        step2_url = normalized(request.form.get("step2_url"), "#documents")
        step3_text = normalized(request.form.get("step3_text"), "Зв'язатися з комісією")
        step3_url = normalized(request.form.get("step3_url"), "#contacts")
        template_text = normalized(request.form.get("template_text"), "Шаблон")
        template_url = normalized(request.form.get("template_url"), "#")

        set_site_setting("admissions_step1_text", step1_text)
        set_site_setting("admissions_step1_url", step1_url)
        set_site_setting("admissions_step2_text", step2_text)
        set_site_setting("admissions_step2_url", step2_url)
        set_site_setting("admissions_step3_text", step3_text)
        set_site_setting("admissions_step3_url", step3_url)
        set_site_setting("admissions_template_text", template_text)
        set_site_setting("admissions_template_url", template_url)

        remove_template_file = request.form.get("remove_template_file")
        current_template_path = get_site_setting("admissions_template_path", "")

        if remove_template_file and current_template_path:
            try:
                file_path = upload_fs_path(current_template_path)
                if file_path:
                    os.remove(file_path)
            except OSError:
                pass
            set_site_setting("admissions_template_path", "")

        template_file = request.files.get("template_file")
        if template_file and template_file.filename:
            filename = secure_filename(template_file.filename)
            ext = os.path.splitext(filename)[1].lower()
            allowed_ext = {".pdf", ".doc", ".docx"}
            if ext not in allowed_ext:
                flash("Дозволені формати: PDF, DOC, DOCX.", "error")
                return redirect(url_for("admin_admissions_settings"))

            upload_dir = upload_fs_path("admissions")
            if upload_dir:
                os.makedirs(upload_dir, exist_ok=True)
            unique_name = f"{uuid.uuid4().hex}{ext}"
            rel_path = f"admissions/{unique_name}"
            upload_path = upload_fs_path(rel_path)
            if not upload_path:
                flash("Помилка збереження файлу.", "error")
                return redirect(url_for("admin_admissions_settings"))
            template_file.save(upload_path)
            set_site_setting("admissions_template_path", rel_path)

        flash("Налаштування вступу оновлено.", "success")
        return redirect(url_for("admin_admissions_settings"))

    template_path = get_site_setting("admissions_template_path", "")
    template_url = uploads_url(template_path) if template_path else ""

    settings = {
        "step1_text": get_site_setting("admissions_step1_text", "Переглянути освітні програми"),
        "step1_url": get_site_setting("admissions_step1_url", url_for("courses")),
        "step2_text": get_site_setting("admissions_step2_text", "Переглянути перелік"),
        "step2_url": get_site_setting("admissions_step2_url", "#documents"),
        "step3_text": get_site_setting("admissions_step3_text", "Зв'язатися з комісією"),
        "step3_url": get_site_setting("admissions_step3_url", "#contacts"),
        "template_text": get_site_setting("admissions_template_text", "Шаблон"),
        "template_url": get_site_setting("admissions_template_url", "#"),
        "template_path": template_path,
        "template_download_url": template_url,
    }

    return render_template("admin/admissions_settings.html", settings=settings, active_title="")


@app.route("/admin/home-promos")
@role_required("owner", "admin", "editor")
def admin_home_promos():
    promos = query_db(
        """
        SELECT *
        FROM home_promos
        ORDER BY sort_order ASC, id ASC
        """
    )
    return render_template("admin/home_promos.html", promos=promos, active_title="")


@app.route("/admin/home-promos/new", methods=["GET", "POST"])
@role_required("owner", "admin", "editor")
def admin_home_promo_new():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = normalize_optional_text(request.form.get("description"))
        button_text = normalize_optional_text(request.form.get("button_text"))
        button_url = normalize_button_url(request.form.get("button_url", "").strip())
        block_size = request.form.get("block_size", "md").strip()
        button_size = request.form.get("button_size", "md").strip()
        button_position = request.form.get("button_position", "center").strip()
        button_bg_color = normalize_hex_color(request.form.get("button_bg_color"), "#0b5ed7")
        button_text_color = normalize_hex_color(request.form.get("button_text_color"), "#ffffff")
        sort_order_raw = request.form.get("sort_order", "0").strip()
        is_active = 1 if request.form.get("is_active") == "on" else 0

        block_size = block_size if block_size in {"sm", "md", "lg"} else "md"
        button_size = button_size if button_size in {"sm", "md", "lg"} else "md"
        button_position = button_position if button_position in {"left", "center", "right"} else "center"
        sort_order = int(sort_order_raw) if sort_order_raw.isdigit() else 0
        image_path = None

        if "image_file" in request.files:
            file = request.files["image_file"]
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                rel_path = f"home_promos/{unique_filename}"
                upload_path = upload_fs_path(rel_path)
                os.makedirs(os.path.dirname(upload_path), exist_ok=True)
                file.save(upload_path)
                resize_image(upload_path, max_width=1600, max_height=1000)
                image_path = rel_path

        if not title:
            flash("Вкажіть назву блоку.", "error")
        else:
            now = datetime.utcnow().isoformat()
            execute_db(
                """
                INSERT INTO home_promos
                (
                  title, description, image_path, block_size, button_text, button_url, button_size,
                  button_bg_color, button_text_color, button_position, sort_order, is_active,
                  created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    title,
                    description,
                    image_path,
                    block_size,
                    button_text,
                    button_url,
                    button_size,
                    button_bg_color,
                    button_text_color,
                    button_position,
                    sort_order,
                    is_active,
                    now,
                    now,
                ),
            )
            flash("Промо-блок створено.", "success")
            return redirect(url_for("admin_home_promos"))

    return render_template("admin/home_promo_form.html", promo=None, active_title="")


@app.route("/admin/home-promos/<int:promo_id>/edit", methods=["GET", "POST"])
@role_required("owner", "admin", "editor")
def admin_home_promo_edit(promo_id: int):
    promo = query_db("SELECT * FROM home_promos WHERE id = ?", (promo_id,), one=True)
    if not promo:
        abort(404)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = normalize_optional_text(request.form.get("description"))
        button_text = normalize_optional_text(request.form.get("button_text"))
        button_url = normalize_button_url(request.form.get("button_url", "").strip())
        block_size = request.form.get("block_size", "md").strip()
        button_size = request.form.get("button_size", "md").strip()
        button_position = request.form.get("button_position", "center").strip()
        button_bg_color = normalize_hex_color(request.form.get("button_bg_color"), "#0b5ed7")
        button_text_color = normalize_hex_color(request.form.get("button_text_color"), "#ffffff")
        sort_order_raw = request.form.get("sort_order", "0").strip()
        is_active = 1 if request.form.get("is_active") == "on" else 0
        remove_image = request.form.get("remove_image") == "1"

        block_size = block_size if block_size in {"sm", "md", "lg"} else "md"
        button_size = button_size if button_size in {"sm", "md", "lg"} else "md"
        button_position = button_position if button_position in {"left", "center", "right"} else "center"
        sort_order = int(sort_order_raw) if sort_order_raw.isdigit() else 0

        image_path = promo["image_path"]
        if remove_image and image_path:
            old_path = upload_fs_path(image_path)
            if old_path and os.path.exists(old_path):
                os.remove(old_path)
            image_path = None

        if "image_file" in request.files:
            file = request.files["image_file"]
            if file and file.filename and allowed_file(file.filename):
                if image_path:
                    old_path = upload_fs_path(image_path)
                    if old_path and os.path.exists(old_path):
                        os.remove(old_path)
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                rel_path = f"home_promos/{unique_filename}"
                upload_path = upload_fs_path(rel_path)
                os.makedirs(os.path.dirname(upload_path), exist_ok=True)
                file.save(upload_path)
                resize_image(upload_path, max_width=1600, max_height=1000)
                image_path = rel_path

        if not title:
            flash("Вкажіть назву блоку.", "error")
        else:
            execute_db(
                """
                UPDATE home_promos
                SET title = ?, description = ?, image_path = ?, block_size = ?, button_text = ?, button_url = ?,
                    button_size = ?, button_bg_color = ?, button_text_color = ?, button_position = ?,
                    sort_order = ?, is_active = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    title,
                    description,
                    image_path,
                    block_size,
                    button_text,
                    button_url,
                    button_size,
                    button_bg_color,
                    button_text_color,
                    button_position,
                    sort_order,
                    is_active,
                    datetime.utcnow().isoformat(),
                    promo_id,
                ),
            )
            flash("Промо-блок оновлено.", "success")
            return redirect(url_for("admin_home_promos"))

    return render_template("admin/home_promo_form.html", promo=promo, active_title="")


@app.route("/admin/home-promos/<int:promo_id>/delete", methods=["POST"])
@role_required("owner", "admin", "editor")
def admin_home_promo_delete(promo_id: int):
    promo = query_db("SELECT * FROM home_promos WHERE id = ?", (promo_id,), one=True)
    if not promo:
        abort(404)
    if promo["image_path"]:
        old_path = upload_fs_path(promo["image_path"])
        if old_path and os.path.exists(old_path):
            os.remove(old_path)
    execute_db("DELETE FROM home_promos WHERE id = ?", (promo_id,))
    flash("Промо-блок видалено.", "success")
    return redirect(url_for("admin_home_promos"))


@app.route("/admin/course-applications")
@role_required("owner", "admin", "editor")
def admin_course_applications():
    applications = query_db(
        """
        SELECT *
        FROM course_applications
        ORDER BY created_at DESC
        """
    )
    return render_template(
        "admin/course_applications.html",
        applications=applications,
        status_suggestions=COURSE_APPLICATION_STATUSES,
        active_title="",
    )


@app.route("/admin/course-applications/<int:application_id>/status", methods=["POST"])
@role_required("owner", "admin", "editor")
def admin_course_application_status(application_id: int):
    application = query_db(
        "SELECT id FROM course_applications WHERE id = ?",
        (application_id,),
        one=True,
    )
    if not application:
        abort(404)

    status = normalize_optional_text(request.form.get("status")) or "Нова"
    execute_db(
        "UPDATE course_applications SET status = ? WHERE id = ?",
        (status, application_id),
    )
    flash("Статус заявки оновлено.", "success")
    return redirect(url_for("admin_course_applications"))


@app.route("/admin/admission-questions")
@role_required("owner", "admin", "editor")
def admin_admission_questions():
    questions = query_db(
        """
        SELECT *
        FROM admission_questions
        ORDER BY created_at DESC
        """
    )
    return render_template(
        "admin/admission_questions.html",
        questions=questions,
        status_suggestions=ADMISSION_QUESTION_STATUSES,
        active_title="",
    )


@app.route("/admin/admission-questions/<int:question_id>/status", methods=["POST"])
@role_required("owner", "admin", "editor")
def admin_admission_question_status(question_id: int):
    question = query_db(
        "SELECT id FROM admission_questions WHERE id = ?",
        (question_id,),
        one=True,
    )
    if not question:
        abort(404)

    status = normalize_optional_text(request.form.get("status")) or "Нове"
    execute_db(
        "UPDATE admission_questions SET status = ? WHERE id = ?",
        (status, question_id),
    )
    flash("Статус запитання оновлено.", "success")
    return redirect(url_for("admin_admission_questions"))


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
        email = normalize_optional_text(request.form.get("email"))
        if email:
            email = email.lower()
        last_name = normalize_optional_text(request.form.get("last_name"))
        first_name = normalize_optional_text(request.form.get("first_name"))
        middle_name = normalize_optional_text(request.form.get("middle_name"))
        position = normalize_optional_text(request.form.get("position"))
        profile_text = normalize_optional_text(request.form.get("profile_text"))
        if role not in roles:
            flash("???????????????????? ???????? ?????? ??????????????????.", "error")
        elif not username or not password:
            flash("?????????????????? ?????????? ?? ????????????.", "error")
        elif email and query_db("SELECT id FROM users WHERE LOWER(COALESCE(email, '')) = ?", (email,), one=True):
            flash("?????????? ? ????? ?????? ??? ?????.", "error")
        else:
            try:
                execute_db(
                    """
                    INSERT INTO users (username, password_hash, email, role, last_name, first_name, middle_name, position, profile_text, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        username,
                        generate_password_hash(password),
                        email,
                        role,
                        last_name,
                        first_name,
                        middle_name,
                        position,
                        profile_text,
                        datetime.utcnow().isoformat(),
                    ),
                )
                flash("?????????????????????? ????????????????.", "success")
                return redirect(url_for("admin_users"))
            except IntegrityError:
                flash("?????????? ?????????? ?????? ??????????.", "error")
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
        email = normalize_optional_text(request.form.get("email"))
        if email:
            email = email.lower()
        last_name = normalize_optional_text(request.form.get("last_name"))
        first_name = normalize_optional_text(request.form.get("first_name"))
        middle_name = normalize_optional_text(request.form.get("middle_name"))
        position = normalize_optional_text(request.form.get("position"))
        profile_text = normalize_optional_text(request.form.get("profile_text"))
        if not username:
            flash("?????????? ???? ???????? ???????? ????????????????.", "error")
        elif email and query_db("SELECT id FROM users WHERE LOWER(COALESCE(email, '')) = ? AND id <> ?", (email, user_id), one=True):
            flash("?????????? ? ????? ?????? ??? ?????.", "error")
        else:
            if role not in roles and g.user["id"] != user["id"]:
                role = user["role"]
            execute_db(
                """
                UPDATE users
                SET username = ?, email = ?, role = ?, last_name = ?, first_name = ?, middle_name = ?, position = ?, profile_text = ?
                WHERE id = ?
                """,
                (username, email, role, last_name, first_name, middle_name, position, profile_text, user_id),
            )
            if password:
                execute_db(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (generate_password_hash(password), user_id),
                )
            flash("???????? ?????????????????????? ????????????????.", "success")
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
        summary = normalize_optional_text(request.form.get("summary")) or ""
        content = request.form.get("content", "").strip()
        category = request.form.get("category", ARTICLE_CATEGORIES[0])
        section_id = request.form.get("section_id") or None
        section_id = int(section_id) if section_id else None
        published_date = request.form.get("published_date") or datetime.utcnow().date().isoformat()
        event_date = normalize_optional_text(request.form.get("event_date"))
        external_link = normalize_optional_text(request.form.get("external_link"))

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
                (title, summary, content, category, section_id, published_date, event_date, external_link, featured_image, image_gallery, author_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    g.user["id"] if g.user else None,
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
        summary = normalize_optional_text(request.form.get("summary")) or ""
        content = request.form.get("content", "").strip()
        category = request.form.get("category", ARTICLE_CATEGORIES[0])
        section_id = request.form.get("section_id") or None
        section_id = int(section_id) if section_id else None
        published_date = request.form.get("published_date") or datetime.utcnow().date().isoformat()
        event_date = normalize_optional_text(request.form.get("event_date"))
        external_link = normalize_optional_text(request.form.get("external_link"))

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
