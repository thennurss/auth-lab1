import os
import re
import secrets
import sqlite3
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")

# Две учётки, которые создаются при первом запуске
DEFAULT_ACCOUNTS = [
    ("user", "User123!", "user"),
    ("admin", "Admin123!", "admin"),
]


# ---------- База данных ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute(
        """CREATE TABLE IF NOT EXISTS users (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               username TEXT UNIQUE NOT NULL,
               password_hash TEXT NOT NULL,
               role TEXT NOT NULL CHECK (role IN ('user', 'admin')),
               created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
           )"""
    )
    for username, password, role in DEFAULT_ACCOUNTS:
        exists = db.execute(
            "SELECT 1 FROM users WHERE username = ?", (username,)
        ).fetchone()
        if not exists:
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), role),
            )
    db.commit()
    db.close()


# ---------- CSRF ----------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("_csrf", "")):
            abort(400, "Недействительный CSRF-токен")


# ---------- Авторизация ----------
@app.before_request
def load_user():
    g.user = None
    uid = session.get("user_id")
    if uid is not None:
        g.user = get_db().execute(
            "SELECT id, username, role FROM users WHERE id = ?", (uid,)
        ).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Сначала войдите в систему.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapped


# ---------- Маршруты ----------
@app.route("/")
def index():
    if g.user:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        error = None
        if not USERNAME_RE.match(username):
            error = "Логин: 3–20 символов, только латиница, цифры и _."
        elif len(password) < 6:
            error = "Пароль должен быть не короче 6 символов."
        elif password != confirm:
            error = "Пароли не совпадают."
        else:
            db = get_db()
            if db.execute(
                "SELECT 1 FROM users WHERE username = ?", (username,)
            ).fetchone():
                error = "Такой логин уже занят."
            else:
                # Все, кто регистрируется сами, получают роль user
                db.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
                    (username, generate_password_hash(password)),
                )
                db.commit()
                flash("Регистрация прошла успешно. Теперь войдите.", "success")
                return redirect(url_for("login"))
        flash(error, "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        row = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["user_id"] = row["id"]
            flash(f"Добро пожаловать, {row['username']}!", "success")
            return redirect(url_for("dashboard"))
        flash("Неверный логин или пароль.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Вы вышли из системы.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/admin")
@admin_required
def admin():
    users = get_db().execute(
        "SELECT id, username, role, created_at FROM users ORDER BY id"
    ).fetchall()
    return render_template("admin.html", users=users)


@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403,
                           text="Доступ запрещён: нужны права администратора."), 403


@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, text=str(e.description)), 400


init_db()

if __name__ == "__main__":
    app.run(debug=True, port=5001)
