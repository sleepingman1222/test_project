import os
import re
import secrets
import sqlite3
import time
from datetime import timedelta
from functools import wraps
from threading import Lock

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "memo.db")
IS_PRODUCTION = os.environ.get("APP_ENV", "development").lower() == "production"
SECRET_KEY = os.environ.get("SECRET_KEY")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

if IS_PRODUCTION and not SECRET_KEY:
    raise RuntimeError("운영 환경에서는 SECRET_KEY 환경변수가 필요합니다.")
if IS_PRODUCTION and (not ADMIN_PASSWORD or len(ADMIN_PASSWORD) < 16):
    raise RuntimeError("운영 환경의 ADMIN_PASSWORD는 16자 이상이어야 합니다.")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY or secrets.token_hex(32),
    ADMIN_PASSWORD=ADMIN_PASSWORD or "Admin!Memo2026#Safe",
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    MAX_CONTENT_LENGTH=64 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    SESSION_REFRESH_EACH_REQUEST=False,
)

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,30}$")
DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(32))
LOGIN_ATTEMPTS = {}
LOGIN_ATTEMPTS_LOCK = Lock()
LOGIN_ATTEMPT_LIMIT = 5
LOGIN_ATTEMPT_WINDOW = 60


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def init_db():
    with get_db() as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        user_columns = {
            column["name"] for column in db.execute("PRAGMA table_info(users)")
        }
        if "is_admin" not in user_columns:
            db.execute(
                "ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0"
            )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id TEXT NOT NULL UNIQUE,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
            """
        )
        note_columns = {
            column["name"] for column in db.execute("PRAGMA table_info(notes)")
        }
        if "public_id" not in note_columns:
            db.execute("ALTER TABLE notes ADD COLUMN public_id TEXT")
        notes_without_public_id = db.execute(
            "SELECT id FROM notes WHERE public_id IS NULL OR public_id = ''"
        ).fetchall()
        for note in notes_without_public_id:
            db.execute(
                "UPDATE notes SET public_id = ? WHERE id = ?",
                (secrets.token_urlsafe(18), note["id"]),
            )
        db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_notes_public_id ON notes (public_id)"
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes (user_id)"
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS app_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )

        admin = db.execute(
            "SELECT id FROM users WHERE username = ?", ("admin",)
        ).fetchone()
        if admin is None:
            cursor = db.execute(
                """
                INSERT INTO users (username, password_hash, is_admin)
                VALUES (?, ?, 1)
                """,
                ("admin", generate_password_hash(app.config["ADMIN_PASSWORD"])),
            )
            admin_id = cursor.lastrowid
        else:
            admin_id = admin["id"]
            db.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (admin_id,))

        password_upgraded = db.execute(
            "SELECT value FROM app_metadata WHERE key = ?",
            ("admin_password_security_v1",),
        ).fetchone()
        if ADMIN_PASSWORD is not None or password_upgraded is None:
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(app.config["ADMIN_PASSWORD"]), admin_id),
            )
        if password_upgraded is None:
            db.execute(
                "INSERT INTO app_metadata (key, value) VALUES (?, ?)",
                ("admin_password_security_v1", "1"),
            )

        admin_note_seeded = db.execute(
            "SELECT value FROM app_metadata WHERE key = ?", ("admin_note_seeded",)
        ).fetchone()
        if admin_note_seeded is None:
            flag = f"SBOB{{{secrets.token_hex(12)}_Flag}}"
            db.execute(
                """
                INSERT INTO notes (public_id, user_id, title, content)
                VALUES (?, ?, ?, ?)
                """,
                (secrets.token_urlsafe(18), admin_id, "관리자 비밀 메모", flag),
            )
            db.execute(
                "INSERT INTO app_metadata (key, value) VALUES (?, ?)",
                ("admin_note_seeded", "1"),
            )


def csrf_token():
    token = session.get("_csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_from_csrf():
    # Login is the session bootstrap endpoint documented for non-browser clients.
    # JSON API requests are not form submissions and are authenticated separately.
    if request.endpoint == "login" or request.path.startswith("/api/"):
        return None

    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        expected = session.get("_csrf_token")
        supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not expected or not supplied or not secrets.compare_digest(expected, supplied):
            app.logger.warning(
                "CSRF validation failed: path=%r remote_addr=%r",
                request.path,
                request.remote_addr,
            )
            abort(400)


@app.before_request
def require_api_session():
    if not request.path.startswith("/api/"):
        return None

    user_id = session.get("user_id")
    if user_id is not None:
        with get_db() as db:
            user_exists = db.execute(
                "SELECT 1 FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        if user_exists is not None:
            return None

        session.clear()

    return jsonify(error="authentication required"), 401


@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; img-src 'self' data:; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; "
        "form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def login_attempt_key(username):
    return f"{request.remote_addr or 'unknown'}:{username.casefold()}"


def login_is_limited(key):
    with LOGIN_ATTEMPTS_LOCK:
        now = time.monotonic()
        recent = [
            attempted_at
            for attempted_at in LOGIN_ATTEMPTS.get(key, [])
            if now - attempted_at < LOGIN_ATTEMPT_WINDOW
        ]
        if recent:
            LOGIN_ATTEMPTS[key] = recent
        else:
            LOGIN_ATTEMPTS.pop(key, None)
        return len(recent) >= LOGIN_ATTEMPT_LIMIT


def record_login_failure(key):
    with LOGIN_ATTEMPTS_LOCK:
        if len(LOGIN_ATTEMPTS) >= 10_000 and key not in LOGIN_ATTEMPTS:
            LOGIN_ATTEMPTS.pop(next(iter(LOGIN_ATTEMPTS)))
        LOGIN_ATTEMPTS.setdefault(key, []).append(time.monotonic())


def clear_login_failures(key):
    with LOGIN_ATTEMPTS_LOCK:
        LOGIN_ATTEMPTS.pop(key, None)


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))

        with get_db() as db:
            admin = db.execute(
                "SELECT is_admin FROM users WHERE id = ?",
                (session["user_id"],),
            ).fetchone()
        if admin is None or not admin["is_admin"]:
            app.logger.warning(
                "Admin access denied: user_id=%r remote_addr=%r",
                session.get("user_id"),
                request.remote_addr,
            )
            abort(403)
        return view(*args, **kwargs)

    return wrapped_view


def get_owned_note(public_id):
    with get_db() as db:
        note = db.execute(
            """
            SELECT id, public_id, title, content, created_at, updated_at
            FROM notes
            WHERE public_id = ? AND user_id = ?
            """,
            (public_id, session["user_id"]),
        ).fetchone()

    if note is None:
        app.logger.warning(
            "Note access denied or not found: user_id=%r remote_addr=%r",
            session.get("user_id"),
            request.remote_addr,
        )
        abort(404)
    return note


def note_to_api_dict(note):
    return {
        "id": note["id"],
        "title": note["title"],
        "body": note["content"],
        "created_at": note["created_at"],
        "updated_at": note["updated_at"],
    }


def api_error(message, status_code):
    return jsonify(error=message), status_code


@app.route("/")
def index():
    if "user_id" in session:
        return render_template("index.html", username=session["username"])
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")

        if not username or not password:
            flash("아이디와 비밀번호를 모두 입력해 주세요.")
        elif not USERNAME_PATTERN.fullmatch(username):
            flash("아이디는 영문, 숫자, 밑줄로 된 3~30자여야 합니다.")
        elif len(password) < 12 or len(password) > 128:
            flash("비밀번호는 12자 이상 128자 이하로 입력해 주세요.")
        elif password != password_confirm:
            flash("비밀번호가 일치하지 않습니다.")
        else:
            try:
                with get_db() as db:
                    db.execute(
                        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                        (username, generate_password_hash(password)),
                    )
                flash("회원가입이 완료되었습니다. 로그인해 주세요.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("이미 사용 중인 아이디입니다.")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        attempt_key = login_attempt_key(username)

        if login_is_limited(attempt_key):
            app.logger.warning(
                "Login rate limit reached: username=%r remote_addr=%r",
                username,
                request.remote_addr,
            )
            abort(429)

        user = None
        if len(username) <= 30 and len(password) <= 128:
            with get_db() as db:
                user = db.execute(
                    """
                    SELECT id, username, password_hash, is_admin
                    FROM users
                    WHERE username = ?
                    """,
                    (username,),
                ).fetchone()

        password_hash = user["password_hash"] if user is not None else DUMMY_PASSWORD_HASH
        password_is_valid = check_password_hash(password_hash, password)

        if user is None or not password_is_valid:
            record_login_failure(attempt_key)
            app.logger.warning(
                "Login failed: username=%r remote_addr=%r",
                username,
                request.remote_addr,
            )
            flash("아이디 또는 비밀번호가 올바르지 않습니다.")
        else:
            clear_login_failures(attempt_key)
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
            session.permanent = not bool(user["is_admin"])
            app.logger.info(
                "Login succeeded: user_id=%r is_admin=%r remote_addr=%r",
                user["id"],
                bool(user["is_admin"]),
                request.remote_addr,
            )
            flash("로그인되었습니다.")
            return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    user_id = session.get("user_id")
    session.clear()
    app.logger.info("Logout succeeded: user_id=%r", user_id)
    flash("로그아웃되었습니다.")
    return redirect(url_for("index"))


@app.route("/notes")
@login_required
def note_list():
    with get_db() as db:
        notes = db.execute(
            """
            SELECT public_id, title, content, created_at, updated_at
            FROM notes
            WHERE user_id = ?
            ORDER BY updated_at DESC, id DESC
            """,
            (session["user_id"],),
        ).fetchall()
    return render_template("notes.html", notes=notes)


@app.route("/notes/new", methods=["GET", "POST"])
@login_required
def note_create():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()

        if not title or not content:
            flash("제목과 내용을 모두 입력해 주세요.")
        elif len(title) > 100:
            flash("제목은 100자 이하로 입력해 주세요.")
        elif len(content) > 20_000:
            flash("내용은 20,000자 이하로 입력해 주세요.")
        else:
            with get_db() as db:
                public_id = secrets.token_urlsafe(18)
                db.execute(
                    """
                    INSERT INTO notes (public_id, user_id, title, content)
                    VALUES (?, ?, ?, ?)
                    """,
                    (public_id, session["user_id"], title, content),
                )
            flash("메모를 저장했습니다.")
            return redirect(url_for("note_detail", public_id=public_id))

    return render_template("note_form.html", note=None, page_title="새 메모")


@app.route("/notes/<string:public_id>")
@login_required
def note_detail(public_id):
    return render_template("note_detail.html", note=get_owned_note(public_id))


@app.route("/notes/<string:public_id>/edit", methods=["GET", "POST"])
@login_required
def note_edit(public_id):
    note = get_owned_note(public_id)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()

        if not title or not content:
            flash("제목과 내용을 모두 입력해 주세요.")
        elif len(title) > 100:
            flash("제목은 100자 이하로 입력해 주세요.")
        elif len(content) > 20_000:
            flash("내용은 20,000자 이하로 입력해 주세요.")
        else:
            with get_db() as db:
                db.execute(
                    """
                    UPDATE notes
                    SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE public_id = ? AND user_id = ?
                    """,
                    (title, content, public_id, session["user_id"]),
                )
            flash("메모를 수정했습니다.")
            return redirect(url_for("note_detail", public_id=public_id))

    return render_template("note_form.html", note=note, page_title="메모 수정")


@app.route("/notes/<string:public_id>/delete", methods=["POST"])
@login_required
def note_delete(public_id):
    get_owned_note(public_id)
    with get_db() as db:
        db.execute(
            "DELETE FROM notes WHERE public_id = ? AND user_id = ?",
            (public_id, session["user_id"]),
        )
    flash("메모를 삭제했습니다.")
    return redirect(url_for("note_list"))


@app.route("/api/notes", methods=["GET"])
def api_note_list():
    with get_db() as db:
        notes = db.execute(
            """
            SELECT id, title, content, created_at, updated_at
            FROM notes
            WHERE user_id = ?
            ORDER BY updated_at DESC, id DESC
            """,
            (session["user_id"],),
        ).fetchall()

    return jsonify(notes=[note_to_api_dict(note) for note in notes])


@app.route("/api/notes", methods=["POST"])
def api_note_create():
    if not request.is_json:
        return api_error("request body must be JSON", 400)

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return api_error("request body must be a JSON object", 400)

    title = payload.get("title")
    if not isinstance(title, str) or not title.strip():
        return api_error("title is required", 400)

    body = payload.get("body", "")
    if not isinstance(body, str):
        return api_error("body must be a string", 400)

    with get_db() as db:
        cursor = db.execute(
            """
            INSERT INTO notes (public_id, user_id, title, content)
            VALUES (?, ?, ?, ?)
            """,
            (secrets.token_urlsafe(18), session["user_id"], title.strip(), body),
        )
        note = db.execute(
            """
            SELECT id, title, content, created_at, updated_at
            FROM notes
            WHERE id = ? AND user_id = ?
            """,
            (cursor.lastrowid, session["user_id"]),
        ).fetchone()

    return jsonify(note_to_api_dict(note)), 201


@app.route("/api/notes/<int:note_id>", methods=["GET"])
def api_note_detail(note_id):
    with get_db() as db:
        note = db.execute(
            """
            SELECT id, title, content, created_at, updated_at
            FROM notes
            WHERE id = ? AND user_id = ?
            """,
            (note_id, session["user_id"]),
        ).fetchone()

    if note is None:
        return api_error("note not found", 404)
    return jsonify(note_to_api_dict(note))


@app.route("/admin")
@admin_required
def admin_users():
    with get_db() as db:
        users = db.execute(
            """
            SELECT users.id, users.username, users.is_admin, users.created_at,
                   COUNT(notes.id) AS note_count
            FROM users
            LEFT JOIN notes ON notes.user_id = users.id
            GROUP BY users.id
            ORDER BY users.created_at ASC, users.id ASC
            """
        ).fetchall()
    app.logger.info(
        "Admin member list viewed: user_id=%r remote_addr=%r",
        session["user_id"],
        request.remote_addr,
    )
    return render_template("admin.html", users=users)


@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(413)
@app.errorhandler(429)
def handle_http_error(error):
    if request.path.startswith("/api/"):
        return api_error(error.name.lower(), error.code)

    messages = {
        400: ("잘못된 요청", "요청을 확인한 뒤 다시 시도해 주세요."),
        401: ("로그인 필요", "로그인한 뒤 다시 시도해 주세요."),
        403: ("접근 권한 없음", "이 페이지에 접근할 권한이 없습니다."),
        404: ("페이지를 찾을 수 없음", "요청한 페이지가 없거나 접근할 수 없습니다."),
        405: ("허용되지 않은 요청", "이 주소에서는 사용할 수 없는 요청 방식입니다."),
        413: ("요청이 너무 큼", "입력 가능한 데이터 크기를 초과했습니다."),
        429: ("요청이 너무 많음", "잠시 후 다시 시도해 주세요."),
    }
    title, message = messages[error.code]
    return render_template(
        "error.html", page_title=title, message=message, status_code=error.code
    ), error.code


init_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
