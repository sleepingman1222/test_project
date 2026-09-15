import os
import sqlite3
from datetime import timedelta
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "memo.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db() as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
            """
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes (user_id)"
        )


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def get_owned_note(note_id):
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
        abort(404)
    return note


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
        elif len(username) < 3 or len(username) > 30:
            flash("아이디는 3자 이상 30자 이하로 입력해 주세요.")
        elif len(password) < 8:
            flash("비밀번호는 8자 이상이어야 합니다.")
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

        with get_db() as db:
            user = db.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("아이디 또는 비밀번호가 올바르지 않습니다.")
        else:
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session.permanent = True
            flash("로그인되었습니다.")
            return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("로그아웃되었습니다.")
    return redirect(url_for("index"))


@app.route("/notes")
@login_required
def note_list():
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
        else:
            with get_db() as db:
                cursor = db.execute(
                    "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
                    (session["user_id"], title, content),
                )
                note_id = cursor.lastrowid
            flash("메모를 저장했습니다.")
            return redirect(url_for("note_detail", note_id=note_id))

    return render_template("note_form.html", note=None, page_title="새 메모")


@app.route("/notes/<int:note_id>")
@login_required
def note_detail(note_id):
    return render_template("note_detail.html", note=get_owned_note(note_id))


@app.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
@login_required
def note_edit(note_id):
    note = get_owned_note(note_id)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()

        if not title or not content:
            flash("제목과 내용을 모두 입력해 주세요.")
        elif len(title) > 100:
            flash("제목은 100자 이하로 입력해 주세요.")
        else:
            with get_db() as db:
                db.execute(
                    """
                    UPDATE notes
                    SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ? AND user_id = ?
                    """,
                    (title, content, note_id, session["user_id"]),
                )
            flash("메모를 수정했습니다.")
            return redirect(url_for("note_detail", note_id=note_id))

    return render_template("note_form.html", note=note, page_title="메모 수정")


@app.route("/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def note_delete(note_id):
    get_owned_note(note_id)
    with get_db() as db:
        db.execute(
            "DELETE FROM notes WHERE id = ? AND user_id = ?",
            (note_id, session["user_id"]),
        )
    flash("메모를 삭제했습니다.")
    return redirect(url_for("note_list"))


init_db()


if __name__ == "__main__":
    app.run(debug=True)
