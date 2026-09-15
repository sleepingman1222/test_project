import os
import sqlite3
from datetime import timedelta
from functools import wraps

from flask import (
    Flask,
    flash,
    redirect,
    render_template_string,
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


PAGE_TEMPLATE = """
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }} - 메모 서비스</title>
</head>
<body>
  <header>
    <h1><a href="{{ url_for('index') }}">메모 서비스</a></h1>
    <nav>
      {% if session.get('user_id') %}
        <span>{{ session.get('username') }}님</span>
        <a href="{{ url_for('logout') }}">로그아웃</a>
      {% else %}
        <a href="{{ url_for('login') }}">로그인</a>
        <a href="{{ url_for('register') }}">회원가입</a>
      {% endif %}
    </nav>
  </header>

  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <ul>
        {% for message in messages %}
          <li>{{ message }}</li>
        {% endfor %}
      </ul>
    {% endif %}
  {% endwith %}

  <main>
    {{ content | safe }}
  </main>
</body>
</html>
"""


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


def render_page(title, content_template, **context):
    content = render_template_string(content_template, **context)
    return render_template_string(PAGE_TEMPLATE, title=title, content=content)


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


@app.route("/")
def index():
    if "user_id" in session:
        content = """
        <h2>환영합니다, {{ username }}님!</h2>
        <p>로그인 상태가 유지되고 있습니다.</p>
        <p>메모 기능은 다음 단계에서 추가할 수 있습니다.</p>
        """
        return render_page("홈", content, username=session["username"])

    content = """
    <h2>간단한 메모 서비스</h2>
    <p>서비스를 이용하려면 로그인하거나 회원가입해 주세요.</p>
    """
    return render_page("홈", content)


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

    content = """
    <h2>회원가입</h2>
    <form method="post">
      <p>
        <label for="username">아이디</label><br>
        <input id="username" name="username" type="text" minlength="3"
               maxlength="30" value="{{ request.form.get('username', '') }}" required>
      </p>
      <p>
        <label for="password">비밀번호</label><br>
        <input id="password" name="password" type="password" minlength="8" required>
      </p>
      <p>
        <label for="password_confirm">비밀번호 확인</label><br>
        <input id="password_confirm" name="password_confirm" type="password" minlength="8" required>
      </p>
      <button type="submit">가입하기</button>
    </form>
    """
    return render_page("회원가입", content)


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

    content = """
    <h2>로그인</h2>
    <form method="post">
      <p>
        <label for="username">아이디</label><br>
        <input id="username" name="username" type="text"
               value="{{ request.form.get('username', '') }}" required autofocus>
      </p>
      <p>
        <label for="password">비밀번호</label><br>
        <input id="password" name="password" type="password" required>
      </p>
      <button type="submit">로그인</button>
    </form>
    """
    return render_page("로그인", content)


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("로그아웃되었습니다.")
    return redirect(url_for("index"))


init_db()


if __name__ == "__main__":
    app.run(debug=True)
