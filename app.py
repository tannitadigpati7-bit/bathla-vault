"""
Bathla Vault - one internal place for company Google Sheets and the
dashboards people build.

- Sheets: attach a Google Sheet by its link (metadata only; the sheet itself
  stays in Google Drive with its own sharing rules).
- Dashboards: upload a self-contained .html dashboard. It is stored here and
  rendered in a sandboxed frame so its scripts cannot touch the vault pages.

Access: one shared password (VAULT_PASSWORD). Set it before starting - the app
refuses to run without it.
"""

import hmac
import os
import re
import secrets
import sqlite3
from datetime import datetime

from flask import (Flask, abort, flash, redirect, render_template_string,
                   request, send_from_directory, session, url_for)
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "vault.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
PASSWORD = os.getenv("VAULT_PASSWORD")

app = Flask(__name__)
app.secret_key = os.getenv("VAULT_SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB per upload

SHEET_ID_RE = re.compile(r"/spreadsheets/d/([a-zA-Z0-9_-]+)")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS sheets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                url TEXT NOT NULL,
                department TEXT,
                owner TEXT,
                description TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dashboards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                owner TEXT,
                department TEXT,
                description TEXT,
                filename TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        """)
    os.makedirs(UPLOAD_DIR, exist_ok=True)


def logged_in():
    return session.get("ok") is True


def require_login(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not logged_in():
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


PAGE = """
<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bathla Vault</title>
<style>
  :root { --bg:#f6f5f2; --card:#ffffff; --ink:#2b2b28; --muted:#7a776f; --line:#e4e1da; --accent:#5b6b5e; }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) { --bg:#1f1f1d; --card:#2a2a27; --ink:#e9e7e1; --muted:#9b978d; --line:#3a3a36; --accent:#8fa294; }
  }
  body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif; }
  main { max-width:1000px; margin:0 auto; padding:24px 16px 48px; }
  header { display:flex; justify-content:space-between; align-items:center; margin-bottom:24px; }
  h1 { font-size:22px; margin:0; font-weight:600; }
  h2 { font-size:17px; margin:32px 0 12px; font-weight:600; }
  a { color:var(--accent); }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:16px; margin-bottom:12px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(240px,1fr)); gap:12px; }
  .meta { color:var(--muted); font-size:13px; }
  form.add { display:grid; gap:8px; grid-template-columns:1fr 1fr; }
  form.add .full { grid-column:1 / -1; }
  input, textarea, button { font:inherit; padding:8px 10px; border-radius:8px; border:1px solid var(--line); background:var(--bg); color:var(--ink); box-sizing:border-box; width:100%; }
  button { background:var(--accent); color:#fff; border:none; cursor:pointer; width:auto; padding:8px 16px; }
  .danger { background:none; color:var(--muted); padding:0; font-size:13px; text-decoration:underline; }
  .flash { padding:10px 12px; border-radius:8px; background:var(--card); border:1px solid var(--line); margin-bottom:16px; }
  .narrow { max-width:360px; margin:12vh auto 0; }
  @media (max-width:600px) { form.add { grid-template-columns:1fr; } }
</style></head>
<body><main>
{% with msgs = get_flashed_messages() %}{% for m in msgs %}<div class="flash">{{ m }}</div>{% endfor %}{% endwith %}
{{ body|safe }}
</main></body></html>
"""


def page(body, **ctx):
    return render_template_string(PAGE, body=render_template_string(body, **ctx))


LOGIN_BODY = """
<div class="narrow card">
  <h1>Bathla Vault</h1>
  <form method="post" style="margin-top:16px;display:grid;gap:8px">
    <input type="password" name="password" placeholder="Password" autofocus required>
    <button type="submit">Enter</button>
  </form>
</div>
"""

HOME_BODY = """
<header>
  <h1>Bathla Vault</h1>
  <a href="{{ url_for('logout') }}">Log out</a>
</header>

<h2>Sheets</h2>
<div class="grid">
{% for s in sheets %}
  <div class="card">
    <a href="{{ s['url'] }}" target="_blank" rel="noopener"><strong>{{ s['title'] }}</strong></a>
    <div class="meta">{{ s['department'] or '-' }} · {{ s['owner'] or '-' }}</div>
    {% if s['description'] %}<div class="meta">{{ s['description'] }}</div>{% endif %}
    <form method="post" action="{{ url_for('delete_sheet', sid=s['id']) }}" style="margin-top:8px">
      <button class="danger" type="submit" onclick="return confirm('Remove this sheet from the vault? (The Google Sheet itself is not deleted.)')">Remove</button>
    </form>
  </div>
{% else %}<div class="meta">No sheets attached yet.</div>{% endfor %}
</div>
<div class="card" style="margin-top:12px">
  <form class="add" method="post" action="{{ url_for('add_sheet') }}">
    <input class="full" name="url" placeholder="Google Sheet link" required>
    <input name="title" placeholder="Title (e.g. Blinkit DRR Tracker)" required>
    <input name="department" placeholder="Department">
    <input name="owner" placeholder="Owner">
    <input class="full" name="description" placeholder="What is this sheet for? (optional)">
    <div class="full"><button type="submit">Attach sheet</button></div>
  </form>
</div>

<h2>Dashboards</h2>
<div class="grid">
{% for d in dashboards %}
  <div class="card">
    <a href="{{ url_for('view_dashboard', did=d['id']) }}" target="_blank"><strong>{{ d['title'] }}</strong></a>
    <div class="meta">{{ d['department'] or '-' }} · {{ d['owner'] or '-' }} · {{ d['created_at'][:10] }}</div>
    {% if d['description'] %}<div class="meta">{{ d['description'] }}</div>{% endif %}
    <form method="post" action="{{ url_for('delete_dashboard', did=d['id']) }}" style="margin-top:8px">
      <button class="danger" type="submit" onclick="return confirm('Delete this dashboard permanently?')">Delete</button>
    </form>
  </div>
{% else %}<div class="meta">No dashboards uploaded yet.</div>{% endfor %}
</div>
<div class="card" style="margin-top:12px">
  <form class="add" method="post" action="{{ url_for('upload_dashboard') }}" enctype="multipart/form-data">
    <input class="full" type="file" name="file" accept=".html,text/html" required>
    <input name="title" placeholder="Dashboard title" required>
    <input name="department" placeholder="Department">
    <input name="owner" placeholder="Your name" required>
    <input class="full" name="description" placeholder="What does it show? (optional)">
    <div class="full"><button type="submit">Upload dashboard</button>
    <span class="meta">Single .html file, up to 20 MB.</span></div>
  </form>
</div>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        given = request.form.get("password", "")
        if hmac.compare_digest(given.encode(), PASSWORD.encode()):
            session["ok"] = True
            return redirect(request.args.get("next") or url_for("home"))
        flash("Wrong password.")
    return page(LOGIN_BODY)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@require_login
def home():
    with db() as conn:
        sheets = conn.execute("SELECT * FROM sheets ORDER BY department, title").fetchall()
        dashboards = conn.execute("SELECT * FROM dashboards ORDER BY created_at DESC").fetchall()
    return page(HOME_BODY, sheets=sheets, dashboards=dashboards)


@app.route("/sheets", methods=["POST"])
@require_login
def add_sheet():
    url = request.form["url"].strip()
    if not SHEET_ID_RE.search(url):
        flash("That doesn't look like a Google Sheet link.")
        return redirect(url_for("home"))
    with db() as conn:
        conn.execute(
            "INSERT INTO sheets (title, url, department, owner, description, created_at) VALUES (?,?,?,?,?,?)",
            (request.form["title"].strip(), url, request.form.get("department", "").strip(),
             request.form.get("owner", "").strip(), request.form.get("description", "").strip(),
             datetime.now().isoformat(timespec="seconds")),
        )
    flash("Sheet attached.")
    return redirect(url_for("home"))


@app.route("/sheets/<int:sid>/delete", methods=["POST"])
@require_login
def delete_sheet(sid):
    with db() as conn:
        conn.execute("DELETE FROM sheets WHERE id = ?", (sid,))
    flash("Sheet removed from the vault.")
    return redirect(url_for("home"))


@app.route("/dashboards", methods=["POST"])
@require_login
def upload_dashboard():
    f = request.files.get("file")
    if not f or not f.filename.lower().endswith(".html"):
        flash("Please upload an .html file.")
        return redirect(url_for("home"))
    created = datetime.now()
    stored = f"{created:%Y%m%d%H%M%S%f}_{secure_filename(f.filename)}"
    f.save(os.path.join(UPLOAD_DIR, stored))
    with db() as conn:
        conn.execute(
            "INSERT INTO dashboards (title, owner, department, description, filename, created_at) VALUES (?,?,?,?,?,?)",
            (request.form["title"].strip(), request.form.get("owner", "").strip(),
             request.form.get("department", "").strip(), request.form.get("description", "").strip(),
             stored, created.isoformat(timespec="seconds")),
        )
    flash("Dashboard uploaded.")
    return redirect(url_for("home"))


@app.route("/dashboards/<int:did>")
@require_login
def view_dashboard(did):
    with db() as conn:
        row = conn.execute("SELECT filename FROM dashboards WHERE id = ?", (did,)).fetchone()
    if not row:
        abort(404)
    resp = send_from_directory(UPLOAD_DIR, row["filename"], mimetype="text/html")
    # Uploaded pages run their own scripts, but in a sandbox with a unique
    # origin: they cannot read the vault session cookie or call vault pages.
    resp.headers["Content-Security-Policy"] = "sandbox allow-scripts allow-forms"
    return resp


@app.route("/dashboards/<int:did>/delete", methods=["POST"])
@require_login
def delete_dashboard(did):
    with db() as conn:
        row = conn.execute("SELECT filename FROM dashboards WHERE id = ?", (did,)).fetchone()
        if row:
            conn.execute("DELETE FROM dashboards WHERE id = ?", (did,))
            path = os.path.join(UPLOAD_DIR, row["filename"])
            if os.path.exists(path):
                os.remove(path)
    flash("Dashboard deleted.")
    return redirect(url_for("home"))


init_db()

if __name__ == "__main__":
    if not PASSWORD:
        raise SystemExit("Set VAULT_PASSWORD before starting the vault.")
    app.run(host="127.0.0.1", port=int(os.getenv("VAULT_PORT", "5050")), debug=False)
