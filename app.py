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
PASSWORD = os.getenv("VAULT_PASSWORD")              # members: add and view
ADMIN_PASSWORD = os.getenv("VAULT_ADMIN_PASSWORD")  # admins: add, view and delete
# Local-only: skip the login when no password is set. Only honoured on
# 127.0.0.1, so a hosted copy with no password still refuses to start.
# Local-open users are treated as admins, since it's your own PC.
LOCAL_OPEN = os.getenv("VAULT_LOCAL_OPEN") == "1" and not (PASSWORD or ADMIN_PASSWORD)

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
            CREATE TABLE IF NOT EXISTS apps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                url TEXT NOT NULL,
                department TEXT,
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
        cols = [r[1] for r in conn.execute("PRAGMA table_info(dashboards)")]
        if "url" not in cols:
            conn.execute("ALTER TABLE dashboards ADD COLUMN url TEXT")
    os.makedirs(UPLOAD_DIR, exist_ok=True)


def logged_in():
    return LOCAL_OPEN or session.get("ok") is True


def is_admin():
    return LOCAL_OPEN or session.get("role") == "admin"


def require_admin(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not is_admin():
            flash("Only admins can delete items.")
            return redirect(url_for("home"))
        return view(*args, **kwargs)

    return wrapped


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
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bathla Vault</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>
  tailwind.config = { theme: { extend: {
    colors: {
      background: 'hsl(var(--background))', foreground: 'hsl(var(--foreground))',
      card: 'hsl(var(--card))', 'card-foreground': 'hsl(var(--card-foreground))',
      muted: 'hsl(var(--muted))', 'muted-foreground': 'hsl(var(--muted-foreground))',
      primary: 'hsl(var(--primary))', 'primary-foreground': 'hsl(var(--primary-foreground))',
      border: 'hsl(var(--border))', input: 'hsl(var(--input))', ring: 'hsl(var(--ring))',
      destructive: 'hsl(var(--destructive))'
    },
    borderRadius: { lg: 'var(--radius)', md: 'calc(var(--radius) - 2px)', sm: 'calc(var(--radius) - 4px)' }
  } } };
</script>
<style>
  /* shadcn/ui "zinc" theme tokens: light by default, dark when the system asks for it. */
  :root {
    --background: 0 0% 100%; --foreground: 240 10% 3.9%;
    --card: 0 0% 100%; --card-foreground: 240 10% 3.9%;
    --muted: 240 4.8% 95.9%; --muted-foreground: 240 3.8% 46.1%;
    --primary: 240 5.9% 10%; --primary-foreground: 0 0% 98%;
    --border: 240 5.9% 90%; --input: 240 5.9% 90%; --ring: 240 5.9% 10%;
    --destructive: 0 84.2% 60.2%; --radius: 0.5rem;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --background: 240 10% 3.9%; --foreground: 0 0% 98%;
      --card: 240 10% 3.9%; --card-foreground: 0 0% 98%;
      --muted: 240 3.7% 15.9%; --muted-foreground: 240 5% 64.9%;
      --primary: 0 0% 98%; --primary-foreground: 240 5.9% 10%;
      --border: 240 3.7% 15.9%; --input: 240 3.7% 15.9%; --ring: 240 4.9% 83.9%;
      --destructive: 0 62.8% 30.6%;
    }
  }
  body { background: hsl(var(--background)); color: hsl(var(--foreground)); font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }
</style>
</head>
<body class="antialiased">
<main class="mx-auto max-w-5xl px-4 py-8">
{% with msgs = get_flashed_messages() %}{% for m in msgs %}
  <div class="mb-6 rounded-md border bg-muted px-4 py-3 text-sm">{{ m }}</div>
{% endfor %}{% endwith %}
{{ body|safe }}
</main>
</body>
</html>
"""


def page(body, **ctx):
    ctx.setdefault("admin", is_admin())
    return render_template_string(PAGE, body=render_template_string(body, **ctx))


# shadcn/ui class sets, filled into the templates below.
TOKENS = {
    "__BTN__": "inline-flex h-9 items-center justify-center rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground shadow hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
    "__INPUT__": "flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
    "__CARD__": "rounded-lg border bg-card text-card-foreground shadow-sm",
    "__GHOST__": "text-sm text-muted-foreground underline-offset-4 hover:text-destructive hover:underline",
    "__BADGE__": "rounded-md border px-2 py-0.5 text-xs font-medium text-muted-foreground",
}

LOGIN_BODY = """
<div class="mx-auto mt-24 max-w-sm __CARD__ p-6">
  <h1 class="text-lg font-semibold tracking-tight">Bathla Vault</h1>
  <p class="mt-1 text-sm text-muted-foreground">Enter the password to continue.</p>
  <form method="post" class="mt-6 grid gap-3">
    <input class="__INPUT__" type="password" name="password" placeholder="Password" autofocus required>
    <button class="__BTN__" type="submit">Enter</button>
  </form>
</div>
"""

HOME_BODY = """
<header class="mb-8 flex items-center justify-between">
  <div>
    <h1 class="text-2xl font-semibold tracking-tight">Bathla Vault</h1>
    <p class="text-sm text-muted-foreground">Company sheets and dashboards in one place.</p>
  </div>
  <div class="flex items-center gap-3">
    <span class="__BADGE__">{% if admin %}Admin{% else %}Member{% endif %}</span>
    <a class="text-sm text-muted-foreground hover:text-foreground" href="{{ url_for('logout') }}">Log out</a>
  </div>
</header>

<section class="mb-10">
  <div class="mb-4 flex items-baseline justify-between">
    <h2 class="text-lg font-semibold tracking-tight">Sheets</h2>
    <span class="text-sm text-muted-foreground">{{ sheets|length }} attached</span>
  </div>
  <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
  {% for s in sheets %}
    <div class="__CARD__ flex flex-col p-5">
      <div class="flex items-start justify-between gap-2">
        <a class="font-medium underline-offset-4 hover:underline" href="{{ s['url'] }}" target="_blank" rel="noopener">{{ s['title'] }}</a>
        {% if s['department'] %}<span class="__BADGE__">{{ s['department'] }}</span>{% endif %}
      </div>
      {% if s['description'] %}<p class="mt-2 text-sm text-muted-foreground">{{ s['description'] }}</p>{% endif %}
    {% if admin %}<div class="mt-auto pt-4">
        <form method="post" action="{{ url_for('delete_sheet', sid=s['id']) }}">
          <button class="__GHOST__" type="submit" onclick="return confirm('Remove this sheet from the vault? (The Google Sheet itself is not deleted.)')">Remove</button>
        </form>
      </div>{% endif %}
    </div>
  {% else %}<p class="text-sm text-muted-foreground">No sheets attached yet.</p>{% endfor %}
  </div>
  <form class="__CARD__ mt-4 grid gap-3 p-5 sm:grid-cols-2" method="post" action="{{ url_for('add_sheet') }}">
    <p class="text-sm font-medium sm:col-span-2">Attach a sheet</p>
    <input class="__INPUT__ sm:col-span-2" name="url" placeholder="Google Sheet link" required>
    <input class="__INPUT__" name="title" placeholder="Title (e.g. Blinkit DRR Tracker)" required>
    <input class="__INPUT__" name="department" placeholder="Department">
    <input class="__INPUT__ sm:col-span-2" name="description" placeholder="What is this sheet for? (optional)">
    <input class="__INPUT__" name="owner" placeholder="Owner (optional)">
    <div class="sm:col-span-2"><button class="__BTN__" type="submit">Attach sheet</button></div>
  </form>
</section>

<section class="mb-10">
  <div class="mb-4 flex items-baseline justify-between">
    <h2 class="text-lg font-semibold tracking-tight">Apps</h2>
    <span class="text-sm text-muted-foreground">{{ apps|length }} projects</span>
  </div>
  <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
  {% for a in apps %}
    <div class="__CARD__ flex flex-col p-5">
      <div class="flex items-start justify-between gap-2">
        <a class="font-medium underline-offset-4 hover:underline" href="{{ a['url'] }}" target="_blank" rel="noopener">{{ a['title'] }}</a>
        {% if a['department'] %}<span class="__BADGE__">{{ a['department'] }}</span>{% endif %}
      </div>
      {% if a['description'] %}<p class="mt-2 text-sm text-muted-foreground">{{ a['description'] }}</p>{% endif %}
    {% if admin %}<div class="mt-auto pt-4">
        <form method="post" action="{{ url_for('delete_app', aid=a['id']) }}">
          <button class="__GHOST__" type="submit" onclick="return confirm('Remove this app from the vault? (The project itself is not deleted.)')">Remove</button>
        </form>
      </div>{% endif %}
    </div>
  {% else %}<p class="text-sm text-muted-foreground">No apps added yet.</p>{% endfor %}
  </div>
</section>

<section>
  <div class="mb-4 flex items-baseline justify-between">
    <h2 class="text-lg font-semibold tracking-tight">Dashboards</h2>
    <span class="text-sm text-muted-foreground">{{ dashboards|length }} uploaded</span>
  </div>
  <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
  {% for d in dashboards %}
    <div class="__CARD__ flex flex-col p-5">
      <div class="flex items-start justify-between gap-2">
        <a class="font-medium underline-offset-4 hover:underline" href="{{ d['url'] or url_for('view_dashboard', did=d['id']) }}" target="_blank" rel="noopener">{{ d['title'] }}</a>
        {% if d['department'] %}<span class="__BADGE__">{{ d['department'] }}</span>{% endif %}
      </div>
      {% if d['description'] %}<p class="mt-2 text-sm text-muted-foreground">{{ d['description'] }}</p>{% endif %}
      <p class="mt-2 text-xs text-muted-foreground">{% if d['owner'] %}{{ d['owner'] }} · {% endif %}{{ d['created_at'][:10] }}</p>
    {% if admin %}<div class="mt-auto pt-4">
        <form method="post" action="{{ url_for('delete_dashboard', did=d['id']) }}">
          <button class="__GHOST__" type="submit" onclick="return confirm('Delete this dashboard permanently?')">Delete</button>
        </form>
      </div>{% endif %}
    </div>
  {% else %}<p class="text-sm text-muted-foreground">No dashboards uploaded yet.</p>{% endfor %}
  </div>
  <form class="__CARD__ mt-4 grid gap-3 p-5 sm:grid-cols-2" method="post" action="{{ url_for('upload_dashboard') }}" enctype="multipart/form-data">
    <p class="text-sm font-medium sm:col-span-2">Upload a dashboard</p>
    <input class="__INPUT__ sm:col-span-2" type="file" name="file" accept=".html,text/html" required>
    <input class="__INPUT__" name="title" placeholder="Dashboard title" required>
    <input class="__INPUT__" name="department" placeholder="Department">
    <input class="__INPUT__" name="owner" placeholder="Your name" required>
    <input class="__INPUT__" name="description" placeholder="What does it show? (optional)">
    <div class="flex items-center gap-3 sm:col-span-2">
      <button class="__BTN__" type="submit">Upload dashboard</button>
      <span class="text-xs text-muted-foreground">Single .html file, up to 20 MB.</span>
    </div>
  </form>
</section>
"""

for _k, _v in TOKENS.items():
    LOGIN_BODY = LOGIN_BODY.replace(_k, _v)
    HOME_BODY = HOME_BODY.replace(_k, _v)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        given = request.form.get("password", "").encode()
        if ADMIN_PASSWORD and hmac.compare_digest(given, ADMIN_PASSWORD.encode()):
            session.update(ok=True, role="admin")
            return redirect(request.args.get("next") or url_for("home"))
        if PASSWORD and hmac.compare_digest(given, PASSWORD.encode()):
            session.update(ok=True, role="member")
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
        apps = conn.execute("SELECT * FROM apps ORDER BY title").fetchall()
    return page(HOME_BODY, sheets=sheets, dashboards=dashboards, apps=apps)


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
@require_admin
def delete_sheet(sid):
    with db() as conn:
        conn.execute("DELETE FROM sheets WHERE id = ?", (sid,))
    flash("Sheet removed from the vault.")
    return redirect(url_for("home"))


@app.route("/apps", methods=["POST"])
@require_login
def add_app():
    url = request.form["url"].strip()
    if not url.startswith(("http://", "https://")):
        flash("App link must start with http:// or https://")
        return redirect(url_for("home"))
    with db() as conn:
        conn.execute(
            "INSERT INTO apps (title, url, department, description, created_at) VALUES (?,?,?,?,?)",
            (request.form["title"].strip(), url, request.form.get("department", "").strip(),
             request.form.get("description", "").strip(), datetime.now().isoformat(timespec="seconds")),
        )
    flash("App added.")
    return redirect(url_for("home"))


@app.route("/apps/<int:aid>/delete", methods=["POST"])
@require_login
@require_admin
def delete_app(aid):
    with db() as conn:
        conn.execute("DELETE FROM apps WHERE id = ?", (aid,))
    flash("App removed from the vault.")
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
        row = conn.execute("SELECT filename, url FROM dashboards WHERE id = ?", (did,)).fetchone()
    if not row:
        abort(404)
    if row["url"]:
        return redirect(row["url"])
    resp = send_from_directory(UPLOAD_DIR, row["filename"], mimetype="text/html")
    # Uploaded pages run their own scripts, but in a sandbox with a unique
    # origin: they cannot read the vault session cookie or call vault pages.
    resp.headers["Content-Security-Policy"] = "sandbox allow-scripts allow-forms"
    return resp


@app.route("/dashboards/<int:did>/delete", methods=["POST"])
@require_login
@require_admin
def delete_dashboard(did):
    with db() as conn:
        row = conn.execute("SELECT filename FROM dashboards WHERE id = ?", (did,)).fetchone()
        if row:
            conn.execute("DELETE FROM dashboards WHERE id = ?", (did,))
            path = os.path.join(UPLOAD_DIR, row["filename"] or "")
            if row["filename"] and os.path.exists(path):
                os.remove(path)
    flash("Dashboard deleted.")
    return redirect(url_for("home"))


init_db()

if __name__ == "__main__":
    if not (PASSWORD or ADMIN_PASSWORD or LOCAL_OPEN):
        raise SystemExit("Set VAULT_PASSWORD and/or VAULT_ADMIN_PASSWORD, or VAULT_LOCAL_OPEN=1 for local use.")
    app.run(host="127.0.0.1", port=int(os.getenv("VAULT_PORT", "5050")), debug=False)
