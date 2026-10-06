# Deploying the vault to PythonAnywhere

The vault runs on PythonAnywhere behind a password. Anyone with the link sees
only the login page until they enter a password.

## 1. Get the code onto PythonAnywhere

Open a **Bash console** on PythonAnywhere and run (replace `YOUR_USERNAME`):

```bash
git clone https://github.com/tannitadigpati7-bit/bathla-vault.git
```

The repo is private, so you may need to log in to GitHub or use a token.

## 2. Install the requirements

In the same Bash console:

```bash
pip install --user -r bathla-vault/requirements.txt
```

## 3. Create the web app

1. **Web** tab -> **Add a new web app** -> **Manual configuration** -> pick the same Python version as your console.
2. Open the **WSGI configuration file** link and replace its contents with
   `pythonanywhere_wsgi.py` (change `YOUR_USERNAME` in it).
3. Under **Environment variables** on the Web tab, add:
   - `VAULT_PASSWORD` - the member password (view and add)
   - `VAULT_ADMIN_PASSWORD` - the admin password (view, add and delete)
   - `VAULT_SECRET_KEY` - a long random string, so logins survive reloads
   Do not set `VAULT_LOCAL_OPEN`.
4. Click **Reload**.

Your link is `https://YOUR_USERNAME.pythonanywhere.com`.

## 4. Your data

The database (`vault.db`) and uploaded dashboards (`uploads/`) are created on
the server the first time it starts. They are not in GitHub. The vault on your
PC has the current sheets, apps and dashboards; to copy them up, upload
`vault.db` and the `uploads/` folder into `bathla-vault/` on PythonAnywhere
with the **Files** tab. Skip this step if you'd rather start empty.

## Updating later

In the Bash console, `cd bathla-vault && git pull`, then **Reload** the web app.
