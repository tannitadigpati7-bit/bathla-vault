# Bathla Vault

One internal place for company Google Sheets and the dashboards people build.

## Run locally

1. `pip install -r requirements.txt`
2. Set a password: `set VAULT_PASSWORD=your-password` (PowerShell: `$env:VAULT_PASSWORD="..."`)
3. `python app.py` and open http://127.0.0.1:5050

The app refuses to start without `VAULT_PASSWORD`.

## What it does

- **Sheets:** attach a Google Sheet by link with title, department, owner. The vault stores the link only; sharing stays with Google Drive. "Remove" does not delete the sheet.
- **Dashboards:** upload a single self-contained `.html` file (max 20 MB). It is stored in `uploads/` and rendered in a sandboxed frame.

## Notes

- Data lives in `vault.db` and `uploads/`, both git-ignored. Back them up.
- Everyone with the password sees everything. Per-person access is not built yet.
