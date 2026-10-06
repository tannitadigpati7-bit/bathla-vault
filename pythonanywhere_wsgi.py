# Paste this into the WSGI configuration file on PythonAnywhere
# (Web tab -> "WSGI configuration file" link). Replace YOUR_USERNAME.
import sys

path = "/home/YOUR_USERNAME/bathla-vault"
if path not in sys.path:
    sys.path.insert(0, path)

from app import app as application  # noqa: E402
