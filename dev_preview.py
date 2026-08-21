import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

os.environ.setdefault("CSRF_SECRET", "local-dev-secret-that-is-at-least-32-chars-long")
os.environ.setdefault("PUBLIC_BASE_URL", "http://localhost:8000")
os.environ.setdefault("AUTH_COOKIE_SECURE", "false")
os.environ.setdefault("ALLOW_REGISTRATION", "false")
os.environ.setdefault("MIHOMO_VALIDATE_ENABLED", "false")
os.environ.setdefault("APP_DB_PATH", os.path.join(os.path.dirname(__file__), "_dev.db"))

import api
import uvicorn

if __name__ == "__main__":
    uvicorn.run(api.app, host="127.0.0.1", port=8000, reload=False)
