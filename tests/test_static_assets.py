"""主页拆分配套：/、/v2 主页、/ui/ 白名单静态资源、CSP 与模块依赖边界。"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import api


EXPECTED_CSP = (
    "default-src 'self'; "
    "script-src 'self' https://static.cloudflareinsights.com; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self' https://cloudflareinsights.com; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "object-src 'none'; "
    "form-action 'self'"
)


class StaticAssetsTest(unittest.TestCase):
    ENV_NAMES = ("APP_DB_PATH", "PUBLIC_BASE_URL", "CSRF_SECRET", "RULESET_DIR")

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.previous_env = {name: os.environ.get(name) for name in self.ENV_NAMES}
        os.environ.update(
            {
                "APP_DB_PATH": os.path.join(self.tmpdir.name, "app.db"),
                "PUBLIC_BASE_URL": "https://test.local",
                "CSRF_SECRET": "test-secret-that-is-longer-than-thirty-two-characters",
                "RULESET_DIR": os.path.join(self.tmpdir.name, "ruleset"),
            }
        )
        # 用临时目录模拟 design/：主页、资源目录与一个白名单外的同目录文件。
        self.design_dir = Path(self.tmpdir.name, "design")
        self.assets_dir = self.design_dir / "assets"
        self.assets_dir.mkdir(parents=True)
        (self.design_dir / "index.html").write_text(
            '<!doctype html><link rel="stylesheet" href="/ui/app.css"><script src="/ui/app.js" defer></script>',
            encoding="utf-8",
        )
        (self.assets_dir / "app.css").write_text("body{color:#fff}", encoding="utf-8")
        (self.assets_dir / "app.js").write_text("console.log('主页');", encoding="utf-8")
        (self.assets_dir / "secret.txt").write_text("not-public", encoding="utf-8")
        missing_dir = Path(self.tmpdir.name, "missing")
        self.patches = [
            patch.object(api, "V2_PREVIEW_CANDIDATES", [missing_dir / "index.html", self.design_dir / "index.html"]),
            patch.object(api, "UI_ASSET_DIR_CANDIDATES", [missing_dir / "assets", self.assets_dir]),
        ]
        for item in self.patches:
            item.start()
        self.client = TestClient(api.app)

    def tearDown(self):
        self.client.close()
        for item in reversed(self.patches):
            item.stop()
        for name, value in self.previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        self.tmpdir.cleanup()

    def test_root_and_v2_serve_index_html_with_csp(self):
        root = self.client.get("/")
        v2 = self.client.get("/v2")
        self.assertEqual(200, root.status_code)
        self.assertEqual(200, v2.status_code)
        self.assertEqual(root.content, v2.content)
        self.assertIn(b"/ui/app.js", root.content)
        self.assertTrue(root.headers["content-type"].startswith("text/html"))
        self.assertEqual("no-cache", root.headers.get("cache-control"))
        self.assertEqual(EXPECTED_CSP, root.headers.get("content-security-policy"))

    def test_ui_assets_have_exact_media_type_and_no_cache(self):
        cases = {
            "/ui/app.css": ("text/css; charset=utf-8", b"body{color:#fff}"),
            "/ui/app.js": ("text/javascript; charset=utf-8", "console.log('主页');".encode("utf-8")),
        }
        for path, (media_type, body) in cases.items():
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(200, response.status_code)
                self.assertEqual(media_type, response.headers.get("content-type"))
                self.assertEqual("no-cache", response.headers.get("cache-control"))
                self.assertEqual(body, response.content)
                self.assertEqual(EXPECTED_CSP, response.headers.get("content-security-policy"))
                self.assertEqual("nosniff", response.headers.get("x-content-type-options"))

    def test_missing_ui_asset_returns_404(self):
        (self.assets_dir / "app.js").unlink()
        response = self.client.get("/ui/app.js")
        self.assertEqual(404, response.status_code)
        self.assertEqual(EXPECTED_CSP, response.headers.get("content-security-policy"))
        self.assertEqual(200, self.client.get("/ui/app.css").status_code)

    def test_missing_index_returns_404(self):
        (self.design_dir / "index.html").unlink()
        self.assertEqual(404, self.client.get("/").status_code)
        self.assertEqual(404, self.client.get("/v2").status_code)

    def test_only_whitelisted_ui_files_are_served(self):
        for path in (
            "/ui/secret.txt",
            "/ui/index.html",
            "/ui/assets/app.js",
            "/ui/app.js/",
            "/ui/..%2Findex.html",
            "/ui/%2e%2e/%2e%2e/src/api.py",
            "/ui/app.css%2F..%2Fsecret.txt",
            "/ui/",
        ):
            with self.subTest(path=path):
                response = self.client.get(path, follow_redirects=False)
                self.assertIn(response.status_code, {404, 307}, response.text)
                self.assertNotIn(b"not-public", response.content)

    def test_json_responses_also_carry_csp(self):
        response = self.client.get("/api/session")
        self.assertEqual(200, response.status_code)
        self.assertEqual(EXPECTED_CSP, response.headers.get("content-security-policy"))


class ModuleBoundaryTest(unittest.TestCase):
    def test_backend_service_modules_do_not_import_api(self):
        """Streamlit 依赖的后端模块不能再把 api（FastAPI app 装配）拉进来。"""
        src_dir = Path(__file__).resolve().parent.parent / "src"
        code = (
            "import sys\n"
            "import ruleset_store, draft_service, auth_service, api_errors\n"
            "assert 'api' not in sys.modules, 'api 被间接导入'\n"
            "print('ok')\n"
        )
        env = dict(os.environ, PYTHONPATH=str(src_dir), PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=str(src_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("ok", result.stdout.strip())

    def test_web_app_imports_ruleset_helpers_from_ruleset_store(self):
        web_app_source = (Path(__file__).resolve().parent.parent / "src" / "web_app.py").read_text(encoding="utf-8")
        self.assertNotIn("from api import", web_app_source)
        self.assertIn("from ruleset_store import _ruleset_user_lock", web_app_source)


if __name__ == "__main__":
    unittest.main()
