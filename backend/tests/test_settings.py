import os
import subprocess
import sys
from pathlib import Path

from django.test import SimpleTestCase

BACKEND = Path(__file__).resolve().parent.parent


class SettingsSafetyTests(SimpleTestCase):
    def check(self, **env):
        clean = {k: v for k, v in os.environ.items() if not k.startswith("DJANGO_")}
        clean.update(env, DJANGO_SETTINGS_MODULE="config.settings")
        return subprocess.run([sys.executable, "-c", "import config.settings as s; print(s.DEBUG, s.SESSION_COOKIE_SECURE if not s.DEBUG else '-')"], cwd=BACKEND, env=clean, capture_output=True, text=True)

    def test_production_refuses_to_start_without_a_secret_key(self):
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DJANGO_SECRET_KEY", result.stderr)

    def test_production_defaults_are_secure(self):
        result = self.check(DJANGO_SECRET_KEY="x" * 50)
        self.assertEqual(result.stdout.strip(), "False True")
