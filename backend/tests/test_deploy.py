import os
import tempfile
from io import StringIO
from pathlib import Path
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase, override_settings

from alerts.models import Upload


class SinglePageAppTests(SimpleTestCase):
    def setUp(self):
        self.dist = Path(tempfile.mkdtemp())
        (self.dist / "index.html").write_text("<!doctype html><title>ThreatLens</title>")

    def test_health_check_needs_no_login_or_database(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"ok")

    def test_client_side_routes_return_the_app(self):
        with override_settings(FRONTEND_DIST=self.dist):
            for path in ["/", "/alerts", "/alerts/12", "/model"]:
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200, path)
                self.assertIn(b"ThreatLens", b"".join(response.streaming_content), path)
                self.assertEqual(response["Cache-Control"], "no-cache")

    def test_unbuilt_dashboard_is_a_clear_404(self):
        with override_settings(FRONTEND_DIST=self.dist / "missing"):
            self.assertEqual(self.client.get("/alerts").status_code, 404)

    def test_api_paths_are_never_swallowed_by_the_app(self):
        with override_settings(FRONTEND_DIST=self.dist):
            response = self.client.get("/api/alerts/")
            self.assertEqual(response.status_code, 401)
            self.assertEqual(self.client.get("/api/nope/").status_code, 404)
            self.assertNotIn(b"ThreatLens", self.client.get("/api/nope/").content)

    def test_security_headers_on_the_app_but_not_the_admin(self):
        with override_settings(FRONTEND_DIST=self.dist):
            response = self.client.get("/alerts")
        self.assertIn("default-src 'self'", response["Content-Security-Policy"])
        self.assertEqual(response["Referrer-Policy"], "no-referrer")
        self.assertNotIn("Content-Security-Policy", self.client.get("/admin/login/"))


ENV = {
    "THREATLENS_ADMIN_USER": "analyst",
    "THREATLENS_ADMIN_PASSWORD": "a-long-demo-passphrase-1",
    "THREATLENS_VIEWER_USER": "viewer",
    "THREATLENS_VIEWER_PASSWORD": "another-long-passphrase-2",
    "THREATLENS_SEED_DEMO": "true",
}


class BootstrapDemoTests(TestCase):
    def run_command(self, **env):
        out = StringIO()
        with mock.patch.dict(os.environ, env, clear=False):
            call_command("bootstrap_demo", stdout=out)
        return out.getvalue()

    def test_does_nothing_without_credentials(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            for key in ENV:
                os.environ.pop(key, None)
            call_command("bootstrap_demo", stdout=StringIO())
        self.assertEqual(get_user_model().objects.count(), 0)

    def test_creates_both_roles_and_loads_sample_data_once(self):
        self.run_command(**ENV)
        User = get_user_model()
        self.assertTrue(User.objects.get(username="analyst").groups.filter(name="analyst").exists())
        self.assertTrue(User.objects.get(username="viewer").groups.filter(name="viewer").exists())
        uploads = Upload.objects.count()
        self.assertEqual(uploads, 2)
        self.run_command(**ENV)  # a restart must not duplicate anything
        self.assertEqual(Upload.objects.count(), uploads)
        self.assertEqual(User.objects.count(), 2)

    def test_restart_never_resets_an_existing_password(self):
        self.run_command(**ENV)
        user = get_user_model().objects.get(username="analyst")
        user.set_password("changed-by-the-owner-3")
        user.save()
        self.run_command(**ENV)
        self.assertTrue(get_user_model().objects.get(username="analyst").check_password("changed-by-the-owner-3"))

    def test_weak_password_is_refused(self):
        with self.assertRaises(CommandError):
            self.run_command(**{**ENV, "THREATLENS_ADMIN_PASSWORD": "short"})

    def test_demo_login_works_end_to_end(self):
        self.run_command(**ENV)
        response = self.client.post("/api/auth/token/", {"username": "viewer", "password": ENV["THREATLENS_VIEWER_PASSWORD"]}, content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("token", response.json())
