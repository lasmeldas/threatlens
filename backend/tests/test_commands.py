import os
from io import StringIO
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase


class CreateUserTests(TestCase):
    def run_command(self, *args, password="correct-horse-battery-1"):
        with mock.patch.dict(os.environ, {"THREATLENS_PASSWORD": password}):
            call_command("create_user", *args, stdout=StringIO())

    def test_creates_a_user_in_the_right_group(self):
        self.run_command("ana", "--role", "analyst")
        self.assertTrue(User.objects.get(username="ana").groups.filter(name="analyst").exists())

    def test_defaults_to_viewer(self):
        self.run_command("vic")
        self.assertTrue(User.objects.get(username="vic").groups.filter(name="viewer").exists())

    def test_weak_passwords_and_duplicates_are_refused(self):
        with self.assertRaises(CommandError):
            self.run_command("ana", password="12345")
        self.run_command("ana")
        with self.assertRaises(CommandError):
            self.run_command("ana")


class SeedDemoTests(TestCase):
    def test_loads_both_samples_once_and_refuses_a_second_time(self):
        from alerts.models import Alert, Upload

        User.objects.create_user("ana", password="correct-horse-battery-1")
        out = StringIO()
        call_command("seed_demo", "--user", "ana", stdout=out)
        self.assertIn("3 alerts", out.getvalue())
        self.assertIn("14 alerts", out.getvalue())
        self.assertEqual(Upload.objects.count(), 2)
        self.assertEqual((Alert.objects.filter(source="rules").count(), Alert.objects.filter(source="ml").count()), (3, 14))
        with self.assertRaises(CommandError):
            call_command("seed_demo", "--user", "ana", stdout=StringIO())

    def test_needs_an_existing_user(self):
        with self.assertRaises(CommandError):
            call_command("seed_demo", "--user", "nobody", stdout=StringIO())

    def test_bundled_samples_match_the_originals(self):
        from pathlib import Path

        repo = Path(__file__).resolve().parents[2]
        bundled = repo / "backend" / "alerts" / "sample_data"
        self.assertEqual((bundled / "connections_sample.csv").read_text(), (repo / "ml" / "sample" / "connections_sample.csv").read_text())
