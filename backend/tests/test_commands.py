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
