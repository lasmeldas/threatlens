import os

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError

from alerts.models import Upload
from alerts.permissions import ANALYST_GROUP, VIEWER_GROUP


class Command(BaseCommand):
    help = (
        "First-start setup for a hosted instance. Creates an analyst from THREATLENS_ADMIN_USER / THREATLENS_ADMIN_PASSWORD "
        "(and an optional read-only viewer from THREATLENS_VIEWER_USER / THREATLENS_VIEWER_PASSWORD), then loads the sample data "
        "once when THREATLENS_SEED_DEMO is on. Safe to run on every start: it never changes an existing user."
    )

    def make(self, username, password, role):
        User = get_user_model()
        if User.objects.filter(username=username).exists():
            self.stdout.write(f"User '{username}' already exists; left unchanged.")
            return None
        try:
            validate_password(password)
        except ValidationError as error:
            raise CommandError(f"Password for '{username}': " + "; ".join(error.messages))
        user = User.objects.create_user(username=username, password=password)
        group, _ = Group.objects.get_or_create(name=role)
        user.groups.add(group)
        self.stdout.write(self.style.SUCCESS(f"Created {role} '{username}'."))
        return user

    def handle(self, *args, **options):
        admin_user = os.environ.get("THREATLENS_ADMIN_USER", "").strip()
        admin_password = os.environ.get("THREATLENS_ADMIN_PASSWORD", "")
        if not admin_user or not admin_password:
            self.stdout.write("THREATLENS_ADMIN_USER / THREATLENS_ADMIN_PASSWORD not set; no users created.")
            return
        self.make(admin_user, admin_password, ANALYST_GROUP)
        viewer_user = os.environ.get("THREATLENS_VIEWER_USER", "").strip()
        viewer_password = os.environ.get("THREATLENS_VIEWER_PASSWORD", "")
        if viewer_user and viewer_password:
            self.make(viewer_user, viewer_password, VIEWER_GROUP)
        wants_seed = os.environ.get("THREATLENS_SEED_DEMO", "").strip().lower() in {"1", "true", "yes", "on"}
        if wants_seed and not Upload.objects.exists():
            call_command("seed_demo", user=admin_user, stdout=self.stdout)
