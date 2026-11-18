import getpass
import os

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from alerts.permissions import ANALYST_GROUP, VIEWER_GROUP


class Command(BaseCommand):
    help = "Create a user with the analyst or viewer role. The password comes from THREATLENS_PASSWORD or a prompt."

    def add_arguments(self, parser):
        parser.add_argument("username")
        parser.add_argument("--role", choices=[ANALYST_GROUP, VIEWER_GROUP], default=VIEWER_GROUP)

    def handle(self, *args, username, role, **options):
        User = get_user_model()
        if User.objects.filter(username=username).exists():
            raise CommandError(f"User '{username}' already exists.")
        password = os.environ.get("THREATLENS_PASSWORD") or getpass.getpass("Password: ")
        try:
            validate_password(password)
        except ValidationError as error:
            raise CommandError("; ".join(error.messages))
        user = User.objects.create_user(username=username, password=password)
        group, _ = Group.objects.get_or_create(name=role)
        user.groups.add(group)
        self.stdout.write(self.style.SUCCESS(f"Created {role} '{username}'."))
