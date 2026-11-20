from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from alerts import services
from alerts.models import Upload

DATA = Path(__file__).resolve().parents[2] / "sample_data"


class Command(BaseCommand):
    help = "Load the two bundled sample files (an SSH log and 60 network connections) as uploads by an existing user, so the dashboard has something to show."

    def add_arguments(self, parser):
        parser.add_argument("--user", required=True, help="username of an existing analyst or admin")
        parser.add_argument("--year", type=int, default=2026, help="year to assume for the SSH log, which has no year in it")

    def handle(self, *args, user, year, **options):
        owner = get_user_model().objects.filter(username=user).first()
        if owner is None:
            raise CommandError(f"No user named '{user}'. Create one first with create_user.")
        if Upload.objects.filter(name__in=["sample SSH log", "sample network connections"]).exists():
            raise CommandError("The sample data is already loaded.")
        ssh = services.analyze_ssh_log(owner, name="sample SSH log", text=(DATA / "auth.log").read_text(), year=year)
        result = services.analyze_connections(owner, name="sample network connections", text=(DATA / "connections_sample.csv").read_text())
        self.stdout.write(self.style.SUCCESS(f"Loaded sample SSH log ({ssh.alerts.count()} alerts) and {result['records']} sample connections ({result['alerts_created']} alerts)."))
