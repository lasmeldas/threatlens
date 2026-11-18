"""The detection engine here must give the same alerts as authwatch itself.

tests/data/authwatch_logs.json holds 28 logs and the alerts the real authwatch produced for them.
"""

import json
from pathlib import Path

from django.test import SimpleTestCase

from detection import detect, parse_lines

LOGS = json.loads((Path(__file__).parent / "data" / "authwatch_logs.json").read_text(encoding="utf-8"))["logs"]


class DetectionParityTests(SimpleTestCase):
    def test_matches_authwatch_on_every_log(self):
        for i, log in enumerate(LOGS):
            with self.subTest(log=i):
                events = list(parse_lines(log["text"].splitlines(True), log["year"]))
                alerts = [a.to_dict() for a in detect(events, **log["opts"])]
                self.assertEqual(alerts, log["alerts"])

    def test_the_fixtures_cover_all_three_rules(self):
        kinds = {a["kind"] for log in LOGS for a in log["alerts"]}
        self.assertEqual(kinds, {"success_after_failures", "brute_force", "username_spray"})
