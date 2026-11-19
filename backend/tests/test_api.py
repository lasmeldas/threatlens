from django.contrib.auth.models import Group, User
from django.test import override_settings
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase

from alerts.models import Alert, AuditEntry

BRUTE = "".join(
    f"Nov  8 03:12:{s:02d} web01 sshd[1]: Failed password for {u} from 203.0.113.45 port 22 ssh2\n"
    for s, u in [(1, "root"), (3, "admin"), (5, "test"), (8, "ubuntu"), (10, "oracle")]
) + "Nov  8 03:12:19 web01 sshd[1]: Accepted password for ubuntu from 203.0.113.45 port 22 ssh2\n"


def make_user(name, role=None, superuser=False):
    user = User.objects.create_user(name, password="correct-horse-battery-1", is_superuser=superuser, is_staff=superuser)
    if role:
        user.groups.add(Group.objects.get_or_create(name=role)[0])
    return user


class ApiTestCase(APITestCase):
    def login_as(self, user):
        token, _ = Token.objects.get_or_create(user=user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")

    def upload(self, **extra):
        return self.client.post("/api/uploads/", {"log": BRUTE, "year": 2026, **extra}, format="json")


class AuthTests(ApiTestCase):
    def test_everything_needs_a_token(self):
        for url in ["/api/alerts/", "/api/uploads/", "/api/stats/", "/api/audit/"]:
            self.assertEqual(self.client.get(url).status_code, 401, url)

    def test_login_returns_a_token_and_rejects_a_bad_password(self):
        make_user("ana", "analyst")
        ok = self.client.post("/api/auth/token/", {"username": "ana", "password": "correct-horse-battery-1"}, format="json")
        self.assertEqual(ok.status_code, 200)
        self.assertTrue(ok.data["token"])
        self.assertEqual(ok.data["user"], {"username": "ana", "role": "analyst"})
        bad = self.client.post("/api/auth/token/", {"username": "ana", "password": "nope"}, format="json")
        self.assertEqual(bad.status_code, 400)

    def test_login_is_rate_limited(self):
        from django.core.cache import cache
        from rest_framework.throttling import ScopedRateThrottle

        cache.clear()
        make_user("ana", "analyst")
        old = dict(ScopedRateThrottle.THROTTLE_RATES)
        ScopedRateThrottle.THROTTLE_RATES["login"] = "3/minute"
        try:
            codes = [self.client.post("/api/auth/token/", {"username": "ana", "password": "x"}, format="json").status_code for _ in range(5)]
        finally:
            ScopedRateThrottle.THROTTLE_RATES.clear()
            ScopedRateThrottle.THROTTLE_RATES.update(old)
            cache.clear()
        self.assertEqual(codes[:3], [400, 400, 400])
        self.assertEqual(codes[3:], [429, 429])


class UploadTests(ApiTestCase):
    def test_analyst_upload_creates_alerts_and_an_audit_entry(self):
        self.login_as(make_user("ana", "analyst"))
        response = self.upload()
        self.assertEqual(response.status_code, 201)
        self.assertEqual((response.data["events"], response.data["failed"], response.data["accepted"], response.data["alert_count"]), (6, 5, 1, 1))
        alert = Alert.objects.get()
        self.assertEqual((alert.severity, alert.kind, alert.ip, alert.failures, alert.status), ("critical", "success_after_failures", "203.0.113.45", 5, "new"))
        self.assertEqual(alert.users, ["admin", "oracle", "root", "test", "ubuntu"])
        self.assertEqual(AuditEntry.objects.get().action, "upload.create")

    def test_viewers_cannot_upload(self):
        self.login_as(make_user("vic", "viewer"))
        self.assertEqual(self.upload().status_code, 403)
        self.assertEqual(Alert.objects.count(), 0)

    def test_settings_change_what_is_flagged(self):
        self.login_as(make_user("ana", "analyst"))
        self.assertEqual(self.upload(threshold=50, spray_users=50).data["alert_count"], 0)
        self.assertEqual(self.upload(threshold=50).data["alert_count"], 1)  # still a slow spray: 5 different usernames

    def test_file_upload_works(self):
        from django.core.files.uploadedfile import SimpleUploadedFile

        self.login_as(make_user("ana", "analyst"))
        response = self.client.post("/api/uploads/", {"file": SimpleUploadedFile("auth.log", BRUTE.encode()), "year": 2026}, format="multipart")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["name"], "auth.log")

    def test_bad_requests_are_rejected(self):
        self.login_as(make_user("ana", "analyst"))
        self.assertEqual(self.client.post("/api/uploads/", {}, format="json").status_code, 400)
        self.assertEqual(self.client.post("/api/uploads/", {"log": "x", "threshold": 0}, format="json").status_code, 400)
        self.assertEqual(self.client.post("/api/uploads/", {"log": "x", "window": "abc"}, format="json").status_code, 400)

    @override_settings(MAX_LOG_BYTES=100)
    def test_oversized_logs_are_rejected(self):
        self.login_as(make_user("ana", "analyst"))
        self.assertEqual(self.upload().status_code, 400)

    def test_a_log_with_no_ssh_lines_gives_no_alerts(self):
        self.login_as(make_user("ana", "analyst"))
        response = self.client.post("/api/uploads/", {"log": "hello\nworld\n"}, format="json")
        self.assertEqual((response.status_code, response.data["events"], response.data["alert_count"]), (201, 0, 0))


class AlertTests(ApiTestCase):
    def setUp(self):
        self.analyst = make_user("ana", "analyst")
        self.viewer = make_user("vic", "viewer")
        self.login_as(self.analyst)
        self.upload()
        self.upload(threshold=3, spray_users=1)

    def test_filtering_and_ordering(self):
        self.assertEqual(self.client.get("/api/alerts/").data["count"], 2)
        self.assertEqual(self.client.get("/api/alerts/?severity=critical").data["count"], 2)
        self.assertEqual(self.client.get("/api/alerts/?severity=high").data["count"], 0)
        self.assertEqual(self.client.get("/api/alerts/?ip=203.0.113.45&status=new").data["count"], 2)
        self.assertEqual(self.client.get("/api/alerts/?ordering=severity").status_code, 200)
        self.assertEqual(self.client.get("/api/alerts/?ordering=__import__").status_code, 200)

    def test_analyst_can_change_status_and_it_is_audited(self):
        alert = Alert.objects.first()
        response = self.client.patch(f"/api/alerts/{alert.id}/", {"status": "investigating"}, format="json")
        self.assertEqual((response.status_code, response.data["status"]), (200, "investigating"))
        entry = AuditEntry.objects.filter(action="alert.status").get()
        self.assertEqual(entry.detail, {"old": "new", "new": "investigating"})
        self.assertEqual(entry.actor, self.analyst)

    def test_only_status_can_be_changed(self):
        alert = Alert.objects.first()
        before = (alert.severity, alert.ip, alert.detail)
        self.client.patch(f"/api/alerts/{alert.id}/", {"severity": "medium", "ip": "1.1.1.1", "detail": "x", "status": "resolved"}, format="json")
        alert.refresh_from_db()
        self.assertEqual((alert.severity, alert.ip, alert.detail), before)
        self.assertEqual(alert.status, "resolved")

    def test_invalid_status_is_rejected(self):
        alert = Alert.objects.first()
        self.assertEqual(self.client.patch(f"/api/alerts/{alert.id}/", {"status": "banana"}, format="json").status_code, 400)

    def test_viewer_can_read_but_not_change(self):
        self.login_as(self.viewer)
        alert = Alert.objects.first()
        self.assertEqual(self.client.get(f"/api/alerts/{alert.id}/").status_code, 200)
        self.assertEqual(self.client.patch(f"/api/alerts/{alert.id}/", {"status": "resolved"}, format="json").status_code, 403)

    def test_alerts_cannot_be_created_or_deleted_through_the_api(self):
        alert = Alert.objects.first()
        self.assertEqual(self.client.delete(f"/api/alerts/{alert.id}/").status_code, 405)
        self.assertEqual(self.client.post("/api/alerts/", {}, format="json").status_code, 405)

    def test_stats(self):
        data = self.client.get("/api/stats/").data
        self.assertEqual((data["alerts"], data["open"], data["uploads"]), (2, 2, 2))
        self.assertEqual(data["by_severity"], {"critical": 2})
        self.assertEqual(data["top_ips"], [{"ip": "203.0.113.45", "alerts": 2}])


class AuditTests(ApiTestCase):
    def test_only_admins_can_read_the_audit_log(self):
        self.login_as(make_user("ana", "analyst"))
        self.assertEqual(self.client.get("/api/audit/").status_code, 403)
        self.login_as(make_user("root1", superuser=True))
        self.assertEqual(self.client.get("/api/audit/").status_code, 200)


class SessionTests(ApiTestCase):
    def sign_in(self, name="ana"):
        response = self.client.post("/api/auth/token/", {"username": name, "password": "correct-horse-battery-1"}, format="json")
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {response.data['token']}")
        return response.data["token"]

    def test_me_reports_the_role(self):
        for name, role, admin in [("ana", "analyst", False), ("vic", "viewer", False), ("boss", None, True)]:
            make_user(name, role, superuser=admin)
        expected = {"ana": "analyst", "vic": "viewer", "boss": "admin"}
        for name, role in expected.items():
            self.sign_in(name)
            self.assertEqual(self.client.get("/api/me/").data, {"username": name, "role": role})

    def test_signing_in_again_replaces_the_old_token(self):
        make_user("ana", "analyst")
        first = self.sign_in()
        second = self.sign_in()
        self.assertNotEqual(first, second)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {first}")
        self.assertEqual(self.client.get("/api/me/").status_code, 401)

    def test_logout_revokes_the_token(self):
        make_user("ana", "analyst")
        token = self.sign_in()
        self.assertEqual(self.client.post("/api/auth/logout/").status_code, 204)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token}")
        self.assertEqual(self.client.get("/api/me/").status_code, 401)

    def test_expired_tokens_are_refused_and_deleted(self):
        from datetime import timedelta

        from django.utils import timezone

        make_user("ana", "analyst")
        token = self.sign_in()
        Token.objects.filter(key=token).update(created=timezone.now() - timedelta(hours=13))
        response = self.client.get("/api/me/")
        self.assertEqual(response.status_code, 401)
        self.assertIn("expired", str(response.data["detail"]))
        self.assertFalse(Token.objects.filter(key=token).exists())

    @override_settings(TOKEN_TTL_HOURS=1)
    def test_the_lifetime_is_configurable(self):
        from datetime import timedelta

        from django.utils import timezone

        make_user("ana", "analyst")
        token = self.sign_in()
        Token.objects.filter(key=token).update(created=timezone.now() - timedelta(hours=2))
        self.assertEqual(self.client.get("/api/me/").status_code, 401)
