import sys
from pathlib import Path

from django.test import SimpleTestCase, override_settings
from rest_framework.test import APITestCase

from alerts import scoring
from alerts.models import Alert, AuditEntry, Upload

from .test_api import ApiTestCase, make_user

REPO = Path(__file__).resolve().parents[2]
SAMPLE = (REPO / "ml" / "sample" / "connections_sample.csv").read_text()
FIRST_ROW = SAMPLE.splitlines()[0]


class FeatureListTests(SimpleTestCase):
    def test_backend_and_training_code_use_the_same_41_features_in_the_same_order(self):
        sys.path.insert(0, str(REPO / "ml"))
        try:
            import nslkdd
        finally:
            sys.path.remove(str(REPO / "ml"))
        self.assertEqual(scoring.FEATURES, nslkdd.FEATURES)
        self.assertEqual(scoring.CATEGORICAL, nslkdd.CATEGORICAL)


class ParseRecordsTests(SimpleTestCase):
    def test_accepts_41_or_43_columns(self):
        frame, labels = scoring.parse_records(SAMPLE)
        self.assertEqual((len(frame), frame.shape[1]), (60, 41))
        self.assertEqual(int((labels != "normal").sum()), 30)
        no_labels = ",".join(FIRST_ROW.split(",")[:41])
        frame, labels = scoring.parse_records(no_labels)
        self.assertEqual(len(frame), 1)
        self.assertIsNone(labels)

    def test_rejects_the_wrong_number_of_columns(self):
        with self.assertRaisesRegex(scoring.RecordError, "41 values.*found 5"):
            scoring.parse_records("1,2,3,4,5")

    def test_names_the_record_and_column_that_is_not_a_number(self):
        row = FIRST_ROW.split(",")
        row[4] = "lots"  # src_bytes
        with self.assertRaisesRegex(scoring.RecordError, r"Record 1: 'src_bytes' must be a number, got 'lots'"):
            scoring.parse_records(",".join(row))

    def test_rejects_empty_input_and_blank_categories(self):
        with self.assertRaises(scoring.RecordError):
            scoring.parse_records("\n\n")
        row = FIRST_ROW.split(",")
        row[2] = ""
        with self.assertRaisesRegex(scoring.RecordError, "service"):
            scoring.parse_records(",".join(row))

    @override_settings(MAX_CONNECTION_RECORDS=10)
    def test_enforces_the_record_limit(self):
        with self.assertRaisesRegex(scoring.RecordError, "Too many records"):
            scoring.parse_records(SAMPLE)


class ConnectionsApiTests(ApiTestCase):
    def setUp(self):
        self.login_as(make_user("ana", "analyst"))

    def post(self, **data):
        return self.client.post("/api/connections/", data, format="json")

    def test_scores_the_sample_and_raises_ml_alerts(self):
        response = self.post(csv=SAMPLE)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual((response.data["records"], response.data["flagged"], response.data["alerts_created"]), (60, 14, 14))
        self.assertEqual(response.data["against_labels"], {"records": 60, "agreed": 44, "attacks_missed": 16, "false_alarms": 0})
        upload = Upload.objects.get()
        self.assertEqual((upload.kind, upload.events), ("connections", 60))
        alerts = Alert.objects.all()
        self.assertEqual(alerts.count(), 14)
        first = alerts.order_by("-score").first()
        self.assertEqual((first.source, first.kind, first.ip, first.users), ("ml", "network_attack", "", []))
        self.assertTrue(0.5 <= first.score <= 1)
        self.assertEqual((alerts.filter(severity="high").count(), alerts.filter(severity="medium").count()), (13, 1))  # high at 90%+
        self.assertIn("by row number", first.detail)
        self.assertEqual(AuditEntry.objects.get().action, "connections.score")

    def test_a_higher_threshold_flags_fewer_and_the_cap_limits_alerts(self):
        self.assertEqual(self.post(csv=SAMPLE, threshold=1.0).data["flagged"], 0)
        capped = self.post(csv=SAMPLE, max_alerts=3).data
        self.assertEqual((capped["flagged"], capped["alerts_created"]), (14, 3))
        self.assertEqual(Alert.objects.filter(upload=capped["upload"]["id"]).count(), 3)

    def test_the_most_likely_attacks_are_kept_when_capped(self):
        self.post(csv=SAMPLE, max_alerts=3)
        scores = sorted(Alert.objects.values_list("score", flat=True))
        self.assertEqual(len(scores), 3)
        self.assertGreaterEqual(min(scores), 0.99)

    def test_without_label_columns_there_is_no_comparison(self):
        rows = "\n".join(",".join(line.split(",")[:41]) for line in SAMPLE.splitlines())
        self.assertNotIn("against_labels", self.post(csv=rows).data)

    def test_file_upload_works(self):
        from django.core.files.uploadedfile import SimpleUploadedFile

        response = self.client.post("/api/connections/", {"file": SimpleUploadedFile("conns.csv", SAMPLE.encode())}, format="multipart")
        self.assertEqual((response.status_code, response.data["records"]), (201, 60))

    def test_bad_input_gives_a_clear_400(self):
        for data in ({}, {"csv": "1,2,3"}, {"csv": SAMPLE, "threshold": 2}, {"csv": SAMPLE, "max_alerts": 0}):
            self.assertEqual(self.post(**data).status_code, 400, data)
        self.assertIn("41 values", str(self.post(csv="1,2,3").data))
        self.assertEqual(Alert.objects.count(), 0)

    @override_settings(MAX_LOG_BYTES=100)
    def test_oversized_uploads_are_rejected(self):
        self.assertEqual(self.post(csv=SAMPLE).status_code, 400)

    def test_viewers_cannot_score_records(self):
        self.login_as(make_user("vic", "viewer"))
        self.assertEqual(self.post(csv=SAMPLE).status_code, 403)

    def test_anonymous_requests_are_refused(self):
        self.client.credentials()
        self.assertEqual(self.post(csv=SAMPLE).status_code, 401)

    @override_settings(ML_MODEL_DIR=REPO / "does-not-exist")
    def test_a_missing_model_is_a_503_not_a_crash(self):
        scoring.load_model.cache_clear()
        try:
            self.assertEqual(self.post(csv=SAMPLE).status_code, 503)
        finally:
            scoring.load_model.cache_clear()

    def test_ml_alerts_can_be_filtered_and_do_not_pollute_the_top_addresses(self):
        self.post(csv=SAMPLE)
        self.assertEqual(self.client.get("/api/alerts/?source=ml").data["count"], 14)
        self.assertEqual(self.client.get("/api/alerts/?source=rules").data["count"], 0)
        stats = self.client.get("/api/stats/").data
        self.assertEqual((stats["by_source"], stats["top_ips"]), ({"ml": 14}, []))
        self.assertEqual(stats["by_kind"], {"network_attack": 14})

    def test_ml_alert_status_can_be_changed_like_any_other(self):
        self.post(csv=SAMPLE)
        alert = Alert.objects.first()
        response = self.client.patch(f"/api/alerts/{alert.id}/", {"status": "false_positive"}, format="json")
        self.assertEqual(response.data["status"], "false_positive")


class ModelEndpointTests(ApiTestCase):
    def test_reports_the_evaluation_and_needs_a_login(self):
        self.assertEqual(self.client.get("/api/ml/model/").status_code, 401)
        self.login_as(make_user("vic", "viewer"))
        data = self.client.get("/api/ml/model/").data
        self.assertEqual(data["selected_model"], "gradient_boosting")
        self.assertEqual((data["train_records"], data["test_records"]), (125973, 22544))
        self.assertEqual(data["test"]["accuracy"], 0.8032)
        self.assertEqual(set(data["by_category"]), {"normal", "DoS", "Probe", "R2L", "U2R"})
        self.assertEqual(set(data["compared_on_test"]), {"logistic_regression", "random_forest", "gradient_boosting"})
        self.assertEqual(data["unseen_attacks"]["detected_unseen"], 0.4061)
