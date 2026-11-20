"""The work behind the two upload endpoints, shared by the API views and the seed_demo command."""

from datetime import timezone as dt_timezone

from django.db import transaction
from django.utils import timezone

from detection import detect, parse_lines

from . import scoring
from .models import Alert, AuditEntry, Upload


def audit(actor, action, target, **detail):
    AuditEntry.objects.create(actor=actor, action=action, target_type=target.__class__.__name__.lower(), target_id=target.pk, detail=detail)


def analyze_ssh_log(user, *, name, text, year=None, threshold=5, window=300, spray_users=5):
    """Runs the SSH rules over a log, stores the upload and its alerts, and returns the upload."""
    year = year or timezone.now().year
    events = list(parse_lines(text.splitlines(True), year))
    found = detect(events, threshold=threshold, window=window, spray_users=spray_users)
    failed = sum(1 for e in events if e.kind == "failed")
    utc = dt_timezone.utc
    with transaction.atomic():
        upload = Upload.objects.create(
            name=name, uploaded_by=user, year=year, threshold=threshold, window=window, spray_users=spray_users,
            events=len(events), failed=failed, accepted=len(events) - failed,
        )
        Alert.objects.bulk_create(
            Alert(
                upload=upload, severity=a.severity, kind=a.kind, ip=a.ip, failures=a.failures, users=a.users,
                first_seen=a.first_seen.replace(tzinfo=utc), last_seen=a.last_seen.replace(tzinfo=utc), detail=a.detail,
            )
            for a in found
        )
        audit(user, "upload.create", upload, events=len(events), alerts=len(found))
    return upload


def analyze_connections(user, *, name, text, threshold=0.5, max_alerts=50):
    """Scores connection records with the ML model. Raises scoring.RecordError for bad data and FileNotFoundError if the model is missing."""
    frame, labels = scoring.parse_records(text)
    probabilities = scoring.score(frame)
    flagged = [i for i, p in enumerate(probabilities) if p >= threshold]
    flagged.sort(key=lambda i: (-probabilities[i], i))
    shown = flagged[:max_alerts]
    now = timezone.now()
    with transaction.atomic():
        upload = Upload.objects.create(
            name=name, kind="connections", uploaded_by=user, year=now.year, threshold=1, window=1, spray_users=1, events=len(frame),
        )
        Alert.objects.bulk_create(
            Alert(
                upload=upload, source="ml", kind="network_attack", severity="high" if probabilities[i] >= 0.9 else "medium",
                score=round(float(probabilities[i]), 4), first_seen=now, last_seen=now,
                detail=(
                    f"Record {i + 1}: the model gives a {probabilities[i]:.0%} chance this is an attack "
                    f"({frame['protocol_type'].iloc[i]}, service {frame['service'].iloc[i]}, flag {frame['flag'].iloc[i]}). "
                    "Connection records carry no IP address, so match it to your own logs by row number."
                ),
            )
            for i in shown
        )
        audit(user, "connections.score", upload, records=len(frame), flagged=len(flagged), alerts=len(shown))
    result = {"upload": upload, "records": len(frame), "flagged": len(flagged), "alerts_created": len(shown), "threshold": threshold}
    if labels is not None:
        actual = (labels != "normal").to_numpy()
        predicted = probabilities >= threshold
        result["against_labels"] = {"records": len(frame), "agreed": int((actual == predicted).sum()), "attacks_missed": int((actual & ~predicted).sum()), "false_alarms": int((~actual & predicted).sum())}
    return result
