from collections import Counter
from datetime import timezone as dt_timezone

from django.db import transaction
from django.db.models import Count
from django.utils import timezone
from rest_framework import mixins, status, viewsets
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from detection import detect, parse_lines

from .models import Alert, AuditEntry, Upload
from .permissions import IsAdmin, is_analyst
from . import scoring
from .serializers import AlertSerializer, AuditEntrySerializer, ConnectionsRequestSerializer, UploadRequestSerializer, UploadSerializer


def audit(actor, action, target, **detail):
    AuditEntry.objects.create(actor=actor, action=action, target_type=target.__class__.__name__.lower(), target_id=target.pk, detail=detail)


class LoginView(ObtainAuthToken):
    """POST username and password, get a token. Rate limited to slow down password guessing."""

    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]  # ObtainAuthToken switches throttling off by default
    throttle_scope = "login"

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        Token.objects.filter(user=user).delete()  # every sign-in gets a fresh token with a fresh expiry
        token = Token.objects.create(user=user)
        return Response({"token": token.key, "user": describe_user(user)})


def describe_user(user):
    role = "admin" if user.is_superuser else "analyst" if is_analyst(user) else "viewer"
    return {"username": user.get_username(), "role": role}


class LogoutView(APIView):
    """Throw away the caller's token."""

    def post(self, request):
        Token.objects.filter(user=request.user).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class MeView(APIView):
    def get(self, request):
        return Response(describe_user(request.user))


class UploadViewSet(mixins.CreateModelMixin, mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    queryset = Upload.objects.all()
    serializer_class = UploadSerializer
    parser_classes = [JSONParser, MultiPartParser, FormParser]
    throttle_scope = "upload"

    def get_throttles(self):
        # Only creating an upload is expensive, so only that is limited.
        return super().get_throttles() if self.action == "create" else []

    def create(self, request, *args, **kwargs):
        form = UploadRequestSerializer(data=request.data)
        form.is_valid(raise_exception=True)
        data = form.validated_data
        year = data.get("year") or timezone.now().year
        events = list(parse_lines(data["text"].splitlines(True), year))
        found = detect(events, threshold=data["threshold"], window=data["window"], spray_users=data["spray_users"])
        failed = sum(1 for e in events if e.kind == "failed")
        utc = dt_timezone.utc
        with transaction.atomic():
            upload = Upload.objects.create(
                name=data["name"], uploaded_by=request.user, year=year, threshold=data["threshold"], window=data["window"],
                spray_users=data["spray_users"], events=len(events), failed=failed, accepted=len(events) - failed,
            )
            Alert.objects.bulk_create(
                Alert(
                    upload=upload, severity=a.severity, kind=a.kind, ip=a.ip, failures=a.failures, users=a.users,
                    first_seen=a.first_seen.replace(tzinfo=utc), last_seen=a.last_seen.replace(tzinfo=utc), detail=a.detail,
                )
                for a in found
            )
            audit(request.user, "upload.create", upload, events=len(events), alerts=len(found))
        return Response(UploadSerializer(upload).data, status=status.HTTP_201_CREATED)


class ConnectionsView(APIView):
    """Score network connection records (NSL-KDD format) with the attack model and raise alerts for likely attacks."""

    parser_classes = [JSONParser, MultiPartParser, FormParser]
    throttle_scope = "upload"

    def get_throttles(self):
        return super().get_throttles() if self.request.method == "POST" else []

    def post(self, request):
        form = ConnectionsRequestSerializer(data=request.data)
        form.is_valid(raise_exception=True)
        data = form.validated_data
        try:
            frame, labels = scoring.parse_records(data["text"])
            probabilities = scoring.score(frame)
        except scoring.RecordError as error:
            raise ValidationError({"detail": str(error)}) from None
        except FileNotFoundError:
            return Response({"detail": "The attack model is not installed on this server."}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        flagged = [i for i, p in enumerate(probabilities) if p >= data["threshold"]]
        flagged.sort(key=lambda i: (-probabilities[i], i))
        shown = flagged[: data["max_alerts"]]
        now = timezone.now()
        with transaction.atomic():
            upload = Upload.objects.create(
                name=data["name"], kind="connections", uploaded_by=request.user, year=now.year, threshold=1, window=1, spray_users=1,
                events=len(frame),
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
            audit(request.user, "connections.score", upload, records=len(frame), flagged=len(flagged), alerts=len(shown))
        result = {
            "upload": UploadSerializer(upload).data, "records": len(frame), "flagged": len(flagged), "alerts_created": len(shown),
            "threshold": data["threshold"],
        }
        if labels is not None:
            actual = (labels != "normal").to_numpy()
            predicted = probabilities >= data["threshold"]
            result["against_labels"] = {"records": len(frame), "agreed": int((actual == predicted).sum()), "attacks_missed": int((actual & ~predicted).sum()), "false_alarms": int((~actual & predicted).sum())}
        return Response(result, status=status.HTTP_201_CREATED)


class ModelView(APIView):
    """What the model was trained on and how it scored, for the dashboard's Model page."""

    def get(self, request):
        try:
            return Response(scoring.model_summary())
        except (FileNotFoundError, KeyError):
            return Response({"detail": "The attack model is not installed on this server."}, status=status.HTTP_503_SERVICE_UNAVAILABLE)


class AlertViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """List and read alerts. The only thing that can be changed is an alert's status."""

    serializer_class = AlertSerializer
    http_method_names = ["get", "patch", "head", "options"]
    ORDERINGS = {"newest": ("-created_at", "-id"), "severity": ("severity_rank", "-failures", "ip"), "failures": ("-failures", "ip")}

    def get_queryset(self):
        from django.db.models import Case, IntegerField, Value, When

        qs = Alert.objects.all()
        params = self.request.query_params
        for field in ("severity", "status", "kind", "source", "ip", "upload"):
            if params.get(field):
                qs = qs.filter(**{field: params[field]})
        order = self.ORDERINGS.get(params.get("ordering", "newest"), self.ORDERINGS["newest"])
        if "severity_rank" in order:
            qs = qs.annotate(severity_rank=Case(When(severity="critical", then=Value(0)), When(severity="high", then=Value(1)), default=Value(2), output_field=IntegerField()))
        return qs.order_by(*order)

    def perform_update(self, serializer):
        before = serializer.instance.status
        alert = serializer.save()
        if alert.status != before:
            audit(self.request.user, "alert.status", alert, old=before, new=alert.status)


class StatsView(APIView):
    def get(self, request):
        alerts = Alert.objects.all()
        by = lambda field: dict(alerts.values_list(field).annotate(n=Count("id")).order_by())
        top_ips = Counter({row["ip"]: row["total"] for row in alerts.exclude(ip="").values("ip").annotate(total=Count("id")).order_by("-total", "ip")[:5]})
        return Response(
            {
                "alerts": alerts.count(),
                "open": alerts.filter(status__in=["new", "investigating"]).count(),
                "by_severity": by("severity"),
                "by_status": by("status"),
                "by_kind": by("kind"),
                "by_source": by("source"),
                "top_ips": [{"ip": ip, "alerts": n} for ip, n in top_ips.most_common()],
                "uploads": Upload.objects.count(),
            }
        )


class AuditViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    queryset = AuditEntry.objects.all()
    serializer_class = AuditEntrySerializer
    permission_classes = [IsAdmin]
