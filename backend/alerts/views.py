from collections import Counter
from datetime import timezone as dt_timezone

from django.db import transaction
from django.db.models import Count
from django.utils import timezone
from rest_framework import mixins, status, viewsets
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from detection import detect, parse_lines

from .models import Alert, AuditEntry, Upload
from .permissions import IsAdmin
from .serializers import AlertSerializer, AuditEntrySerializer, UploadRequestSerializer, UploadSerializer


def audit(actor, action, target, **detail):
    AuditEntry.objects.create(actor=actor, action=action, target_type=target.__class__.__name__.lower(), target_id=target.pk, detail=detail)


class LoginView(ObtainAuthToken):
    """POST username and password, get a token. Rate limited to slow down password guessing."""

    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]  # ObtainAuthToken switches throttling off by default
    throttle_scope = "login"


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


class AlertViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """List and read alerts. The only thing that can be changed is an alert's status."""

    serializer_class = AlertSerializer
    http_method_names = ["get", "patch", "head", "options"]
    ORDERINGS = {"newest": ("-created_at", "-id"), "severity": ("severity_rank", "-failures", "ip"), "failures": ("-failures", "ip")}

    def get_queryset(self):
        from django.db.models import Case, IntegerField, Value, When

        qs = Alert.objects.all()
        params = self.request.query_params
        for field in ("severity", "status", "kind", "ip", "upload"):
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
        top_ips = Counter({row["ip"]: row["total"] for row in alerts.values("ip").annotate(total=Count("id")).order_by("-total", "ip")[:5]})
        return Response(
            {
                "alerts": alerts.count(),
                "open": alerts.filter(status__in=["new", "investigating"]).count(),
                "by_severity": by("severity"),
                "by_status": by("status"),
                "by_kind": by("kind"),
                "top_ips": [{"ip": ip, "alerts": n} for ip, n in top_ips.most_common()],
                "uploads": Upload.objects.count(),
            }
        )


class AuditViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    queryset = AuditEntry.objects.all()
    serializer_class = AuditEntrySerializer
    permission_classes = [IsAdmin]
