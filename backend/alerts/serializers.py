from django.conf import settings
from rest_framework import serializers

from .models import Alert, AuditEntry, Upload


class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = ["id", "upload", "severity", "kind", "source", "score", "ip", "failures", "users", "first_seen", "last_seen", "detail", "status", "created_at", "updated_at"]
        read_only_fields = [f for f in fields if f != "status"]


class UploadSerializer(serializers.ModelSerializer):
    alert_count = serializers.IntegerField(source="alerts.count", read_only=True)

    class Meta:
        model = Upload
        fields = ["id", "name", "kind", "created_at", "year", "threshold", "window", "spray_users", "events", "failed", "accepted", "alert_count"]
        read_only_fields = fields


class UploadRequestSerializer(serializers.Serializer):
    """What a client sends to /api/uploads/. The log comes either as text or as a file."""

    name = serializers.CharField(max_length=200, required=False, allow_blank=True)
    log = serializers.CharField(required=False, allow_blank=False, trim_whitespace=False)
    file = serializers.FileField(required=False)
    year = serializers.IntegerField(required=False, min_value=1970, max_value=2100)
    threshold = serializers.IntegerField(required=False, min_value=1, max_value=10000, default=5)
    window = serializers.IntegerField(required=False, min_value=1, max_value=86400, default=300)
    spray_users = serializers.IntegerField(required=False, min_value=1, max_value=10000, default=5)

    def validate(self, attrs):
        if bool(attrs.get("log")) == bool(attrs.get("file")):
            raise serializers.ValidationError("Send exactly one of 'log' (text) or 'file'.")
        limit = settings.MAX_LOG_BYTES
        if "file" in attrs:
            if attrs["file"].size > limit:
                raise serializers.ValidationError(f"The log is larger than {limit} bytes.")
            raw = attrs["file"].read()
        else:
            raw = attrs["log"].encode("utf-8")
            if len(raw) > limit:
                raise serializers.ValidationError(f"The log is larger than {limit} bytes.")
        attrs["text"] = raw.decode("utf-8", errors="replace")
        if "name" not in attrs or not attrs["name"]:
            attrs["name"] = attrs["file"].name[:200] if "file" in attrs else "pasted log"
        return attrs


class AuditEntrySerializer(serializers.ModelSerializer):
    actor = serializers.StringRelatedField()

    class Meta:
        model = AuditEntry
        fields = ["id", "actor", "action", "target_type", "target_id", "detail", "created_at"]


class ConnectionsRequestSerializer(serializers.Serializer):
    """What a client sends to /api/connections/: NSL-KDD style records as CSV text or a file."""

    name = serializers.CharField(max_length=200, required=False, allow_blank=True)
    csv = serializers.CharField(required=False, allow_blank=False, trim_whitespace=False)
    file = serializers.FileField(required=False)
    threshold = serializers.FloatField(required=False, min_value=0.0, max_value=1.0, default=0.5)
    max_alerts = serializers.IntegerField(required=False, min_value=1, max_value=500, default=50)

    def validate(self, attrs):
        if bool(attrs.get("csv")) == bool(attrs.get("file")):
            raise serializers.ValidationError("Send exactly one of 'csv' (text) or 'file'.")
        limit = settings.MAX_LOG_BYTES
        raw = attrs["file"].read() if "file" in attrs else attrs["csv"].encode("utf-8")
        if len(raw) > limit:
            raise serializers.ValidationError(f"The data is larger than {limit} bytes.")
        attrs["text"] = raw.decode("utf-8", errors="replace")
        if not attrs.get("name"):
            attrs["name"] = attrs["file"].name[:200] if "file" in attrs else "pasted connections"
        return attrs
