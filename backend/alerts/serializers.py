from django.conf import settings
from rest_framework import serializers

from .models import Alert, AuditEntry, Upload


class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = ["id", "upload", "severity", "kind", "ip", "failures", "users", "first_seen", "last_seen", "detail", "status", "created_at", "updated_at"]
        read_only_fields = [f for f in fields if f != "status"]


class UploadSerializer(serializers.ModelSerializer):
    alert_count = serializers.IntegerField(source="alerts.count", read_only=True)

    class Meta:
        model = Upload
        fields = ["id", "name", "created_at", "year", "threshold", "window", "spray_users", "events", "failed", "accepted", "alert_count"]
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
