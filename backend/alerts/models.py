from django.conf import settings
from django.db import models


class Upload(models.Model):
    """One log that an analyst submitted, with the settings used to analyse it."""

    name = models.CharField(max_length=200)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="uploads")
    created_at = models.DateTimeField(auto_now_add=True)
    year = models.PositiveSmallIntegerField()
    threshold = models.PositiveIntegerField()
    window = models.PositiveIntegerField()
    spray_users = models.PositiveIntegerField()
    events = models.PositiveIntegerField(default=0)
    failed = models.PositiveIntegerField(default=0)
    accepted = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["-created_at", "-id"]

    def __str__(self):
        return f"{self.name} ({self.created_at:%Y-%m-%d})"


class Alert(models.Model):
    SEVERITIES = [("critical", "Critical"), ("high", "High"), ("medium", "Medium")]
    STATUSES = [("new", "New"), ("investigating", "Investigating"), ("resolved", "Resolved"), ("false_positive", "False positive")]

    upload = models.ForeignKey(Upload, on_delete=models.CASCADE, related_name="alerts")
    severity = models.CharField(max_length=10, choices=SEVERITIES)
    kind = models.CharField(max_length=40)
    ip = models.CharField(max_length=45)
    failures = models.PositiveIntegerField()
    users = models.JSONField(default=list)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    detail = models.TextField()
    status = models.CharField(max_length=20, choices=STATUSES, default="new")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [models.Index(fields=["severity", "status"]), models.Index(fields=["ip"])]

    def __str__(self):
        return f"{self.severity} {self.kind} from {self.ip}"


class AuditEntry(models.Model):
    """Who did what, and when. Written for uploads and every alert status change."""

    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    action = models.CharField(max_length=40)
    target_type = models.CharField(max_length=40)
    target_id = models.PositiveIntegerField()
    detail = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        verbose_name_plural = "audit entries"
