from django.contrib import admin
from django.urls import include, path, re_path

from . import spa

urlpatterns = [
    path("healthz", spa.healthz),
    path("admin/", admin.site.urls),
    path("api/", include("alerts.urls")),
    # Everything else is the React app. Keep this last.
    re_path(r"^(?!api/|admin/|static/)(?P<path>.*)$", spa.spa),
]
