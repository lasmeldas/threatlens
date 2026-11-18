from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register("uploads", views.UploadViewSet, basename="upload")
router.register("alerts", views.AlertViewSet, basename="alert")
router.register("audit", views.AuditViewSet, basename="audit")

urlpatterns = [
    path("auth/token/", views.LoginView.as_view(), name="login"),
    path("stats/", views.StatsView.as_view(), name="stats"),
    path("", include(router.urls)),
]
