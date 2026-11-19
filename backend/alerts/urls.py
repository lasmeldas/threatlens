from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register("uploads", views.UploadViewSet, basename="upload")
router.register("alerts", views.AlertViewSet, basename="alert")
router.register("audit", views.AuditViewSet, basename="audit")

urlpatterns = [
    path("auth/token/", views.LoginView.as_view(), name="login"),
    path("auth/logout/", views.LogoutView.as_view(), name="logout"),
    path("me/", views.MeView.as_view(), name="me"),
    path("connections/", views.ConnectionsView.as_view(), name="connections"),
    path("ml/model/", views.ModelView.as_view(), name="ml-model"),
    path("stats/", views.StatsView.as_view(), name="stats"),
    path("", include(router.urls)),
]
