from rest_framework.permissions import SAFE_METHODS, BasePermission

ANALYST_GROUP = "analyst"
VIEWER_GROUP = "viewer"


def is_analyst(user) -> bool:
    return bool(user and user.is_authenticated and (user.is_superuser or user.groups.filter(name=ANALYST_GROUP).exists()))


class IsAnalystOrReadOnly(BasePermission):
    """Any signed-in user can read. Only analysts (and admins) can upload or change alerts."""

    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        return request.method in SAFE_METHODS or is_analyst(request.user)


class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.is_superuser)
