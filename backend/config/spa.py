"""Serves the React single-page app and a health check."""

from django.conf import settings
from django.http import FileResponse, Http404, HttpResponse


def healthz(request):
    return HttpResponse("ok", content_type="text/plain")


def spa(request, path=""):
    """Any non-API path returns index.html so client-side routes such as /alerts/3 survive a refresh."""
    index = settings.FRONTEND_DIST / "index.html"
    if not index.is_file():
        raise Http404("The dashboard has not been built. Run npm run build in frontend/.")
    response = FileResponse(open(index, "rb"), content_type="text/html; charset=utf-8")
    response.headers["Cache-Control"] = "no-cache"
    return response
