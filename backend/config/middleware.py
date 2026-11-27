"""Security headers for the single-service deployment, matching the policy in frontend/nginx.conf."""

CSP = (
    "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)


class SecurityHeadersMiddleware:
    """Adds the dashboard's Content-Security-Policy and Referrer-Policy. The Django admin keeps its own inline scripts, so it is skipped."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if not request.path.startswith("/admin/"):
            response.headers.setdefault("Content-Security-Policy", CSP)
        return response


def revalidate_index(headers, path, url):
    """The built asset files have hashed names and can be cached; index.html must be re-checked so a new deploy shows up at once."""
    if path.endswith("index.html"):
        headers["Cache-Control"] = "no-cache"
