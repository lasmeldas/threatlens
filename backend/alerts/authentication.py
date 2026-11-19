from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed


class ExpiringTokenAuthentication(TokenAuthentication):
    """Token authentication where a token is only good for TOKEN_TTL_HOURS after it was issued."""

    def authenticate_credentials(self, key):
        user, token = super().authenticate_credentials(key)
        if token.created < timezone.now() - timedelta(hours=settings.TOKEN_TTL_HOURS):
            token.delete()
            raise AuthenticationFailed("This token has expired. Sign in again.")
        return user, token
