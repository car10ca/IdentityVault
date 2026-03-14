"""
JWT authentication views with basic rate limiting.

These views extend the default SimpleJWT authentication endpoints
by applying request throttling to reduce the risk of brute-force
login attempts.
"""
from rest_framework.throttling import AnonRateThrottle
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView


class LoginThrottle(AnonRateThrottle):
    """
    Rate limit for authentication endpoints.

    Limits anonymous login attempts to reduce brute-force attacks.
    """
    rate = "5/min"


class SecureTokenObtainPairView(TokenObtainPairView):
    """
    JWT login endpoint with throttling applied.
    """
    throttle_classes = [LoginThrottle]


class SecureTokenRefreshView(TokenRefreshView):
    """
    JWT token refresh endpoint with throttling applied.
    """
    throttle_classes = [LoginThrottle]
