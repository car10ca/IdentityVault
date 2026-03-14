"""
Identity retrieval endpoint for partner applications.

This endpoint allows registered applications to request identity
attributes associated with a granted consent.

Requirements:
- X-App-Key header for application authentication
- X-Consent-Token header for authorization of a specific consent

Security guarantees:
- Application authentication via API key
- Consent token verification and expiry enforcement
- Data minimisation through Application.allowed_fields
- Request throttling to protect the endpoint from abuse
"""
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from profiles.models import Consent, Application
from .throttles import ApplicationIdentityThrottle


class ApplicationIdentityView(APIView):
    """
    Identity endpoint accessed by external partner applications.

    The endpoint verifies the requesting application, validates the
    consent token, and returns profile attributes only when consent
    has been granted.
    """

    # Authentication handled manually via API key
    authentication_classes = []
    permission_classes = []

    # Dedicated throttle to protect the identity endpoint
    throttle_classes = [ApplicationIdentityThrottle]

    def get(self, request, application_id):

        # ================================
        # 1. Validate Application + API Key
        # ================================
        try:
            application = Application.objects.get(pk=application_id)
        except Application.DoesNotExist:
            return Response({"detail": "Application not found."}, status=status.HTTP_404_NOT_FOUND)

        raw_key = request.headers.get("X-App-Key") or request.headers.get("X-APP-KEY")
        if not raw_key or not application.check_api_key(raw_key):
            return Response({"detail": "Invalid or missing API key."}, status=status.HTTP_401_UNAUTHORIZED)

        # ================================
        # 2. Validate Consent Token
        # ================================
        raw_token = request.headers.get("X-Consent-Token")
        if not raw_token:
            return Response({"detail": "Consent not found."}, status=status.HTTP_404_NOT_FOUND)

        token_hash = Consent._hash_token(raw_token)

        consent = (
            Consent.objects
            .select_related("profile")
            .filter(application=application, consent_token_hash=token_hash)
            .first()
        )

        if not consent:
            return Response({"detail": "Consent not found."}, status=status.HTTP_404_NOT_FOUND)

        # ================================
        # 3. Enforce token expiry
        # ================================
        ttl = getattr(settings, "CONSENT_TOKEN_TTL_SECONDS", 86400)  # default 24h
        if consent.is_consent_token_expired(ttl_seconds=ttl):
            # Treat expired tokens as non-existent to avoid leaking token validity
            return Response({"detail": "Consent not found."}, status=status.HTTP_404_NOT_FOUND)

        # ================================
        # 4. Consent state handling
        # ================================
        if consent.status == Consent.Status.PENDING:
            return Response({"status": "pending"}, status=status.HTTP_202_ACCEPTED)

        if consent.status != Consent.Status.GRANTED:
            return Response({"status": consent.status}, status=status.HTTP_403_FORBIDDEN)

        # ================================
        # 5. Data minimisation
        # ================================
        profile = consent.profile

        full_payload = {
            "profile_name": profile.name,
            "first_name": profile.first_name,
            "last_name": profile.last_name,
            "email": profile.email,
            "birth_year": profile.birth_year,
            "city": profile.city,
        }

        allowed = application.allowed_fields or []
        if not allowed:
            # Backwards-compatible default: return all profile fields
            return Response(full_payload, status=status.HTTP_200_OK)

        scoped_payload = {k: v for k, v in full_payload.items() if k in set(allowed)}
        return Response(scoped_payload, status=status.HTTP_200_OK)