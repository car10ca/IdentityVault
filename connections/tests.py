"""
Security and behaviour tests for the connections application.

These tests verify critical aspects of the identity sharing system,
including ownership isolation, consent lifecycle enforcement,
token security, API authentication, and data minimisation.
"""

from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status
from django.utils import timezone
from datetime import timedelta

from profiles.models import Profile, Application, Consent


class ConnectionSecurityTests(TestCase):
    """
    Security-focused tests for the connections subsystem.

    Covered areas:
    - Ownership isolation
    - Consent finite-state-machine enforcement
    - Token rotation and invalidation
    - API key authentication
    - Field-level data minimisation
    """

    def setUp(self):
        """
        Create two users, a profile, an application, and
        a granted consent used across tests.
        """
        self.user_a = User.objects.create_user(
            username="user_a",
            password="StrongPassw0rd!!"
        )
        self.user_b = User.objects.create_user(
            username="user_b",
            password="StrongPassw0rd!!"
        )

        self.profile = Profile.objects.create(
            owner=self.user_a,
            name="A profile",
            first_name="Alice",
            last_name="Example",
            email="alice@example.com",
            city="Berlin",
            birth_year=1990,
        )

        self.application = Application.objects.create(
            name="Test Application",
            slug="test-application"
        )

        # Generate API key for identity endpoint testing
        self.api_key = self.application.generate_api_key()

        self.consent = Consent.objects.create(
            profile=self.profile,
            application=self.application,
            status=Consent.Status.GRANTED
        )


    def test_revoked_token_cannot_access_identity(self):
        """
        Ensure a token becomes unusable after consent is revoked.
        This prevents replay attacks using previously valid tokens.
        """
        raw_token = self.consent.generate_consent_token()

        # Revoke consent
        self.consent.status = Consent.Status.REVOKED
        self.consent.save()

        client = APIClient()

        response = client.get(
            f"/api/applications/{self.application.id}/identity/",
            HTTP_X_APP_KEY=self.api_key,
            HTTP_X_CONSENT_TOKEN=raw_token,
        )

        self.assertEqual(response.status_code, 403)

    # ------------------------------------------------------
    # JWT Helper
    # ------------------------------------------------------
    def get_auth_client(self, username, password):
        client = APIClient()
        response = client.post(
            "/api/token/",
            {"username": username, "password": password},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        access = response.data["access"]
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        return client

    # ------------------------------------------------------
    # Ownership Isolation
    # ------------------------------------------------------
    def test_user_cannot_list_other_users_connections(self):
        client_b = self.get_auth_client("user_b", "StrongPassw0rd!!")
        response = client_b.get("/api/connections/")
        self.assertEqual(response.status_code, 200)
        returned_ids = [c["id"] for c in response.data]
        self.assertNotIn(self.consent.id, returned_ids)

    def test_user_cannot_revoke_other_users_connection(self):
        client_b = self.get_auth_client("user_b", "StrongPassw0rd!!")
        response = client_b.post(
            f"/api/connections/{self.consent.id}/revoke/"
        )
        self.assertIn(
            response.status_code,
            [status.HTTP_404_NOT_FOUND, status.HTTP_403_FORBIDDEN]
        )

    # ------------------------------------------------------
    # FSM Enforcement
    # ------------------------------------------------------
    def test_illegal_state_transition_is_blocked(self):
        """
        Attempt to revoke from PENDING state.
        Should return 409 conflict.
        """
        self.consent.status = Consent.Status.PENDING
        self.consent.save()

        client = self.get_auth_client("user_a", "StrongPassw0rd!!")

        response = client.post(
            f"/api/connections/{self.consent.id}/revoke/"
        )

        self.assertEqual(response.status_code, 409)

    # ------------------------------------------------------
    # Consent Token Security
    # ------------------------------------------------------
    def test_token_invalid_after_revoke(self):
        """
        A consent token must become invalid immediately
        after revoke.
        """
        raw_token = self.consent.generate_consent_token()

        # Revoke consent
        self.consent.status = Consent.Status.REVOKED
        self.consent.consent_token_hash = ""
        self.consent.save()

        client = APIClient()

        response = client.get(
            f"/api/applications/{self.application.id}/identity/",
            HTTP_X_APP_KEY=self.api_key,
            HTTP_X_CONSENT_TOKEN=raw_token,
        )

        self.assertEqual(response.status_code, 404)

    def test_token_expires(self):
        """
        Expired tokens must not return identity.
        Expiry is calculated based on consent_token_created_at + TTL.
        """

        raw_token = self.consent.generate_consent_token()

        # Force token creation timestamp into the past (beyond TTL)
        self.consent.consent_token_created_at = timezone.now() - timedelta(days=2)
        self.consent.save()

        client = APIClient()

        response = client.get(
            f"/api/applications/{self.application.id}/identity/",
            HTTP_X_APP_KEY=self.api_key,
            HTTP_X_CONSENT_TOKEN=raw_token,
        )

        self.assertEqual(response.status_code, 404)

    # ------------------------------------------------------
    # Field-Level Data Minimisation
    # ------------------------------------------------------
    def test_allowed_fields_restrict_response(self):
        """
        Application.allowed_fields must restrict identity output.
        """
        self.application.allowed_fields = ["first_name", "email"]
        self.application.save()

        raw_token = self.consent.generate_consent_token()

        client = APIClient()

        response = client.get(
            f"/api/applications/{self.application.id}/identity/",
            HTTP_X_APP_KEY=self.api_key,
            HTTP_X_CONSENT_TOKEN=raw_token,
        )

        self.assertEqual(response.status_code, 200)

        self.assertEqual(
            set(response.data.keys()),
            {"first_name", "email"}
        )

    # ------------------------------------------------------
    # API Key Enforcement
    # ------------------------------------------------------
    def test_identity_requires_valid_api_key(self):
        """
        Identity endpoint must reject invalid API key.
        """
        raw_token = self.consent.generate_consent_token()

        client = APIClient()

        response = client.get(
            f"/api/applications/{self.application.id}/identity/",
            HTTP_X_APP_KEY="invalid",
            HTTP_X_CONSENT_TOKEN=raw_token,
        )

        self.assertEqual(response.status_code, 401)

    # ------------------------------------------------------
    # Uniqueness Enforcement
    # ------------------------------------------------------
    def test_only_one_consent_per_profile_application(self):
        """
        Database constraint must prevent duplicate consents.
        """
        with self.assertRaises(Exception):
            Consent.objects.create(
                profile=self.profile,
                application=self.application,
                status=Consent.Status.PENDING
            )