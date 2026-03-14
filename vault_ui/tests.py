"""
Security tests for the vault_ui authentication interface.

These tests verify that login behaviour follows secure practices,
including protection against brute-force attacks and prevention of
user enumeration during authentication attempts.

Test coverage includes:
- Account lockout after repeated failed login attempts (django-axes)
- Consistent error responses for existing and non-existing users
"""
from django.contrib.auth.models import User
from django.test import TestCase, Client
from django.urls import reverse


class LoginLockoutTests(TestCase):
    """
    Security test to verify that django-axes
    locks a user after repeated failed login attempts.
    """
    def setUp(self):
        # Create a valid user
        self.user = User.objects.create_user(
            username="lockout_user",
            password="CorrectPassw0rd!!"
        )
        self.client = Client()

    def test_user_is_locked_out_after_multiple_failed_attempts(self):
        """
        After AXES_FAILURE_LIMIT failed attempts,
        login should be blocked.
        """
        login_url = reverse("vault_login")

        # Perform 5 failed login attempts
        for _ in range(5):
            response = self.client.post(
                login_url,
                {
                    "username": "lockout_user",
                    "password": "WrongPassword"
                }
            )
            self.assertNotEqual(response.status_code, 302)

        # 6th attempt should trigger lockout
        response = self.client.post(
            login_url,
            {
                "username": "lockout_user",
                "password": "WrongPassword"
            }
        )

        # Axes returns 429 (Too Many Requests) or sometimes 403
        self.assertIn(response.status_code, [403, 429])


    def test_login_does_not_reveal_if_user_exists(self):
        """
        Ensure login response does not differ in status code
        or error messaging between existing and non-existing users.
        """
        login_url = reverse("vault_login")

        # Case 1: Existing user, wrong password
        response_existing = self.client.post(
            login_url,
            {
                "username": "lockout_user",
                "password": "WrongPassword"
            }
        )

        # Case 2: Non-existing user
        response_non_existing = self.client.post(
            login_url,
            {
                "username": "ghost_user",
                "password": "WrongPassword"
            }
        )

        # Status codes must match
        self.assertEqual(
            response_existing.status_code,
            response_non_existing.status_code
        )

        # Extract form error messages
        form_existing = response_existing.context["form"]
        form_non_existing = response_non_existing.context["form"]

        errors_existing = form_existing.non_field_errors()
        errors_non_existing = form_non_existing.non_field_errors()

        # Error messages must be identical
        self.assertEqual(errors_existing, errors_non_existing)
