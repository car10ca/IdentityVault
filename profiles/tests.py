"""
Security tests for the Profile API endpoints.

These tests verify that profile data is properly isolated between users.
In particular, they ensure that authenticated users cannot access or
list profiles belonging to other accounts.
"""
from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status

from profiles.models import Profile


class ProfileSecurityTests(TestCase):
    """
    Tests enforcing ownership isolation for profile resources.

    The API must ensure that users can only access profiles they own.
    """
    def setUp(self):
        """
        Create two users and a profile owned by user_a.
        This allows us to test whether user_b can access it.
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
            name="A profile"
        )

    def get_auth_client(self, username, password):
        """
        Helper method that authenticates a user using the JWT endpoint
        and returns an APIClient with the Authorization header set.
        """
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

    def test_user_cannot_read_other_users_profile_detail(self):
        """
        SECURITY TEST:
        Ensure that a user cannot retrieve the detail endpoint of a
        profile owned by another user.
        """
        client_b = self.get_auth_client("user_b", "StrongPassw0rd!!")

        response = client_b.get(f"/api/profiles/{self.profile.id}/")

        self.assertIn(
            response.status_code,
            [status.HTTP_404_NOT_FOUND, status.HTTP_403_FORBIDDEN],
        )

    def test_user_cannot_see_other_users_profiles_in_list(self):
        """
        SECURITY TEST:
        Ensure that listing profiles only returns objects
        owned by the authenticated user.
        """

        # Authenticate as user_b
        client_b = self.get_auth_client("user_b", "StrongPassw0rd!!")

        # Call list endpoint
        response = client_b.get("/api/profiles/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Extract returned IDs
        returned_ids = [p["id"] for p in response.data]

        # The profile created for user_a must NOT appear
        self.assertNotIn(self.profile.id, returned_ids)

