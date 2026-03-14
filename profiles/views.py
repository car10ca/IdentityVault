"""
API views for managing user profiles.

This module exposes REST endpoints for creating, viewing, updating,
and deleting contextual identity profiles.

Security design:
- Only authenticated users can access these endpoints.
- Users can only access profiles they own.
- Profile ownership is enforced server-side during creation.
"""
from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated

from .models import Profile
from .serializers import ProfileSerializer


class ProfileViewSet(ModelViewSet):
    """
    API endpoint for managing contextual identity profiles.

    The viewset ensures that users can only access and modify
    their own profiles. All queryset operations are scoped
    to the authenticated user.
    """
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Restrict returned profiles to those owned by the
        authenticated user.

        This prevents users from accessing profiles belonging
        to other accounts.
        """
        return Profile.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        """
        Automatically assign the authenticated user as the
        owner of the newly created profile.

        This prevents clients from manually specifying or
        spoofing the profile owner in the request payload.
        """
        serializer.save(owner=self.request.user)
