"""
Utility helpers for profile-related operations.

These helpers centralize common logic used across the application,
such as retrieving profiles while enforcing ownership checks.
"""
from django.shortcuts import get_object_or_404
from profiles.models import Profile

def get_user_profile_or_404(user, profile_id):
    """
    Retrieve a profile owned by the given user.

    This helper ensures that profile access is always scoped to
    the authenticated user. If the profile does not exist or does
    not belong to the user, a 404 error is raised.

    Args:
        user: The authenticated user requesting the profile.
        profile_id (int): The ID of the requested profile.

    Returns:
        Profile: The matching profile instance.
    """
    return get_object_or_404(Profile, id=profile_id, owner=user)
