"""
Serializers for profile data exposed through the IdentityVault API.

Serializers transform Profile model instances into JSON responses
and validate incoming data when profiles are created or updated.

Security and privacy considerations:
- Only a defined set of identity attributes is exposed.
- System-managed fields (id, timestamps) are read-only.
"""

from rest_framework import serializers
from .models import Profile

class ProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for contextual identity profiles.

    This serializer defines which profile attributes can be
    created, updated, or returned through the API.
    """
    class Meta:
        model = Profile
        # Identity attributes that can be stored for a profile
        fields = [
            "id",
            "name",
            "first_name",
            "last_name",
            "email",
            "birth_year",
            "city",
            "created_at",
            "updated_at",
        ]
        # System-managed fields that must not be modified by clients
        read_only_fields = ["id", "created_at", "updated_at"]