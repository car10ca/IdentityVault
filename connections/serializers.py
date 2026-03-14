"""
Serializers for the connections application.

These serializers expose partner applications and user connections
(consent relationships) through the API while enforcing safe defaults
and ownership validation.
"""
from rest_framework import serializers
from profiles.models import Application, Consent, Profile


class ApplicationSerializer(serializers.ModelSerializer):
    """
    Read-only serializer for the application catalog.

    Exposes basic metadata about registered partner applications.
    """

    class Meta:
        model = Application
        fields = ["id", "name", "slug", "created_at"]
        read_only_fields = fields


class ConnectionSerializer(serializers.ModelSerializer):
    """
    Read-only serializer representing a user connection.

    Internally, connections are stored as Consent objects.
    This serializer preserves the previous API structure while
    exposing consent lifecycle information.
    """

    application = ApplicationSerializer(read_only=True)
    profile_id = serializers.IntegerField(source="profile.id", read_only=True)

    class Meta:
        model = Consent
        fields = [
            "id",
            "profile_id",
            "application",
            "status",
            "created_at",
            "updated_at",
            "granted_at",
            "revoked_at",
        ]
        read_only_fields = fields


class ConnectionCreateSerializer(serializers.ModelSerializer):
    """
    Serializer used to create a new connection request.

    When a connection is created, a Consent object is generated
    with an initial status of PENDING. Ownership validation ensures
    that users can only create connections for profiles they own.
    """
    profile = serializers.PrimaryKeyRelatedField(queryset=Profile.objects.all())
    application = serializers.PrimaryKeyRelatedField(queryset=Application.objects.all())

    class Meta:
        model = Consent
        fields = ["id", "profile", "application"]
        read_only_fields = ["id"]

    def validate_profile(self, profile: Profile):
        """
        Ensure that the authenticated user owns the selected profile.
        """
        request = self.context["request"]

        if profile.owner_id != request.user.id:
            raise serializers.ValidationError(
                "You can only connect your own profiles."
            )

        return profile

    def create(self, validated_data):
        """
        Create the consent object with an initial PENDING state.
        """
        validated_data["status"] = Consent.Status.PENDING

        return super().create(validated_data)
