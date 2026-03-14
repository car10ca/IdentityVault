"""
Serializers for account-related API operations.

These serializers handle validation and transformation of
user data when interacting with the accounts API.
"""
from rest_framework import serializers
from django.contrib.auth.models import User

class RegisterSerializer(serializers.ModelSerializer):
    """
    Serializer used for user registration.

    Ensures that passwords are write-only and that user
    accounts are created using Django's secure create_user
    helper, which automatically hashes the password.
    """
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def create(self, validated_data):
        """
        Create a new user account with a securely hashed password.
        """
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user
