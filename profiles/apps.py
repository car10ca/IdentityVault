"""
Application configuration for the profiles module.

Registers the profiles app within the Django project.
"""
from django.apps import AppConfig


class ProfilesConfig(AppConfig):
    """Configuration class for the profiles application."""
    name = 'profiles'
