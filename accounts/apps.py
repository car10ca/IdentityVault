"""
Application configuration for the accounts module.

Registers the accounts app within the Django project.
"""
from django.apps import AppConfig


class AccountsConfig(AppConfig):
    """Configuration class for the accounts application."""
    name = 'accounts'
