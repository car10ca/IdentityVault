"""
Application configuration for the vault_ui module.

This app provides the web interface for interacting with the
IdentityVault system, including dashboards and consent management
views presented to authenticated users.
"""
from django.apps import AppConfig


class VaultUiConfig(AppConfig):
    """Django application configuration for the vault UI layer."""
    name = 'vault_ui'
