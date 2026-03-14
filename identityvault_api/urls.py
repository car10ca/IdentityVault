"""
Root URL configuration for the IdentityVault API project.

This module aggregates API routes from the different applications
(profiles, connections, accounts) and exposes authentication
endpoints and the administrative interface.
"""
from django.contrib import admin
from django.urls import path, include
from accounts.jwt_views import SecureTokenObtainPairView, SecureTokenRefreshView


urlpatterns = [
    # Django admin interface
    path("admin/", admin.site.urls),

    # Core API modules
    path("api/", include("profiles.api_urls")),
    path("api/", include("connections.api_urls")),
    path("api/accounts/", include("accounts.api_urls")),

    # JWT authentication endpoints
    path("api/token/", SecureTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/token/refresh/", SecureTokenRefreshView.as_view(), name="token_refresh"),

    # Frontend UI for the vault dashboard
    path("vault/", include("vault_ui.urls")),
]