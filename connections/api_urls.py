"""
API routing configuration for the connections application.

This module registers viewsets related to partner applications
and user connections, and exposes additional endpoints used for
identity retrieval and consent schema inspection.
"""

from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import ConnectionViewSet, ApplicationViewSet
from .identity_views import ApplicationIdentityView
from .schema_views import ConsentStatusSchemaView


router = DefaultRouter()

# Viewsets providing CRUD operations
router.register(r"applications", ApplicationViewSet, basename="application")
router.register(r"connections", ConnectionViewSet, basename="connection")

urlpatterns = router.urls + [
    # Endpoint used by partner applications to retrieve identity data
    path(
        "applications/<int:application_id>/identity/",
        ApplicationIdentityView.as_view(),
        name="application-identity",
    ),
    # Endpoint exposing the consent lifecycle schema (for documentation/debugging)
    path(
        "consent-status-schema/",
        ConsentStatusSchemaView.as_view(),
        name="consent-status-schema",
    ),
]