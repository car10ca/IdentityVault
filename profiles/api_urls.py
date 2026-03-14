"""
API routing configuration for the profiles application.

This module registers the ProfileViewSet with Django REST Framework's
router to expose RESTful endpoints for profile management.
"""
from rest_framework.routers import DefaultRouter
from .views import ProfileViewSet

# Router automatically generates standard REST endpoints:
# /api/profiles/
# /api/profiles/<id>/
router = DefaultRouter()
router.register(r"profiles", ProfileViewSet, basename="profile")

urlpatterns = router.urls