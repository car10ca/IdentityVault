"""
API routing configuration for the accounts application.

This module defines endpoints related to authenticated user
information, such as retrieving the currently logged-in user.
"""
from django.urls import path
from .api import me

urlpatterns = [
    # Returns information about the currently authenticated user
    path("me/", me, name="api_me"),
]