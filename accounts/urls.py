"""
URL routing for the accounts application.

Defines routes related to account-related views, such as
basic test endpoints or user account functionality.
"""
from django.urls import path
from . import views

urlpatterns = [
    # Simple test endpoint used to verify that the accounts app is working
    path('hello/', views.hello_world, name='hello_world'),
    # Example registration endpoint (currently disabled)
    # path("register/", views.register_user, name="register_user")
]
