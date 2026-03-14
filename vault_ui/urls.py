"""
URL routing for the vault_ui application.

These routes define the web interface used by authenticated users
to interact with IdentityVault. The UI allows users to manage
profiles, consent relationships, and personal account data.
"""
from django.urls import path
from . import views


urlpatterns = [

    # Landing and authentication
    path("", views.landing_view, name="vault_landing"),
    path("login/", views.login_view, name="vault_login"),
    path("logout/", views.logout_view, name="vault_logout"),
    path("register/", views.register_view, name="vault_register"),

    # Account management
    path("account/", views.account_data_view, name="vault_account_data"),
    path("account/export/csv/", views.export_my_data_csv, name="vault_export_csv"),
    path("account/delete/", views.delete_my_account, name="vault_delete_account"),
    path("account/deleted/", views.account_deleted_view, name="vault_account_deleted"),

    # Main dashboard
    path("dashboard/", views.dashboard_view, name="vault_dashboard"),

    # Profile management
    path("profiles/create/", views.profile_create_view, name="vault_profile_create"),
    path("profiles/<int:profile_id>/", views.profile_detail_view, name="vault_profile_detail"),
    path("profiles/<int:profile_id>/edit/", views.profile_edit_view, name="vault_profile_edit"),
    path("profiles/<int:profile_id>/delete/", views.profile_delete_execute_view, name="vault_profile_delete"),

    # Connect application from profile detail
    path(
        "profiles/<int:profile_id>/connect/",
        views.connect_application_view,
        name="vault_connect_application",
    ),

    # Consent detail view
    path(
        "profiles/<int:profile_id>/apps/<int:app_id>/consent/",
        views.consent_detail_view,
        name="vault_consent_detail",
    ),

    # Consent lifecycle action endpoint
    path(
        "consent/action/",
        views.consent_action_view,
        name="vault_consent_action",
    ),
]