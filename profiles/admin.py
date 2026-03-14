"""
Django admin configuration for the profiles application.

The admin interface allows administrators to inspect profiles,
applications, consent relationships, and audit logs.

Security considerations:
- Audit logs are read-only to preserve historical integrity.
- Consent records are read-only to prevent manual lifecycle tampering.
"""
from django.contrib import admin
from .models import Profile, Application, Consent
from .models_audit import ConsentAuditLog, ProfileAuditLog


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    """
    Admin configuration for viewing user profiles.
    """
    list_display = ("name", "owner", "created_at")
    search_fields = ("name", "owner__username")


@admin.register(ConsentAuditLog)
class ConsentAuditLogAdmin(admin.ModelAdmin):
    """
    Read-only admin view for consent lifecycle audit events.
    """
    list_display = (
        "created_at",
        "actor",
        "profile",
        "application",
        "action",
        "old_status",
        "new_status",
    )

    list_filter = ("action", "created_at")
    search_fields = (
        "actor__username",
        "profile__name",
        "application__name",
    )

    ordering = ("-created_at",)
    # SECURITY: audit logs must remain immutable
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(ProfileAuditLog)
class ProfileAuditLogAdmin(admin.ModelAdmin):
    """
    Read-only admin view for profile lifecycle audit events.
    """
    list_display = (
        "created_at",
        "actor",
        "profile_id_snapshot",
        "profile_name_snapshot",
        "consents_deleted_count",
        "action",
    )

    list_filter = ("action", "created_at")

    search_fields = (
        "actor__username",
        "profile_name_snapshot",
    )

    ordering = ("-created_at",)

    # SECURITY: audit records must not be modified
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    """
    Admin interface for managing registered partner applications.
    """
    list_display = ("name", "slug", "created_at")
    search_fields = ("name", "slug")



@admin.register(Consent)
class ConsentAdmin(admin.ModelAdmin):
    """
    Read-only admin view for consent relationships.

    Consent lifecycle transitions should occur only through
    application logic and user actions, not manual admin edits.
    """
    list_display = (
        "id",
        "profile",
        "application",
        "status",
        "granted_at",
        "revoked_at",
        "created_at",
        "updated_at",
    )

    search_fields = (
        "profile__name",
        "application__name",
    )

    list_filter = ("status", "created_at")

    ordering = ("-created_at",)

    # SECURITY: prevent manual lifecycle manipulation
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False