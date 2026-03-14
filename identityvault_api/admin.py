"""
Admin configuration for the IdentityVault API project.

This module customizes the Django admin interface for the Axes
authentication protection system. It provides a safe way for
administrators to reset lockouts caused by repeated failed
login attempts.
"""
from django.contrib import admin
from django.contrib import messages


try:
    from axes.models import AccessAttempt
    from axes.helpers import reset

    # Unregister the default Axes admin configuration
    admin.site.unregister(AccessAttempt)

    @admin.action(description="Reset lockout (selected attempts)")
    def reset_lockout(modeladmin, request, queryset):
        """
        Admin action that resets login lockouts for selected records.

        This clears lockouts for both usernames and IP addresses
        associated with failed authentication attempts.
        """
        usernames = set(queryset.values_list("username", flat=True))
        ip_addresses = set(queryset.values_list("ip_address", flat=True))

        for u in usernames:
            if u:
                reset(username=u)

        for ip in ip_addresses:
            if ip:
                reset(ip_address=ip)

        messages.success(request, "Selected lockouts have been reset.")

    @admin.register(AccessAttempt)
    class AccessAttemptAdmin(admin.ModelAdmin):
        """
        Read-only admin view for login failure records tracked by django-axes.
        """
        list_display = (
            "attempt_time",
            "ip_address",
            "username",
            "path_info",
            "failures_since_start",
        )
        search_fields = ("username", "ip_address", "path_info")
        ordering = ("-attempt_time",)

        actions = [reset_lockout]

        # Prevent manual modification of audit records
        def has_add_permission(self, request):
            return False

        def has_change_permission(self, request, obj=None):
            return False

        def has_delete_permission(self, request, obj=None):
            return False

except Exception:
    # Axes may not be installed in all environments (e.g., testing)
    pass