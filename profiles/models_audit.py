"""
Audit logging models for IdentityVault.

These models record security-relevant events related to identity
profiles and consent management. The audit logs provide traceability
for changes to identity sharing decisions and profile lifecycle events.

Design considerations:
- Logs are append-only records and should not be modified.
- Some events use snapshot fields to remain meaningful even if the
  original object is later deleted.
- Indexes are defined to support efficient audit queries.
"""
from django.conf import settings
from django.db import models

class ConsentAuditLog(models.Model):
    """
    Records state changes in the consent lifecycle.

    Each entry represents a transition or action involving a
    Profile and an Application, such as granting or revoking
    consent for identity sharing.

    These logs support traceability of identity disclosure
    decisions and allow administrators to review historical
    consent activity.
    """
    class Action(models.TextChoices):
        """Enumerates possible consent-related actions."""
        GRANT = "grant", "Grant"
        DENY = "deny", "Deny"
        REVOKE = "revoke", "Revoke"
        CONNECT = "connect", "Connect"

    # User responsible for the action (may be null if system triggered)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="consent_audit_events",
    )

    # Profile involved in the consent action
    profile = models.ForeignKey(
        "profiles.Profile",
        on_delete=models.CASCADE,
        related_name="consent_audit_events",
    )

    # Application requesting identity data
    application = models.ForeignKey(
        "profiles.Application",
        on_delete=models.CASCADE,
        related_name="consent_audit_events",
    )

    # Previous consent status (for state transition tracking)
    old_status = models.CharField(max_length=32, blank=True)

    # New consent status after the action
    new_status = models.CharField(max_length=32, blank=True)

    action = models.CharField(max_length=16, choices=Action.choices)

    # Timestamp of the recorded event
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        # Index improves performance for audit queries
        # when reviewing consent history for a profile
        indexes = [
            models.Index(fields=["profile", "application", "created_at"]),
        ]

    def __str__(self):
        """Human-readable summary for admin and debugging."""
        return f"{self.created_at} {self.actor_id} {self.profile_id}->{self.application_id} {self.action}"


class ProfileAuditLog(models.Model):
    """
    Audit log for profile-level actions (e.g., deletion).

    Snapshot fields are used so the log remains meaningful
    even after the Profile is deleted. This ensures that
    historical events can still be interpreted even if the
    referenced profile no longer exists.
    """

    class Action(models.TextChoices):
        """Enumerates profile lifecycle actions."""
        DELETE = "delete", "Delete"

    # User responsible for the action
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="profile_audit_events",
    )

    # Snapshot fields preserve information about the profile
    # even if the original row has been removed.
    profile_id_snapshot = models.IntegerField(null=True, blank=True)
    profile_name_snapshot = models.CharField(max_length=80)

    # Contextual information: how many consent records were removed
    # as part of the profile deletion process.
    consents_deleted_count = models.PositiveIntegerField(default=0)

    action = models.CharField(max_length=16, choices=Action.choices)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        # Indexes support efficient querying of audit history
        indexes = [
            models.Index(fields=["actor", "created_at"]),
            models.Index(fields=["profile_id_snapshot", "created_at"]),
        ]

    def __str__(self):
        """Human-readable summary for audit inspection."""
        return f"{self.created_at} {self.actor_id} profile={self.profile_id_snapshot} {self.action}"
