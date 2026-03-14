"""
Service layer for managing consent lifecycle transitions.

This module centralizes business logic related to consent state changes.
It enforces strict state transition rules and records audit events
whenever consent status changes.

Key guarantees:
- Only valid consent state transitions are allowed.
- All changes are executed inside database transactions.
- Consent lifecycle events are recorded in the audit log.
"""
from django.db import transaction
from django.utils import timezone

from profiles.models import Consent
from profiles.models_audit import ConsentAuditLog


class ConsentActionError(ValueError):
    """Raised when an invalid action is requested."""


class ConsentTransitionError(RuntimeError):
    """Raised when an illegal state transition is requested."""

# Allowed consent lifecycle transitions
# (represents the finite state machine of the consent model)
ALLOWED_TRANSITIONS = {
    Consent.Status.PENDING: {Consent.Status.GRANTED, Consent.Status.DENIED},
    Consent.Status.GRANTED: {Consent.Status.REVOKED},
    Consent.Status.REVOKED: {Consent.Status.PENDING, Consent.Status.GRANTED},
    Consent.Status.DENIED: {Consent.Status.PENDING, Consent.Status.GRANTED},
}

# Maps external action names to target consent states
ACTION_TO_STATUS = {
    "grant": Consent.Status.GRANTED,
    "deny": Consent.Status.DENIED,
    "revoke": Consent.Status.REVOKED,
}


def apply_consent_action(consent: Consent, action: str) -> tuple[str, str | None]:
    """
    Apply a consent action while enforcing lifecycle rules.

    This function performs the state transition logic and prepares
    the consent object for persistence.

    Args:
        consent: The consent object being modified.
        action: The requested action ("grant", "deny", "revoke").

    Returns:
        tuple:
            feedback string (granted/denied/revoked)
            raw_token (only when granted, otherwise None)
    """
    if action not in ACTION_TO_STATUS:
        raise ConsentActionError("Invalid action")

    new_status = ACTION_TO_STATUS[action]
    old_status = consent.status

    allowed = ALLOWED_TRANSITIONS.get(old_status, set())
    if new_status not in allowed:
        raise ConsentTransitionError(
            f"Illegal transition: {old_status} -> {new_status}"
        )

    now = timezone.now()
    raw_token = None

    # =========================
    # GRANT
    # =========================
    if new_status == Consent.Status.GRANTED:
        consent.status = Consent.Status.GRANTED
        consent.granted_at = now
        consent.revoked_at = None

        # SECURITY: rotate token on every grant
        raw_token = consent.generate_consent_token()

        return "granted", raw_token

    # =========================
    # DENY
    # =========================
    if new_status == Consent.Status.DENIED:
        consent.status = Consent.Status.DENIED
        consent.granted_at = None
        consent.revoked_at = None

        # SECURITY: invalidate any existing consent token
        consent.consent_token_hash = ""
        consent.consent_token_created_at = None

        return "denied", None

    # =========================
    # REVOKE
    # =========================
    if new_status == Consent.Status.REVOKED:
        consent.status = Consent.Status.REVOKED
        consent.revoked_at = now

        # Invalidate token completely
        consent.consent_token_hash = ""
        consent.consent_token_created_at = None

        return "revoked", None

    raise ConsentActionError("Unhandled action")


@transaction.atomic
def lock_and_apply_action(consent_qs, action: str, actor=None):
    """
    Apply a consent action with row-level locking.

    The consent row is locked using SELECT FOR UPDATE to prevent
    race conditions when multiple requests attempt to modify
    the same consent simultaneously.
    """
    consent = consent_qs.select_for_update().get()

    old_status = consent.status

    feedback, raw_token = apply_consent_action(consent, action)
    new_status = consent.status

    consent.save(
        update_fields=[
            "status",
            "granted_at",
            "revoked_at",
            "consent_token_hash",
            "consent_token_created_at",
            "updated_at",
        ]
    )

    # Record audit event
    ConsentAuditLog.objects.create(
        actor=actor,
        profile=consent.profile,
        application=consent.application,
        old_status=str(old_status),
        new_status=str(new_status),
        action=action,
    )

    return consent, feedback, raw_token


@transaction.atomic
def connect_or_reset_to_pending(consent: Consent | None) -> Consent:
    """
    Prepare a consent object for a new connection attempt.

    If the consent was previously denied or revoked,
    the state is reset to PENDING and token lifecycle
    data is cleared.

    This ensures a consistent starting state for a new
    consent request.
    """
    if consent.status in {Consent.Status.DENIED, Consent.Status.REVOKED}:
        consent.status = Consent.Status.PENDING
        consent.granted_at = None
        consent.revoked_at = None

        # Clear token lifecycle
        consent.consent_token_hash = ""
        consent.consent_token_created_at = None

        consent.save(
            update_fields=[
                "status",
                "granted_at",
                "revoked_at",
                "consent_token_hash",
                "consent_token_created_at",
                "updated_at",
            ]
        )

    return consent