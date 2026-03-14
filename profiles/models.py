"""
Domain models for the IdentityVault profile and consent system.

This module defines the core data structures used to manage contextual
identity profiles, partner applications, and the consent lifecycle
between them.

Key concepts:
- Profile: a contextual identity representation owned by a user
- Application: an external partner system requesting identity data
- Consent: the stateful permission linking a profile to an application

Security and privacy considerations:
- API keys and consent tokens are stored only as SHA256 hashes
- Tokens are compared using constant-time comparison
- Unique constraints enforce one consent relationship per
  profile-application pair.
"""
from django.conf import settings
from django.db import models
from django.utils import timezone
import secrets
import hashlib
# Import ensures audit model is registered for Django migrations
# even if not referenced directly in this module.
from .models_audit import ConsentAuditLog  # noqa: F401


class Profile(models.Model):
    """
    Represents a contextual identity profile owned by a user.

    A profile contains a limited set of identity attributes that can be
    shared with external partner applications through explicit consent.

    This design allows users to maintain multiple contextual identities
    (e.g., professional, social) and control which attributes are
    disclosed to each application.
    """
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profiles",
    )
    name = models.CharField(max_length=80)

    # Optional identity attributes.
    # These fields represent a minimal identity dataset and can be
    # extended depending on application requirements.
    first_name = models.CharField(max_length=80, blank=True)
    last_name = models.CharField(max_length=80, blank=True)
    email = models.EmailField(blank=True)
    birth_year = models.PositiveIntegerField(null=True, blank=True)
    city = models.CharField(max_length=120, blank=True)

    # Timestamp tracking for auditability
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        """Human-readable representation used in Django admin."""
        return f"{self.name} ({self.owner})"


class Application(models.Model):
    """
    Represents an external partner application registered in IdentityVault.

    Applications authenticate using an API key. For security reasons,
    only a SHA256 hash of the key is stored in the database. The raw key
    is generated once and must be securely stored by the application owner.

    Applications may optionally define a list of allowed_fields which
    restricts the identity attributes returned by the identity endpoint.
    This supports the principle of data minimisation.
    """

    name = models.CharField(max_length=80, unique=True)
    slug = models.SlugField(max_length=80, unique=True)

    # Store hashed API key only
    api_key_hash = models.CharField(max_length=128, blank=True)

    # Data minimisation control.
    # If empty → default identity attributes are returned.
    # If defined → identity endpoint filters response to these fields.
    allowed_fields = models.JSONField(default=list, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        """Human-readable name used in Django admin and logs."""
        return self.name

    # ------------------------------------------------
    # API KEY MANAGEMENT
    # ------------------------------------------------
    # API keys are generated securely and stored only
    # as SHA256 hashes to prevent credential leakage
    # if the database is compromised.

    def generate_api_key(self) -> str:
        """
        Generate a new API key for the application.

        A cryptographically secure random token is created using
        Python's secrets module. Only the SHA256 hash of the key
        is stored in the database.

        Returns:
            str: The raw API key (displayed once to the administrator).
        """
        raw_key = secrets.token_urlsafe(40)
        self.api_key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        self.save(update_fields=["api_key_hash"])
        return raw_key

    def check_api_key(self, raw_key: str) -> bool:
        """
        Verify a provided API key.

        The comparison uses constant-time comparison to mitigate
        timing attacks against the stored hash.
        """
        if not self.api_key_hash:
            return False

        candidate_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        return secrets.compare_digest(candidate_hash, self.api_key_hash)


class Consent(models.Model):
    """
    Represents a consent relationship between a Profile and an Application.

    Consent defines whether a specific partner application is authorised
    to access identity attributes from a given profile.

    The consent lifecycle is modelled as a finite state machine with the
    following states:

    - pending: consent request created but not yet approved
    - granted: user approved identity sharing
    - denied: user rejected the request
    - revoked: previously granted consent was withdrawn

    This explicit state modelling ensures traceability and auditability
    of identity-sharing decisions.
    """

    class Status(models.TextChoices):
        """Enumerates the possible states of the consent lifecycle."""
        PENDING = "pending", "Pending"
        GRANTED = "granted", "Granted"
        DENIED = "denied", "Denied"
        REVOKED = "revoked", "Revoked"

    profile = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name="consents")
    application = models.ForeignKey(Application, on_delete=models.CASCADE, related_name="consents")

    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # when granted/revoked happened, for auditability
    granted_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    # SECURITY: token hashes are stored instead of raw tokens
    # to reduce impact if the database is compromised.
    # Store hashed consent token (least privilege, app-scoped by FK)
    consent_token_hash = models.CharField(max_length=128, blank=True, db_index=True)

    # Token lifecycle (expiry support)
    consent_token_created_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        # Ensure each profile can only have one consent relationship
        # with a specific application.
        constraints = [
            models.UniqueConstraint(fields=["profile", "application"], name="uniq_consent_profile_application")
        ]

    def __str__(self) -> str:
        return f"{self.profile} ↔ {self.application}: {self.status}"

    # ------------------------------------------------
    # CONSENT TOKEN MANAGEMENT
    # ------------------------------------------------
    # Consent tokens are used during the consent approval
    # process. Tokens are generated securely and stored only
    # as SHA256 hashes to prevent token disclosure.
    @staticmethod
    def _hash_token(raw_token: str) -> str:
        """Internal helper for hashing tokens before storage."""
        return hashlib.sha256(raw_token.encode()).hexdigest()

    def generate_consent_token(self) -> str:
        """
        Generate a new consent token.

        A cryptographically secure token is generated and stored as a
        SHA256 hash. The raw token is returned so it can be delivered
        to the user during the consent process.
        """
        raw_token = secrets.token_urlsafe(40)
        self.consent_token_hash = self._hash_token(raw_token)
        self.consent_token_created_at = timezone.now()
        self.save(update_fields=["consent_token_hash", "consent_token_created_at"])
        return raw_token

    def clear_consent_token(self) -> None:
        """
        Explicit invalidation (deny/revoke/reset).
        """
        self.consent_token_hash = ""
        self.consent_token_created_at = None
        self.save(update_fields=["consent_token_hash", "consent_token_created_at"])

    def check_consent_token(self, raw_token: str) -> bool:
        """
        Constant-time comparison of provided token vs stored hash.
        Does NOT check expiry. Expiry is enforced at the endpoint.
        """
        if not self.consent_token_hash:
            return False
        candidate_hash = self._hash_token(raw_token)
        return secrets.compare_digest(candidate_hash, self.consent_token_hash)

    def is_consent_token_expired(self, ttl_seconds: int) -> bool:
        """
        Check whether the consent token exceeded its allowed lifetime.

        Args:
            ttl_seconds (int): maximum token lifetime.

        Returns:
            bool: True if expired, False otherwise.
        """
        if not self.consent_token_hash:
            return True
        if not self.consent_token_created_at:
            # treat legacy/unknown tokens as expired for strict mode
            return True
        return (timezone.now() - self.consent_token_created_at).total_seconds() > ttl_seconds