"""
API views for managing connections between profiles and applications.

Internally these connections are implemented as Consent objects.
This module exposes endpoints that allow users to create connections
and perform consent lifecycle actions such as grant, deny, and revoke.
"""
from django.db import transaction
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.exceptions import NotFound

from profiles.models import Application, Consent
from profiles.models_audit import ConsentAuditLog
from .serializers import (
    ConnectionSerializer,
    ConnectionCreateSerializer,
    ApplicationSerializer,
)


class ApplicationViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read-only catalog of partner applications.

    Applications represent external services that may request
    identity attributes through the IdentityVault API.
    """
    queryset = Application.objects.all().order_by("name")
    serializer_class = ApplicationSerializer
    permission_classes = [IsAuthenticated]


class ConnectionViewSet(viewsets.ModelViewSet):
    """
    Viewset managing connections between profiles and applications.

    Although exposed as "connections" for backwards compatibility,
    these objects are stored internally as Consent records and follow
    a defined consent lifecycle.
    """
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Return only consents belonging to profiles owned by the
        authenticated user.

        This enforces strict ownership isolation between users.
        """
        qs = (
            Consent.objects
            .select_related("profile", "application")
            .filter(profile__owner=self.request.user)
        )

        profile_id = self.request.query_params.get("profile")
        if profile_id:
            qs = qs.filter(profile_id=profile_id)

        application_id = self.request.query_params.get("application")
        if application_id:
            qs = qs.filter(application_id=application_id)

        return qs.order_by("-updated_at")

    def get_serializer_class(self):
        """
        Use a different serializer for connection creation.
        """
        if self.action == "create":
            return ConnectionCreateSerializer
        return ConnectionSerializer

    def update(self, request, *args, **kwargs):
        """
        Disable direct updates to consent objects.

        Consent lifecycle transitions must occur through
        explicit actions such as /grant, /deny, or /revoke.
        """
        return Response(
            {"detail": "Direct updates are not allowed. Use /grant, /deny, or /revoke."},
            status=status.HTTP_405_METHOD_NOT_ALLOWED,
        )

    def partial_update(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    # -----------------------------------------------------
    # Ownership-safe lookup with row locking
    # -----------------------------------------------------
    def _get_owned_consent(self, pk):
        """
        Retrieve a consent object owned by the authenticated user.

        Uses SELECT FOR UPDATE to lock the row and prevent race
        conditions when multiple actions occur concurrently.
        """
        try:
            return (
                Consent.objects
                .select_for_update()
                .select_related("profile", "application")
                .get(
                    pk=pk,
                    profile__owner=self.request.user,
                )
            )
        except Consent.DoesNotExist:
            raise NotFound("Connection not found.")

    # -----------------------------------------------------
    # Consent lifecycle actions
    # -----------------------------------------------------
    @transaction.atomic
    @action(detail=True, methods=["post"])
    def grant(self, request, pk=None):
        """
        Grant consent for an application to access profile data.

        Generates a new consent token and records the action
        in the audit log.
        """
        consent = self._get_owned_consent(pk)
        old_status = consent.status
        now = timezone.now()

        if consent.status == Consent.Status.GRANTED:
            return Response({"detail": "Already granted."}, status=200)

        # Defensive check: ensure only one GRANTED consent per profile/application
        other = (
            Consent.objects
            .select_for_update()
            .filter(
                profile=consent.profile,
                application=consent.application,
                status=Consent.Status.GRANTED,
            )
            .exclude(pk=consent.pk)
            .first()
        )

        if other:
            other_old = other.status
            other.status = Consent.Status.REVOKED
            other.revoked_at = now
            other.save(update_fields=["status", "revoked_at", "updated_at"])

            ConsentAuditLog.objects.create(
                actor=request.user,
                profile=other.profile,
                application=other.application,
                old_status=other_old,
                new_status=other.status,
                action=ConsentAuditLog.Action.REVOKE,
            )

        # Grant consent
        consent.status = Consent.Status.GRANTED
        consent.granted_at = now
        consent.revoked_at = None

        # SECURITY: rotate consent token on every grant
        raw_token = consent.generate_consent_token()

        consent.save(update_fields=["status", "granted_at", "revoked_at", "updated_at"])

        ConsentAuditLog.objects.create(
            actor=request.user,
            profile=consent.profile,
            application=consent.application,
            old_status=old_status,
            new_status=consent.status,
            action=ConsentAuditLog.Action.GRANT,
        )

        data = ConnectionSerializer(consent).data

        # Token is shown once in the response for demonstration purposes
        data["consent_token"] = raw_token

        return Response(data, status=200)

    @transaction.atomic
    @action(detail=True, methods=["post"])
    def deny(self, request, pk=None):
        """
        Deny a pending consent request.
        """
        consent = self._get_owned_consent(pk)
        old_status = consent.status

        if consent.status == Consent.Status.DENIED:
            return Response({"detail": "Already denied."}, status=200)

        if consent.status != Consent.Status.PENDING:
            return Response(
                {"detail": f"Cannot deny from state '{consent.status}'."},
                status=status.HTTP_409_CONFLICT,
            )

        consent.status = Consent.Status.DENIED
        consent.save(update_fields=["status", "updated_at"])

        ConsentAuditLog.objects.create(
            actor=request.user,
            profile=consent.profile,
            application=consent.application,
            old_status=old_status,
            new_status=consent.status,
            action=ConsentAuditLog.Action.DENY,
        )

        return Response(ConnectionSerializer(consent).data, status=200)

    @transaction.atomic
    @action(detail=True, methods=["post"])
    def revoke(self, request, pk=None):
        """
        Revoke previously granted consent.
        """
        consent = self._get_owned_consent(pk)
        old_status = consent.status
        now = timezone.now()

        if consent.status == Consent.Status.REVOKED:
            return Response({"detail": "Already revoked."}, status=200)

        if consent.status != Consent.Status.GRANTED:
            return Response(
                {"detail": f"Cannot revoke from state '{consent.status}'."},
                status=status.HTTP_409_CONFLICT,
            )

        consent.status = Consent.Status.REVOKED
        consent.revoked_at = now
        consent.save(update_fields=["status", "revoked_at", "updated_at"])

        ConsentAuditLog.objects.create(
            actor=request.user,
            profile=consent.profile,
            application=consent.application,
            old_status=old_status,
            new_status=consent.status,
            action=ConsentAuditLog.Action.REVOKE,
        )

        return Response(ConnectionSerializer(consent).data, status=200)