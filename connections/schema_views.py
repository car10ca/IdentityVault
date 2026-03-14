"""
API endpoint exposing the consent lifecycle schema.

This endpoint provides a machine-readable description of the
consent finite-state machine (FSM). It is useful for documentation,
client integrations, and debugging.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from profiles.models import Consent


class ConsentStatusSchemaView(APIView):
    """
    Self-describing schema endpoint for the consent finite-state machine.

    Returns:
    - All possible consent states
    - Allowed transitions between states
    - Supported actions that trigger transitions
    """

    # Public endpoint used for documentation purposes
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        # Extract available states from the Consent model
        states = [choice[0] for choice in Consent.Status.choices]

        # Define allowed lifecycle transitions
        transitions = {
            Consent.Status.PENDING: [Consent.Status.GRANTED, Consent.Status.DENIED],
            Consent.Status.GRANTED: [Consent.Status.REVOKED],
            Consent.Status.REVOKED: [Consent.Status.PENDING, Consent.Status.GRANTED],
            Consent.Status.DENIED: [Consent.Status.PENDING, Consent.Status.GRANTED],
        }

        return Response(
            {
                "states": states,
                "transitions": transitions,
                "actions": {
                    "grant": "pending|revoked|denied -> granted",
                    "deny": "pending -> denied",
                    "revoke": "granted -> revoked",
                },
            },
            status=status.HTTP_200_OK,
        )