"""
Views for the accounts application.

Provides simple authenticated endpoints related to user accounts.
"""
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def hello_world(request):
    """
    Simple authenticated test endpoint.

    Returns a greeting containing the username of the
    authenticated user to confirm that authentication works.
    """
    return Response({"message": f"Hello, {request.user.username}! You are authenticated."})
