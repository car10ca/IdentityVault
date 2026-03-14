"""
API endpoints for account-related operations.

This module exposes endpoints that allow authenticated users
to retrieve information about their own account.
"""
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def me(request):
    """
    Return basic information about the currently authenticated user.

    Access is restricted to authenticated requests.
    """
    user = request.user
    return Response({
        "id": user.id,
        "email": user.email,
        "username": user.username,
    })