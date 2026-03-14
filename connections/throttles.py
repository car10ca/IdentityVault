"""
Custom throttling classes for the connections application.

These throttles protect sensitive endpoints such as identity retrieval
from excessive requests and potential abuse.
"""
from rest_framework.throttling import SimpleRateThrottle


class ApplicationIdentityThrottle(SimpleRateThrottle):
    """
    Rate limit for the application identity endpoint.

    Requests are limited per combination of application ID and client IP
    address to prevent a single application or client from abusing the
    endpoint.
    """

    scope = "app_identity"
    rate = "60/min"  # Adjust if stricter limits are required

    def get_cache_key(self, request, view):
        """
        Build a unique throttle key using application_id and client IP.
        """
        application_id = view.kwargs.get("application_id", "unknown")
        ident = self.get_ident(request)  # client IP address
        return self.cache_format % {"scope": self.scope, "ident": f"{application_id}:{ident}"}