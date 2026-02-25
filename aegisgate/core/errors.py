"""Project error hierarchy."""


class AegisGateError(Exception):
    """Base error."""


class FilterRejectedError(AegisGateError):
    """Raised when a filter rejects request/response."""


class PolicyResolutionError(AegisGateError):
    """Raised when policy cannot be resolved."""
