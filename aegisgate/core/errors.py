"""Project error hierarchy."""


class AegisGateError(Exception):
    """Base error."""


class PolicyResolutionError(AegisGateError):
    """Raised when policy cannot be resolved."""
