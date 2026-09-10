class MailTraceException(Exception):
    """Base exception for MailTrace AI errors."""
    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class EmailParsingError(MailTraceException):
    """Raised when an email file cannot be parsed or decoded."""
    pass


class AuthenticationVerificationError(MailTraceException):
    """Raised when SPF/DKIM/DMARC verification fails unexpectedly."""
    pass


class ThreatIntelError(MailTraceException):
    """Raised when threat intelligence query fails."""
    pass


class GraphBuildError(MailTraceException):
    """Raised when constructing graph relations fails."""
    pass
