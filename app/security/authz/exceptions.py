class TokenError(Exception):
    """Base token exception."""


class InvalidToken(TokenError):
    """Token is invalid."""


class ExpiredToken(TokenError):
    """Token expired."""


class InvalidClaims(TokenError):
    """Claims validation failed."""