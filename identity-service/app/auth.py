"""FastAPI auth dependencies: verify Firebase ID tokens and enforce MFA."""

from fastapi import Depends, Header, HTTPException, status

from app import firebase
from app.config import settings


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
        )
    return authorization.split(" ", 1)[1].strip()


def require_user(authorization: str | None = Header(default=None)) -> dict:
    """Return the decoded Firebase ID token, or 401."""
    token = _bearer(authorization)
    try:
        return firebase.verify_id_token(token)
    except Exception as e:  # firebase raises several subclasses
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"invalid token: {e}",
        ) from e


def require_mfa(claims: dict = Depends(require_user)) -> dict:
    """Require a second factor on the ID token when REQUIRE_MFA is on.

    Firebase stamps a multi-factor sign-in with firebase.sign_in_second_factor
    (e.g. "phone"). We gate sensitive actions (mandate signing) on it.
    """
    if settings.require_mfa:
        second_factor = claims.get("firebase", {}).get("sign_in_second_factor")
        if not second_factor:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="second factor required",
            )
    return claims
