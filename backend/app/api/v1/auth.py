from typing import List, Optional
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Header, status
from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.app.core.database import get_db
from backend.app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
)
from backend.app.models.user import User
from backend.app.api.v1.schemas import (
    UserSignUp,
    UserLogin,
    UserResponse,
    TokenResponse,
)

router = APIRouter(prefix="/auth", tags=["User Authentication & Account Management"])


@router.post(
    "/signup",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new investigator or analyst account",
)
def signup(payload: UserSignUp, db: Session = Depends(get_db)):
    """
    Registers a new forensic investigator account in database.db.
    Stores email, username, full name, role, and cryptographically hashed password.
    """
    email_clean = payload.email.strip().lower()
    username_clean = payload.username.strip().lower()

    # Check existing email or username
    existing_user = db.query(User).filter(
        or_(User.email == email_clean, User.username == username_clean)
    ).first()

    if existing_user:
        if existing_user.email == email_clean:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Email '{email_clean}' is already registered.",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Username '{username_clean}' is already taken.",
            )

    new_user = User(
        email=email_clean,
        username=username_clean,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name or "Forensic Investigator",
        role=payload.role or "Lead Forensic Examiner",
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = create_access_token(
        data={"sub": new_user.id, "email": new_user.email, "username": new_user.username},
        expires_delta=timedelta(days=7),
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(new_user),
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate with username/email and password",
)
def login(payload: UserLogin, db: Session = Depends(get_db)):
    """
    Authenticates investigator via username or email and validates password hash.
    Returns signed access token and user metadata.
    """
    ident = payload.username_or_email.strip().lower()

    user = db.query(User).filter(
        or_(User.email == ident, User.username == ident)
    ).first()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username/email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact system administrator.",
        )

    token = create_access_token(
        data={"sub": user.id, "email": user.email, "username": user.username},
        expires_delta=timedelta(days=7),
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get currently authenticated investigator profile",
)
def get_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """
    Validates the bearer token and returns current user account details.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token missing or invalid.",
        )

    token = authorization.split(" ")[1]
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or token invalid. Please log in again.",
        )

    user = db.query(User).filter(User.id == payload["sub"]).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User account no longer exists.",
        )

    return UserResponse.model_validate(user)


@router.get(
    "/users",
    response_model=List[UserResponse],
    summary="List all registered investigator accounts (for administrative & temporary use verification)",
)
def list_registered_users(db: Session = Depends(get_db)):
    """
    Lists all registered accounts stored in database.db.
    Useful for noting down temporary test emails and managing normal use cases.
    """
    users = db.query(User).order_by(User.created_at.asc()).all()
    return [UserResponse.model_validate(u) for u in users]

