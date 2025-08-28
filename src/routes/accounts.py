from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, status, HTTPException

from fastapi.security import OAuth2PasswordBearer
from jose import ExpiredSignatureError

from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from security import token_manager

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface

from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)

from security.passwords import (
    hash_password,
    verify_password,
)

from exceptions.security import TokenExpiredError

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        result = await db.execute(select(UserModel).where(UserModel.email == user.email))
        existing_user = result.scalars().first()
        if existing_user:
            raise HTTPException(
                status_code=409,
                detail=f"A user with this email {existing_user.email} already exists.")
        db_user = UserModel(
            email=user.email,
            group_id=2,
        )
        db_user.password = user.password

        db.add(db_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=db_user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(db_user)

        return UserRegistrationResponseSchema(id=db_user.id, email=db_user.email)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login(
        login_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    result = await db.execute(select(UserModel).where(UserModel.email == login_data.email))
    db_user = result.scalars().first()
    if not db_user or not db_user.verify_password(login_data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")
    access_token = jwt_manager.create_access_token(
        data={"user_id": db_user.id}, expires_delta=timedelta(days=1)
    )
    refresh_token = jwt_manager.create_refresh_token(
        data={"user_id": db_user.id}
    )

    try:
        db_refresh = RefreshTokenModel(
            user=db_user,
            token=refresh_token
        )
        db.add(db_refresh)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )


@router.post("/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def activate_account(
        activation_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(UserModel).where(UserModel.email == activation_data.email))
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=" Invalid email or token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    result = await db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == user.id,
            ActivationTokenModel.token == activation_data.token
        )
    )
    token = result.scalars().first()

    if not token or token.expires_at < datetime.now():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    new_refresh_token = RefreshTokenModel(user_id=user.id)
    db.add(new_refresh_token)

    user.is_active = True
    try:
        await db.delete(token)

        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to activate user.")
    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def request_password_reset(
        reset_data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    response = {"message": "If you are registered, you will receive an email with instructions."}

    result = await db.execute(select(UserModel).where(UserModel.email == reset_data.email))
    user = result.scalars().first()

    if user and user.is_active:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))

        new_token = PasswordResetTokenModel(user_id=user.id)
        try:
            db.add(new_token)
            await db.commit()
        except SQLAlchemyError:
            await db.rollback()
            raise HTTPException(status_code=500, detail="Failed to activate user.")
    return response


@router.post("/reset-password/complete/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def request_password_reset_complete(
        reset_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(UserModel).where(UserModel.email == reset_data.email))
    user = result.scalars().first()

    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    token_result = await db.execute(
        select(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.user_id == user.id)
        .where(PasswordResetTokenModel.token == reset_data.token)
    )
    token = token_result.scalars().first()
    if not token or token.expires_at < datetime.now():
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    try:
        user.password = reset_data.password
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))

        await db.commit()
        await db.refresh(user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")
    return MessageResponseSchema(message="Password reset successfully.")


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
async def refresh_access_token(
        token_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    result = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == token_data.refresh_token)
    )
    refresh_token_entry = result.scalars().first()

    try:
        jwt_manager.decode_refresh_token(token_data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired.")
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid refresh token.")
    if not refresh_token_entry:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )
    result = await db.execute(
        select(UserModel).where(UserModel.id == refresh_token_entry.user_id)
    )
    user = result.scalars().first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    new_access_token = jwt_manager.create_access_token({"user_id": user.id})

    return TokenRefreshResponseSchema(access_token=new_access_token)
