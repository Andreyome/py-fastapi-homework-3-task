from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from database import UserModel

from security.passwords import hash_password

from schemas.accounts import UserRegistrationRequestSchema

from database.models.accounts import UserGroupEnum, ActivationTokenModel, PasswordResetTokenModel


async def create_user(db: AsyncSession,
                      user: UserRegistrationRequestSchema,
                      ):
    try:
        db_user = UserModel(email=user.email,
                            password=user.password,
                            group_id=2,
                            )
        db.add(db_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=db_user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(db_user)
        return db_user
    except HTTPException as e:
        await db.rollback()
        raise e


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()
