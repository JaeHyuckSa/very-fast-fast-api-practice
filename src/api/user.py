from fastapi import APIRouter, Depends, HTTPException

from cache import redis_client
from database.orm import User
from database.repository import UserRepository
from schema.request import (
    CreateOTPRquest,
    SignInRequest,
    SignUpRequest,
    VerifyOTPRquest,
)
from schema.response import JWTSchema, UserSchema
from security import get_access_token
from service.user import UserService

router = APIRouter(prefix="/user")


@router.post("/sign-up", status_code=201)
def user_sign_up_handler(
    request: SignUpRequest,
    user_service: UserService = Depends(),
    user_repo: UserRepository = Depends(),
):
    hashed_password: str = user_service.hash_password(plain_password=request.password)

    user: User = User.create(
        username=request.username,
        hashed_password=hashed_password,
    )
    user: User = user_repo.save_user(user=user)

    return UserSchema.from_orm(user)


@router.post("/sign-in")
def user_sign_in_handler(
    request: SignInRequest,
    user_service: UserService = Depends(),
    user_repo: UserRepository = Depends(),
):
    user: User | None = user_repo.get_user_by_username(username=request.username)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    verified: bool = user_service.verify_password(
        plain_password=request.password,
        hashed_password=user.password,
    )

    if not verified:
        raise HTTPException(status_code=401, detail="Not Authorized")

    access_token: str = user_service.create_jwt(username=user.username)

    return JWTSchema(access_token=access_token)


@router.post("/email/otp")
def create_otp_handler(
    request: CreateOTPRquest,
    _: str = Depends(get_access_token),
    user_service: UserService = Depends(),
):

    otp: int = user_service.create_otp()

    redis_client.set(name=request.email, value=otp)
    redis_client.expire(name=request.email, time=300)
    return {"otp": otp}


@router.post("/email/otp/verify")
def verify_otp_handler(
    request: VerifyOTPRquest,
    access_token: str = Depends(get_access_token),
    user_service: UserService = Depends(),
    user_repo: UserRepository = Depends(),
):
    otp: str | None = redis_client.get(name=request.email)
    if not otp:
        raise HTTPException(status_code=400, detail="Bad Request")

    if request.otp != int(otp):
        raise HTTPException(status_code=400, detail="Bad Request")

    username: str = user_service.decode_jwt(access_token)
    user: User | None = user_repo.get_user_by_username(username=username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return UserSchema.from_orm(user)
