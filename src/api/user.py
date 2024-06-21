from fastapi import APIRouter, Depends, HTTPException

from database.orm import User
from database.repository import UserRepository
from schema.request import SignInRequest, SignUpRequest
from schema.response import JWTSchema, UserSchema
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
