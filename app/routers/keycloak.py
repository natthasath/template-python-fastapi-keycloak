from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse
from fastapi.security.api_key import APIKey
from fastapi.params import Security
from app.middleware.auth import get_api_key
from app.services.service_keycloak import KeycloakService

router = APIRouter(
    prefix="/keycloak",
    tags=["KEYCLOAK"],
    responses={404: {"message": "Not found"}}
    # dependencies=[Security(get_api_key)]
)

keycloak_service = KeycloakService()

@router.get("/login")
async def login(request: Request):
    return await keycloak_service.login(request)

@router.get("/callback")
async def callback(code: str):
    return await keycloak_service.callback(code)

@router.get("/protected")
async def get_credentials(user_info: dict = Depends(keycloak_service.validate_access_token)):
    return JSONResponse(content={"message": "Access granted", "user": user_info})

@router.get("/session")
async def session_status(session_info: dict = Depends(keycloak_service.verify_session)):
    return JSONResponse(content={"message": "Session is active", "session": session_info})

@router.post("/refresh")
async def refresh_token(refresh_token: str):
    return await keycloak_service.refresh_access_token(refresh_token)

@router.post("/logout")
async def logout(refresh_token: str):
    return await keycloak_service.logout(refresh_token)