from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPBearer
from app.middleware.auth import get_api_key, validate_access_token, verify_session
from app.services.service_keycloak import KeycloakService
from decouple import config

router = APIRouter(
    prefix="/keycloak",
    tags=["KEYCLOAK"],
    responses={404: {"message": "Not found"}}
)

bearer_scheme = HTTPBearer()
keycloak_service = KeycloakService()

KC_CLIENT_ID = config('KC_CLIENT_ID')
KC_ENDPOINT_URL = config('KC_ENDPOINT_URL')
KC_REDIRECT_URI = config('KC_REDIRECT_URI')

@router.get("/login")
async def login(request: Request):
    authorization_url = f"{KC_ENDPOINT_URL}/protocol/openid-connect/auth?client_id={KC_CLIENT_ID}&redirect_uri={KC_REDIRECT_URI}&response_type=code&scope=openid"
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse(content={"login_url": authorization_url})
    return RedirectResponse(authorization_url)

@router.get("/callback")
async def callback(code: str):
    token_data = await keycloak_service.exchange_code_for_token(code)
    return {
        "access_token": token_data.get("access_token"),
        "refresh_token": token_data.get("refresh_token"),
        "expires_in": token_data.get("expires_in"),
        "token_type": token_data.get("token_type"),
    }

@router.get("/protected")
async def get_credentials(user_info: dict = Depends(validate_access_token)):
    return JSONResponse(content={"message": "Access granted", "user": user_info})

@router.get("/session")
async def session_status(session_info: dict = Depends(verify_session)):
    return JSONResponse(content={"message": "Session is active", "session": session_info})

@router.post("/refresh")
async def refresh_token(refresh_token: str):
    return await keycloak_service.refresh_access_token(refresh_token)

@router.post("/logout")
async def logout(refresh_token: str):
    return await keycloak_service.logout_user(refresh_token)