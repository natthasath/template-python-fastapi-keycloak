from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security.api_key import APIKey
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.params import Security
from decouple import config
from app.middleware.auth import get_api_key, validate_access_token, verify_session
import httpx

router = APIRouter(
    prefix="/keycloak",
    tags=["KEYCLOAK"],
    responses={404: {"message": "Not found"}},
    # dependencies=[Security(get_api_key)]
)

KC_CLIENT_ID = config('KC_CLIENT_ID')
KC_CLIENT_SECRET = config('KC_CLIENT_SECRET')
KC_ENDPOINT_URL = config('KC_ENDPOINT_URL')
KC_REDIRECT_URI = config('KC_REDIRECT_URI')
KC_LOGOUT_REDIRECT_URI = config('KC_LOGOUT_REDIRECT_URI')
KC_LOGOUT_ENDPOINT = f"{KC_ENDPOINT_URL}/protocol/openid-connect/logout"
KC_USERINFO_ENDPOINT = f"{KC_ENDPOINT_URL}/protocol/openid-connect/userinfo"

bearer_scheme = HTTPBearer()

@router.get("/login")
async def login(request: Request):
    authorization_url = f"{KC_ENDPOINT_URL}/protocol/openid-connect/auth?client_id={KC_CLIENT_ID}&redirect_uri={KC_REDIRECT_URI}&response_type=code&scope=openid"
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse(content={"login_url": authorization_url})
    return RedirectResponse(authorization_url)

@router.get("/callback")
async def callback(code: str):
    token_url = f"{KC_ENDPOINT_URL}/protocol/openid-connect/token"
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": KC_REDIRECT_URI,
        "client_id": KC_CLIENT_ID,
        "client_secret": KC_CLIENT_SECRET
    }
    
    async with httpx.AsyncClient(verify=False) as client:
        response = await client.post(token_url, data=data)
        
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Token exchange failed")
        
        token_data = response.json()
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
    token_url = f"{KC_ENDPOINT_URL}/protocol/openid-connect/token"
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": KC_CLIENT_ID,
        "client_secret": KC_CLIENT_SECRET
    }

    async with httpx.AsyncClient(verify=False) as client:
        response = await client.post(token_url, data=data)
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Refresh token failed")

        return response.json()
    
@router.post("/logout")
async def logout(refresh_token: str):
    revoke_url = f"{KC_ENDPOINT_URL}/protocol/openid-connect/logout"
    data = {
        "client_id": KC_CLIENT_ID,
        "client_secret": KC_CLIENT_SECRET,
        "refresh_token": refresh_token
    }

    async with httpx.AsyncClient(verify=False) as client:
        response = await client.post(revoke_url, data=data)

        if response.status_code != 204:
            raise HTTPException(status_code=400, detail="Logout failed")

        return {"message": "Logged out successfully"}
