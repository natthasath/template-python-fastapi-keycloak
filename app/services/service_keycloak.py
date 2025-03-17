import httpx
from fastapi import HTTPException, Security, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, RedirectResponse
from decouple import config

class KeycloakService:
    def __init__(self):
        self.client_id = config('KC_CLIENT_ID')
        self.client_secret = config('KC_CLIENT_SECRET')
        self.endpoint_url = config('KC_ENDPOINT_URL')
        self.redirect_uri = config('KC_REDIRECT_URI')
        self.logout_redirect_uri = config('KC_LOGOUT_REDIRECT_URI')
        self.logout_endpoint = f"{self.endpoint_url}/protocol/openid-connect/logout"
        self.userinfo_endpoint = f"{self.endpoint_url}/protocol/openid-connect/userinfo"
        self.token_url = f"{self.endpoint_url}/protocol/openid-connect/token"
        self.introspection_url = f"{self.endpoint_url}/protocol/openid-connect/token/introspect"

    async def login(self, request: Request):
        authorization_url = (
            f"{self.endpoint_url}/protocol/openid-connect/auth"
            f"?client_id={self.client_id}&redirect_uri={self.redirect_uri}"
            f"&response_type=code&scope=openid"
        )

        if "application/json" in request.headers.get("accept", ""):
            return JSONResponse(content={"login_url": authorization_url})

        return RedirectResponse(authorization_url)

    async def exchange_code_for_token(self, code: str):
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }

        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(self.token_url, data=data)

            if response.status_code != 200:
                raise HTTPException(status_code=400, detail="Token exchange failed")

            return response.json()
        
    async def callback(self, code: str):
        token_data = await self.exchange_code_for_token(code)
        return {
            "access_token": token_data.get("access_token"),
            "refresh_token": token_data.get("refresh_token"),
            "expires_in": token_data.get("expires_in"),
            "token_type": token_data.get("token_type"),
        }

    async def refresh_access_token(self, refresh_token: str):
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }

        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(self.token_url, data=data)
            if response.status_code != 200:
                raise HTTPException(status_code=400, detail="Refresh token failed")

            return response.json()

    async def logout(self, refresh_token: str):
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": refresh_token
        }

        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(self.logout_endpoint, data=data)

            if response.status_code != 204:
                raise HTTPException(status_code=400, detail="Logout failed")

            return {"message": "Logged out successfully"}

    async def validate_access_token(self, credentials: HTTPAuthorizationCredentials = Security(HTTPBearer())):
        token = credentials.credentials
        headers = {"Authorization": f"Bearer {token}"}

        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(self.userinfo_endpoint, headers=headers)

            if response.status_code != 200:
                print(f"Invalid token: {response.json()}")
                raise HTTPException(status_code=401, detail="Invalid or expired token")

            return response.json()

    async def verify_session(self, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
        token = credentials.credentials
        data = {
            "token": token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(self.introspection_url, data=data, headers=headers)

            if response.status_code != 200 or not response.json().get("active", False):
                raise HTTPException(status_code=401, detail="Session expired or invalid")

            return response.json()