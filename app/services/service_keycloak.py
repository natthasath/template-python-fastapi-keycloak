import httpx
from decouple import config
from fastapi import HTTPException

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

    async def exchange_code_for_token(self, code: str):
        """Exchange authorization code for access and refresh tokens."""
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

    async def refresh_access_token(self, refresh_token: str):
        """Refresh access token using refresh token."""
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

    async def logout_user(self, refresh_token: str):
        """Logout user by revoking refresh token."""
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
