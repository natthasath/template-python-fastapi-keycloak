from decouple import config

from fastapi.security.api_key import APIKeyHeader
from fastapi import Depends, Security, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.status import HTTP_403_FORBIDDEN
import httpx
import requests

bearer_scheme = HTTPBearer(auto_error=True)
api_key_header = APIKeyHeader(name="access_token", auto_error=False)

KC_ENDPOINT_URL = config("KC_ENDPOINT_URL")
KC_CLIENT_ID = config("KC_CLIENT_ID")
KC_CLIENT_SECRET = config("KC_CLIENT_SECRET")
KC_USERINFO_ENDPOINT = f"{config('KC_ENDPOINT_URL')}/protocol/openid-connect/userinfo"

async def get_api_key(api_key_header: str = Security(api_key_header)):
    if api_key_header == config("API_KEY"):
        return api_key_header   
    else:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN, detail="Could not validate API KEY"
        )

async def validate_access_token(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)):
    token = credentials.credentials
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.get(KC_USERINFO_ENDPOINT, headers=headers, timeout=5, verify=False)
        if response.status_code != 200:
            print(f"Invalid token: {response.json()}")
            raise HTTPException(status_code=401, detail="Invalid or expired token")
    except requests.exceptions.RequestException as e:
        print(f"Keycloak request failed: {e}")
        raise HTTPException(status_code=500, detail="Authentication service unavailable")

    return response.json()

async def verify_session(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    token = credentials.credentials
    introspection_url = f"{KC_ENDPOINT_URL}/protocol/openid-connect/token/introspect"
    data = {
        "token": token,
        "client_id": KC_CLIENT_ID,
        "client_secret": KC_CLIENT_SECRET,
    }
    
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    
    async with httpx.AsyncClient(verify=False) as client:
        response = await client.post(introspection_url, data=data, headers=headers)

        if response.status_code != 200 or not response.json().get("active", False):
            raise HTTPException(status_code=401, detail="Session expired or invalid")

        return response.json()