import base64
import secrets
import json
import hashlib
import asyncio

from fastapi.responses import HTMLResponse
import httpx
from integrations.integration_item import IntegrationItem
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis

from fastapi import HTTPException, Request

# add your own keys
APP_ID = 00000
CLIENT_ID = "xxxx"
CLIENT_SECRET = "xxxx"
REDIRECT_URI = "http://localhost:8000/integrations/hubspot/oauth2callback"
SCOPE = "cms.domains:read cms.domains:write crm.lists:read crm.lists:write crm.objects.contacts:read oauth"
TOKEN_URL = "https://api.hubapi.com/oauth/v1/token"
AUTHORIZATION_URL = f"xxxx"
encoded_client_id_secret = base64.b64encode(
    f"{CLIENT_ID}:{CLIENT_SECRET}".encode()
).decode()


async def authorize_hubspot(user_id, org_id):
    state_data = {
        "state": secrets.token_urlsafe(32),
        "user_id": user_id,
        "org_id": org_id,
    }
    encoded_state = base64.urlsafe_b64encode(
        json.dumps(state_data).encode("utf-8")
    ).decode("utf-8")
    code_verifier = secrets.token_urlsafe(32)
    hash = hashlib.sha256()
    hash.update(code_verifier.encode("utf-8"))
    code_challenge = (
        base64.urlsafe_b64encode(hash.digest()).decode("utf-8").replace("=", "")
    )

    auth_url = (
        f"{AUTHORIZATION_URL}&state={encoded_state}&code_challenge={code_challenge}"
    )
    await asyncio.gather(
        add_key_value_redis(
            f"hubspot_state:{org_id}:{user_id}", json.dumps(state_data), expire=250
        ),
        add_key_value_redis(
            f"hubspot_verifier:{org_id}:{user_id}", code_verifier, expire=250
        ),
    )
    return auth_url


async def oauth2callback_hubspot(request: Request):
    if request.query_params.get("error"):
        raise HTTPException(
            status_code=400, detail=request.query_params.get("error_description")
        )
    authorization_code = request.query_params.get("code")
    encoded_state = request.query_params.get("state")
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode("utf-8"))

    original_state = state_data.get("state")
    user_id = state_data.get("user_id")
    org_id = state_data.get("org_id")

    saved_state, code_verifier = await asyncio.gather(
        get_value_redis(f"hubspot_state:{org_id}:{user_id}"),
        get_value_redis(f"hubspot_verifier:{org_id}:{user_id}"),
    )

    if not saved_state or original_state != json.loads(saved_state).get("state"):
        raise HTTPException(status_code=400, detail="State does not match.")

    async with httpx.AsyncClient() as client:
        response, _, _ = await asyncio.gather(
            client.post(
                TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "code": authorization_code,
                    "redirect_uri": REDIRECT_URI,
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                },
                headers={
                    "Authorization": f"Basic {encoded_client_id_secret}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            ),
            delete_key_redis(f"hubspot_state:{org_id}:{user_id}"),
            delete_key_redis(f"hubspot_verifier:{org_id}:{user_id}"),
        )
    await add_key_value_redis(
        f"hubspot_credentials:{org_id}:{user_id}",
        json.dumps(response.json()),
        expire=250,
    )

    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """

    return HTMLResponse(content=close_window_script)


async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f"hubspot_credentials:{org_id}:{user_id}")
    if not credentials:
        raise HTTPException(status_code=400, detail="No credentials found.")
    credentials = json.loads(credentials)
    await delete_key_redis(f"hubspot_credentials:{org_id}:{user_id}")

    return credentials


def create_integration_item_metadata_object(response) -> IntegrationItem:
    identity = response.get("id")
    url = response.get("domain")
    creation_time = response.get("createdAt")
    last_modified_time = response.get("updatedAt")
    name = response.get("expectedCname")

    integration_item_metadata = IntegrationItem(
        id=identity,
        url=url,
        creation_time=creation_time,
        last_modified_time=last_modified_time,
        name=name,
    )
    return integration_item_metadata


async def get_items_hubspot(credentials) -> list[IntegrationItem]:
    if not credentials:
        raise HTTPException(status_code=400, detail="No credentials found.")
    integration_item_list = []
    credentials = json.loads(credentials)
    token = credentials.get("access_token")

    cms_endpoint = "https://api.hubspot.com/cms/v3/domains"
    crs_endpoint = "https://api.hubspot.com/crm/v3/lists"
    access_token_endpoint = f"https://api.hubapi.com/oauth/v1/access-tokens/{token}"

    async with httpx.AsyncClient() as client:
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        response = await client.get(cms_endpoint, headers=headers)
        response = response.json()

        for result in response.get("results"):
            integration_item_list.append(
                create_integration_item_metadata_object(result)
            )

        # printing the results
        for item in integration_item_list:
            print(item.to_dict())
    return integration_item_list
