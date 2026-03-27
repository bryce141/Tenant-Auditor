import msal
import os
from dotenv import load_dotenv

load_dotenv()

SCOPE = ["https://graph.microsoft.com/.default"]


def get_token():
    # read credentials at call time so values set via the setup wizard are picked up
    tenant_id = os.getenv("TENANT_ID")
    client_id = os.getenv("CLIENT_ID")
    client_secret = os.getenv("CLIENT_SECRET")

    if not all([tenant_id, client_id, client_secret]):
        raise Exception("Tenant credentials not configured. Visit /setup to connect your tenant.")

    authority = f"https://login.microsoftonline.com/{tenant_id}"
    app = msal.ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret,
    )
    result = app.acquire_token_for_client(scopes=SCOPE)
    if "access_token" in result:
        return result["access_token"]
    raise Exception(f"Auth failed: {result.get('error_description')}")
