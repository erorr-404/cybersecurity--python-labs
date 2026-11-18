# Заголовки та один GET-запит
import requests
import os
from labs.lab04.utils import debug

ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_api_key():
    api_key = os.getenv("NVD_API_KEY", "").strip() or None

    if api_key:
        debug("Found API key in environment variables.")
    else:
        debug("API key was not found. Running anonymously. ")

    return api_key


def build_headers():
    api_key = get_api_key()
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    return headers


def fetch_response(cve: str) -> dict:

    response = requests.get(
        ENDPOINT,
        headers=build_headers(),
        params={"cveId": cve},
        timeout=(3.05, 10),
        allow_redirects=False,
    )

    debug("Request URL:", response.url)

    response.raise_for_status()

    if response.status_code != 200:
        raise ValueError("Unexpected HTTP status code.")

    debug("Request completed with status code:", str(response.status_code))
    return response.json()
