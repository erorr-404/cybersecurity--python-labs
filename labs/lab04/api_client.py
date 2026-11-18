# Заголовки та один GET-запит
import os

import requests

from labs.lab04.utils import debug

ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_api_key():
    """Retrieve the NVD API key from the ``NVD_API_KEY`` environment variable.

    Returns:
        str | None: The stripped API key, or ``None`` when it is unavailable.
    """
    api_key = os.getenv("NVD_API_KEY", "").strip() or None

    if api_key:
        debug("Found API key in environment variables.")
    else:
        debug("API key was not found. Running anonymously. ")

    return api_key


def build_headers():
    """Build HTTP headers for requests to the NVD API.

    Returns:
        dict: JSON accept header and, when available, the NVD API key.
    """
    api_key = get_api_key()
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    return headers


def fetch_response(cve: str) -> dict:
    """Fetch CVE details from the NVD API.

    Args:
        cve: The CVE identifier to query.

    Returns:
        The decoded JSON response from the NVD API.

    Raises:
        requests.RequestException: If the request fails.
        ValueError: If the response has an unexpected HTTP status code.
    """

    response = requests.get(
        ENDPOINT,
        headers=build_headers(),
        params={"cveId": cve},
        timeout=(3.05, 10),
        allow_redirects=False,
    )

    response.raise_for_status()

    if response.status_code != 200:
        raise ValueError(f"Unexpected HTTP status code: {response.status_code}")

    debug("Request completed with status code:", str(response.status_code))
    return response.json()
