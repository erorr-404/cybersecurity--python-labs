import json

import pytest
import requests

from labs.lab04 import api_client


# ? фікстура для підробки requests.Response
@pytest.fixture
def mock_response(monkeypatch):
    response = requests.Response()
    response.url = api_client.ENDPOINT
    monkeypatch.setattr(api_client.requests, "get", lambda *args, **kwargs: response)
    return response


# ? HTTP код 404 має викликати помилку HTTPError
def test_fetch_response_404(mock_response):
    mock_response.status_code = 404
    with pytest.raises(requests.HTTPError) as exc_info:
        api_client.fetch_response("CVE-2027-12345")

    assert exc_info.value.response.status_code == 404  # type: ignore


# ? HTTP код 302 (redirect) повинен спричиняти помилку ValueError
def test_fetch_response_302(mock_response):
    mock_response.status_code = 302
    with pytest.raises(ValueError) as exc_info:
        api_client.fetch_response("CVE-2027-12345")

    assert "302" in str(exc_info.value)


# ? Перевірка коректності передачі відповіді сервера
def test_fetch_response_returns_correct_json(mock_response):
    payload = {
        "totalResults": 1,
        "vulnerabilities": [{"cve": {"id": "CVE-2021-44228"}}],
    }
    mock_response.status_code = 200
    mock_response.encoding = "utf-8"
    mock_response._content = json.dumps(payload).encode("utf-8")

    assert api_client.fetch_response("CVE-2021-44228") == payload


# ? Помилка з'єднання має викликати виняток requests.ConnectionError
def test_fetch_response_connection_error(monkeypatch):
    def fail_get(*args, **kwargs):
        raise requests.ConnectionError("Connection failed.")

    monkeypatch.setattr(api_client.requests, "get", fail_get)

    with pytest.raises(requests.ConnectionError, match="Connection failed."):
        api_client.fetch_response("CVE-2021-44228")


# ? Перевірка правильності побудови заголовків із API ключем
def test_build_headers_with_api_key(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "test-key")

    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "test-key",
    }


# ? Перевірка правильності побудови заголовків без API ключа
def test_build_headers_without_api_key():
    assert api_client.build_headers() == {"Accept": "application/json"}
