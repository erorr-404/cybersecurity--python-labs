import json

import pytest

from labs.lab04 import main as cli

CVE_ID = "CVE-2026-12345"


# ? Фікстура для підробки номеру варіанту та заборони виклику api_client.fetch_response
@pytest.fixture(autouse=True)
def local_cli(monkeypatch):
    monkeypatch.setattr(cli.student, "VARIANT_NUMBER", 3)

    def unexpected_fetch(cve_id):
        pytest.fail(f"Unexpected NVD request for {cve_id}")

    monkeypatch.setattr(cli.api_client, "fetch_response", unexpected_fetch)


# ? Перевірки виводу звіту, отриманого із аналізу файлу
def test_local_json_prints_report(tmp_path, capsys):
    input_file = tmp_path / "response.json"
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": CVE_ID,
                    "vulnStatus": "Analyzed",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "type": "Primary",
                                "cvssData": {
                                    "baseScore": 8.0,
                                    "privilegesRequired": "NONE",
                                },
                            },
                        ],
                    },
                },
            },
        ],
    }
    input_file.write_text(json.dumps(payload), encoding="utf-8")

    assert cli.main(["--cve", CVE_ID, "--input", str(input_file)]) == 0

    output = capsys.readouterr()
    report = json.loads(output.out)
    assert report["cve_id"] == CVE_ID
    assert report["score"] == 8.0
    assert report["decision"] == "review"
    assert output.err == ""


# ? Параметризований тест, який перевіряє правильну обробку помилок, пов'язаних із роботою з файлами
@pytest.mark.parametrize(
    ("file_contents", "expected_message"),
    [
        pytest.param("{", "Invalid JSON format.", id="invalid-json"),
        pytest.param(None, "File does not exist.", id="missing-file"),
    ],
)
def test_local_input_error(tmp_path, capsys, file_contents, expected_message):
    input_file = tmp_path / "response.json"
    if file_contents is not None:
        input_file.write_text(file_contents, encoding="utf-8")

    assert cli.main(["--cve", CVE_ID, "--input", str(input_file)]) == 1

    output = capsys.readouterr()
    assert output.out == ""
    assert output.err.strip() == expected_message
