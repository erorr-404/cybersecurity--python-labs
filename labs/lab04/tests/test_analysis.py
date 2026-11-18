import pytest

from labs.lab04 import analysis


# ? Фікстура для підробки відповіді сервера
@pytest.fixture
def cve_payload():
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-12345",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {"lang": "en", "value": "Test description"},
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "first@example.com",
                                "type": "Secondary",
                                "cvssData": {
                                    "baseScore": 2.0,
                                    "privilegesRequired": "NONE",
                                },
                            },
                            {
                                "source": "second@example.com",
                                "type": "Secondary",
                                "cvssData": {
                                    "baseScore": 9.0,
                                    "privilegesRequired": "LOW",
                                },
                            },
                        ],
                    },
                },
            },
        ],
    }


# ? Перевірка, чи дійсно метрика із type=Primary має пріоритет над type=Secondary
def test_primary_has_priority_over_secondary(cve_payload):
    cve = cve_payload["vulnerabilities"][0]["cve"]
    metrics = cve["metrics"]["cvssMetricV31"]
    metrics[1]["type"] = "Primary"

    result = analysis.extract_record(cve_payload, cve["id"])

    assert result is not None
    assert result.metric is not None
    assert result.metric.source == "second@example.com"
    assert result.metric.cvssData.baseScore == 9.0


# ? Перевірка коректного вибору метрики, коли немає метрики із type=Primary
def test_extract_record_uses_first_metric_without_primary(cve_payload):
    cve = cve_payload["vulnerabilities"][0]["cve"]

    result = analysis.extract_record(cve_payload, cve["id"])

    assert result is not None
    assert result.metric is not None
    assert result.metric.source == "first@example.com"
    assert result.metric.cvssData.baseScore == 2.0


# ? Функція повинна повертати None, якщо дана CVE не знайдена
def test_extract_record_returns_none_when_record_not_found():
    result = analysis.extract_record({"vulnerabilities": []}, "CVE-2026-12345")

    assert result is None


# ? Для статусу Rejected збережіть доступні статус і опис та сформуйте rejected без аналізу оцінок
def test_extract_record_skips_metrics_for_rejected_record(cve_payload):
    cve = cve_payload["vulnerabilities"][0]["cve"]
    cve["vulnStatus"] = "Rejected"
    cve["metrics"] = "invalid metrics"

    result = analysis.extract_record(cve_payload, cve["id"])

    assert result == analysis.ExtractionResult(
        vuln_status="Rejected",
        description="Test description",
        metric=None,
    )


# ? Параметризований тест для перевірки обробки ситуацій, коли метрики (cve.metrics.cvssMetricV31) відсутні
@pytest.mark.parametrize(
    "metrics",
    [None, {}, {"cvssMetricV31": []}],
    ids=["missing-metrics", "missing-cvss-v31", "empty-cvss-v31"],
)
def test_extract_record_returns_record_without_metric(cve_payload, metrics):
    cve = cve_payload["vulnerabilities"][0]["cve"]
    if metrics is None:
        del cve["metrics"]
    else:
        cve["metrics"] = metrics

    result = analysis.extract_record(cve_payload, cve["id"])

    assert result == analysis.ExtractionResult(
        vuln_status="Analyzed",
        description="Test description",
        metric=None,
    )


# ? За відсутності metrics.cvssMetricV31.cvssData.privilegesRequired звіт має формуватися із privilegesRequired=None
def test_extract_record_accepts_missing_privileges_required(cve_payload):
    cve = cve_payload["vulnerabilities"][0]["cve"]
    cvss_data = cve["metrics"]["cvssMetricV31"][0]["cvssData"]
    del cvss_data["privilegesRequired"]

    result = analysis.extract_record(cve_payload, cve["id"])

    assert result is not None
    assert result.metric is not None
    assert result.metric.cvssData.privilegesRequired is None


# ? Параметризований тест для перевірки валідації privilegesRequired
@pytest.mark.parametrize(
    "invalid_value",
    [42, "ADMIN", None],
    ids=["wrong-type", "unknown-value", "null"],
)
def test_extract_record_rejects_invalid_privileges_required(cve_payload, invalid_value):
    from pydantic import ValidationError

    cve = cve_payload["vulnerabilities"][0]["cve"]
    cvss_data = cve["metrics"]["cvssMetricV31"][0]["cvssData"]
    cvss_data["privilegesRequired"] = invalid_value

    with pytest.raises(ValidationError) as exc_info:
        analysis.extract_record(cve_payload, cve["id"])

    assert exc_info.value.errors()[0]["loc"] == (
        "cvssData",
        "privilegesRequired",
    )


# ? Параметризований тест для перевірки коректності логіки визначення decision
@pytest.mark.parametrize(
    ("score", "privileges_required", "expected_decision"),
    [
        pytest.param(6.9, "NONE", "other", id="below-threshold"),
        pytest.param(7.0, "NONE", "review", id="at-threshold"),
        pytest.param(7.1, "NONE", "review", id="above-threshold"),
        pytest.param(9.0, "LOW", "other", id="high-score-wrong-privileges"),
    ],
)
def test_build_report_decision(score, privileges_required, expected_decision):
    cve_id = "CVE-2026-12345"
    record = analysis.ExtractionResult(
        vuln_status="Analyzed",
        metric=analysis.CVSSMetricV31(
            cvssData=analysis.CVSSDataV31(
                baseScore=score,
                privilegesRequired=privileges_required,
            ),
        ),
    )

    report = analysis.build_report(record, cve_id, variant=3)

    assert report["decision"] == expected_decision
