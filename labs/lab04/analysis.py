# Перевірка даних і правило варіанта

from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field


def validate_optional_string(value):
    if value is None:
        raise ValueError("Field cannot be null.")

    if not isinstance(value, str) or not value.strip():
        raise ValueError("Field must be a non-empty string.")

    return value


def not_null(value):
    if value is None:
        raise ValueError("Explicit null is not allowed.")
    return value


OptionalNonEmptyString = Annotated[
    str | None, BeforeValidator(validate_optional_string)
]


class CVSSDataV31(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    # поле відсутнє: залишається None
    # поле присутнє з null | "": ValidationError
    # поле присутнє з "3.1": приймається
    version: Annotated[
        Literal["3.1"] | None, BeforeValidator(validate_optional_string)
    ] = None

    vectorString: OptionalNonEmptyString = None
    baseScore: Annotated[float, Field(strict=True, ge=0, le=10, allow_inf_nan=False)]

    privilegesRequired: Annotated[
        Literal["NONE", "LOW", "HIGH"] | None, BeforeValidator(validate_optional_string)
    ] = None


class CVSSMetricV31(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    source: OptionalNonEmptyString = None
    cvssData: CVSSDataV31


class CVSSMetrics(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    cvss_metric_v31: Annotated[list[dict] | None, BeforeValidator(not_null)] = Field(
        default=None, alias="cvssMetricV31"
    )


class CVEDescription(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    lang: str
    value: str


class CVE(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    id: str
    vuln_status: OptionalNonEmptyString = Field(default=None, alias="vulnStatus")
    descriptions: Annotated[list[CVEDescription] | None, BeforeValidator(not_null)] = (
        Field(default=None)
    )
    metrics: object = None


class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    cve: CVE


class NVDResponse(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    vulnerabilities: list[Vulnerability]


@dataclass(frozen=True)
class ExtractionResult:
    vuln_status: str | None = None
    description: str | None = None
    metric: CVSSMetricV31 | None = None


def extract_record(payload: dict, cve_id: str) -> ExtractionResult | None:
    """Validate an NVD payload and extract the requested CVE's data.

    Args:
        payload: NVD API response represented as a dictionary.
        cve_id: CVE identifier that must match the record in ``payload``.

    Returns:
        The extracted status, English description, and selected CVSS metric,
        or ``None`` when the response contains no vulnerabilities.

    Raises:
        ValueError: If the response contains multiple vulnerabilities or the
            returned CVE identifier does not match ``cve_id``.
        pydantic.ValidationError: If the payload does not satisfy the model.
    """

    status: str | None = None
    selected_description: str | None = None
    selected_metric: CVSSMetricV31 | None = None

    payload_model: NVDResponse = NVDResponse.model_validate(payload)

    # * BASIC STRUCTURE

    # Порожній список означає, що CVE не знайдено — повернути None.
    if len(payload_model.vulnerabilities) < 1:
        return None

    if len(payload_model.vulnerabilities) > 1:
        raise ValueError("JSON filed vulnerabilities must contain only one list item.")

    cve: CVE = payload_model.vulnerabilities[0].cve

    # cve.id повинен збігатися з аргументом cve_id.
    if cve.id != cve_id:
        raise ValueError("JSON field cve.id must be equal to cve_id.")

    # * STATUS
    status = cve.vuln_status

    # * DESCRIPTION

    if cve.descriptions is not None:
        for description in cve.descriptions:
            if description.lang == "en" and description.value.strip():
                selected_description = description.value
                break

    # * REJECT STATUS

    if status is None or status == "Rejected":
        return ExtractionResult(vuln_status=status, description=selected_description)

    # * METRIC

    if "metrics" not in cve.model_fields_set:
        return ExtractionResult(vuln_status=status, description=selected_description)

    metrics = CVSSMetrics.model_validate(cve.metrics)

    selected_metric_raw: dict | None = None

    # no cvss_metric_v31 metric at all
    if metrics is None or metrics.cvss_metric_v31 is None:
        return ExtractionResult(vuln_status=status, description=selected_description)

    # no cvss_metric_v31 metric
    if len(metrics.cvss_metric_v31) == 0:
        return ExtractionResult(vuln_status=status, description=selected_description)

    # finding primary metric
    for metric in metrics.cvss_metric_v31:
        if metric.get("type") == "Primary":
            selected_metric_raw = metric
            break

    # choose first available if no primary
    if selected_metric_raw is None:
        selected_metric_raw = metrics.cvss_metric_v31[0]

    selected_metric = CVSSMetricV31.model_validate(selected_metric_raw)

    return ExtractionResult(
        vuln_status=status,
        description=selected_description,
        metric=selected_metric,
    )


def build_report(record: ExtractionResult | None, cve_id: str, variant: int):
    """Build a structured vulnerability report for the requested CVE variant.

    Args:
        record: Extracted CVE data, or ``None`` if the record was not found.
        cve_id: CVE identifier to include in the report.
        variant: Report variant to build; currently only variant 3 is supported.

    Returns:
        A dictionary containing the report data and evaluation decision.

    Raises:
        ValueError: If ``variant`` is not supported.
    """

    if variant != 3:
        raise ValueError("Unsupported variant.")

    result: dict = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {"threshold": 7.0, "field": "privilegesRequired", "expected": "NONE"},
        "observed": None,
        "decision": "other",
    }

    # Запис не знайдено
    if record is None:
        result["decision"] = "not_found"
        return result

    result["vuln_status"] = record.vuln_status
    result["description"] = record.description

    # vulnStatus дорівнює Rejected
    if record.vuln_status == "Rejected":
        result["decision"] = "rejected"
        return result

    # Статус відсутній
    if record.vuln_status is None:
        result["decision"] = "insufficient_data"
        return result

    if record.metric is None:
        result["decision"] = "insufficient_data"
        return result

    cvss_data: CVSSDataV31 = record.metric.cvssData

    result["cvss_version"] = cvss_data.version
    result["score"] = cvss_data.baseScore
    result["score_source"] = record.metric.source
    result["vector"] = cvss_data.vectorString

    required_attr = getattr(cvss_data, result["rule"]["field"])

    # потрібного поля варіанта немає
    if required_attr is None:
        result["decision"] = "insufficient_data"
        return result

    result["observed"] = required_attr

    # Оцінка не менша за поріг і водночас потрібне поле дорівнює заданому значенню
    if (
        required_attr == result["rule"]["expected"]
        and cvss_data.baseScore >= result["rule"]["threshold"]
    ):
        result["decision"] = "review"

    else:
        result["decision"] = "other"

    return result
