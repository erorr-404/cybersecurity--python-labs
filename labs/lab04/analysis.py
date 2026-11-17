# Перевірка даних і правило варіанта

from dataclasses import dataclass
from typing import Literal, Annotated
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, BeforeValidator
from labs.lab04.utils import error, debug


def validate_optional_string(value):
    if value is None:
        raise ValueError("Field cannot be null.")

    if not isinstance(value, str) or not value.strip():
        raise ValueError("Field must be a non-empty string.")

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

    baseSeverity: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    attackVector: Literal["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"] | None = (
        None
    )
    attackComplexity: Literal["LOW", "HIGH"] | None = None
    privilegesRequired: Annotated[
        Literal["NONE", "LOW", "HIGH"] | None, BeforeValidator(validate_optional_string)
    ] = None
    userInteraction: Literal["NONE", "REQUIRED"] | None = None
    scope: Literal["UNCHANGED", "CHANGED"] | None = None

    confidentialityImpact: Literal["NONE", "LOW", "HIGH"] | None = None
    integrityImpact: Literal["NONE", "LOW", "HIGH"] | None = None
    availabilityImpact: Literal["NONE", "LOW", "HIGH"] | None = None


class CVSSMetricV31(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    source: OptionalNonEmptyString = None
    type: Literal["Primary", "Secondary"] | None = None
    cvssData: CVSSDataV31
    exploitabilityScore: float | None = None
    impactScore: float | None = None


class CVSSMetrics(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    cvss_metric_v31: list[dict] | None = Field(default=None, alias="cvssMetricV31")


class CVEDescription(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    lang: str
    value: str


class CVE(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    id: str
    vuln_status: Annotated[str, StringConstraints(min_length=1, strict=True)] | None = (
        Field(default=None, alias="vulnStatus")
    )
    descriptions: list[CVEDescription] | None = None
    metrics: CVSSMetrics | None = None


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


def extract_payload(payload: dict, cve_id: str) -> ExtractionResult | None:

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

    if (status is None) or (status == "Rejected"):
        return ExtractionResult(vuln_status=status, description=selected_description)

    # * METRIC

    selected_metric_raw: dict | None = None

    # no cvss_metric_v31 metric at all
    if cve.metrics is None or cve.metrics.cvss_metric_v31 is None:
        return ExtractionResult(vuln_status=status, description=selected_description)

    # no cvss_metric_v31 metric
    if len(cve.metrics.cvss_metric_v31) == 0:
        return ExtractionResult(vuln_status=status, description=selected_description)

    # finding primary metric
    for metric in cve.metrics.cvss_metric_v31:
        if metric.get("type") == "Primary":
            selected_metric_raw = metric
            break

    # choose first available if no primary
    if selected_metric_raw is None:
        selected_metric_raw = cve.metrics.cvss_metric_v31[0]

    selected_metric = CVSSMetricV31.model_validate(selected_metric_raw)

    return ExtractionResult(
        vuln_status=status,
        description=selected_description,
        metric=selected_metric,
    )


def build_report(record: ExtractionResult | None, cve_id: str, variant: int):

    if variant != 3:
        error("Wrong variant.")

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
