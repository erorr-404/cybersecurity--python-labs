# pydantic-моделі запитів та відповідей
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

import labs.lab03.config as cfg


class CategoryCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: str = Field(min_length=2, max_length=40)


class CategoryRead(CategoryCreate):
    id: int = Field(gt=0)


class RecordCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    code: str = Field(min_length=3, max_length=40)
    title: str = Field(min_length=3, max_length=120)
    category_id: int = Field(gt=0)
    value: float = Field(ge=cfg.value_min, le=cfg.value_max, allow_inf_nan=False)
    status: Literal["new", "in_progress", "done"]


class RecordRead(RecordCreate):
    id: int
    category_name: str


class RecordsFilter(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    category_id: int | None = Field(default=None, gt=0)
    status: Literal["new", "in_progress", "done"] | None = None
    min_value: float | None = Field(
        default=None, ge=cfg.value_min, le=cfg.value_max, allow_inf_nan=False
    )
    q: str | None = Field(default=None, min_length=3, max_length=120)
    limit: int | None = Field(default=20, gt=0, le=100)
    offset: int | None = Field(default=0, ge=0)
