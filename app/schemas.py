"""服务端业务模块。"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class PlanIn(BaseModel):
    plan_version: str = Field(..., min_length=1, max_length=128)
    iana_timezone: str = Field(..., min_length=1, max_length=64)
    required_seconds: int = Field(0, ge=0)


class PlanOut(BaseModel):
    plan_version: str
    iana_timezone: str
    required_seconds: int


class CheckinPayload(BaseModel):
    activity_id: str = ""
    activity_type: str = "regular"
    check_in_at: datetime
    check_out_at: datetime

    @model_validator(mode="after")
    def _check_order(self) -> "CheckinPayload":
        if self.check_out_at <= self.check_in_at:
            raise ValueError("check_out_at must be after check_in_at")
        return self

    @field_validator("check_in_at", "check_out_at")
    @classmethod
    def _ensure_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware (RFC 3339)")
        return v


class MentorConfirmPayload(BaseModel):
    checkin_event_id: str


class LeaveCorrectionPayload(BaseModel):
    adjustment_seconds: int
    reason: str = ""


class EventIn(BaseModel):
    event_id: str = Field(..., min_length=1, max_length=128)
    event_type: Literal["checkin", "mentor_confirm", "leave_correction"]
    student_id: str = Field(..., min_length=1, max_length=128)
    payload: dict[str, Any]


class EventBatchIn(BaseModel):
    events: list[EventIn]


class EventOut(BaseModel):
    event_id: str
    plan_version: str
    event_type: str
    student_id: str
    payload: dict[str, Any]
    created_at: datetime

    model_config = {"from_attributes": True}


class ImportResult(BaseModel):
    accepted: int
    duplicates: list[str]
    rejected: list[dict[str, Any]]


class DailyTotal(BaseModel):
    academic_day: str
    seconds: int


class CheckinExplanation(BaseModel):
    event_id: str
    activity_id: str
    activity_type: str
    status: str
    counts: bool
    location: str | None = None
    mentor_comment: str | None = None
    confirmed_by: str | None = None
    check_in_at_utc: str
    check_out_at_utc: str
    raw_seconds: int
    academic_days: list[dict[str, Any]]


class AdjustmentOut(BaseModel):
    event_id: str
    seconds: int
    reason: str | None = None


class StudentProgressOut(BaseModel):
    student_id: str
    confirmed_seconds: int
    pending_seconds: int
    adjustment_seconds: int
    total_seconds: int
    lesson_units: int
    pending_lesson_units: int
    meets_requirement: bool
    daily: list[DailyTotal]
    checkins: list[CheckinExplanation]
    adjustments: list[AdjustmentOut]
    redacted_fields: list[str] = Field(default_factory=list)


class SnapshotOut(BaseModel):
    plan_version: str
    freeze_id: str | None
    timezone: str
    required_seconds: int
    generated_at: str
    event_cutoff_id: str | None
    students: list[dict[str, Any]]


class FreezeIn(BaseModel):
    pass


class DiffOut(BaseModel):
    plan_version: str
    old_freeze_id: str | None
    new_freeze_id: str | None
    old_generated_at: str
    new_generated_at: str
    old_event_cutoff_id: str | None
    new_event_cutoff_id: str | None
    student_changes: list[dict[str, Any]]
    students_affected: int


# ---------------------------------------------------------------------------
# 隐私字段分级访问
# ---------------------------------------------------------------------------


class ActorIn(BaseModel):
    role: Literal["counselor", "mentor", "auditor", "grant_admin"]
    institution_id: str = Field(..., min_length=1, max_length=128)


class ActorOut(BaseModel):
    actor_id: str
    role: str
    institution_id: str


class EnrollmentIn(BaseModel):
    institution_id: str = Field(..., min_length=1, max_length=128)


class EnrollmentOut(BaseModel):
    student_id: str
    plan_version: str
    institution_id: str


class MentorAssignmentIn(BaseModel):
    active: bool = True


class MentorAssignmentOut(BaseModel):
    mentor_id: str
    student_id: str
    active: bool


class GrantIn(BaseModel):
    grant_id: str = Field(..., min_length=1, max_length=128)
    actor_id: str = Field(..., min_length=1, max_length=128)
    scope_type: Literal["institution", "plan", "student"]
    scope_value: str = Field(..., min_length=1, max_length=128)
    fields: list[str] = Field(..., min_length=1)
    delegated_by: str | None = None
    expires_at: datetime | None = None
    reason: str = ""


class GrantRevokeIn(BaseModel):
    reason: str = ""


class GrantOut(BaseModel):
    grant_id: str
    actor_id: str
    scope_type: str
    scope_value: str
    fields: list[str]
    delegated_by: str | None
    status: str
    expires_at: str | None
    created_at: str | None
    revoked_at: str | None


class GrantEventOut(BaseModel):
    grant_id: str
    action: str
    actor_id: str
    reason: str
    occurred_at: str | None


class SimulateIn(BaseModel):
    actor_id: str = Field(..., min_length=1, max_length=128)
    plan_version: str = Field(..., min_length=1, max_length=128)
    student_id: str = Field(..., min_length=1, max_length=128)


class DecisionOut(BaseModel):
    actor_id: str
    student_id: str
    plan_version: str
    allowed: bool
    visible_fields: list[str]
    redacted_fields: list[str]
    sources: list[str]
    reason: str


class AccessLogOut(BaseModel):
    id: int
    actor_id: str
    action: str
    plan_version: str
    student_id: str
    freeze_id: str | None
    decision: str
    visible_fields: list[str]
    redacted_fields: list[str]
    occurred_at: str | None


class ExportIn(BaseModel):
    student_ids: list[str] | None = None
    freeze_id: str | None = None


class ExportOut(BaseModel):
    plan_version: str
    freeze_id: str | None
    generated_at: str
    exported_count: int
    students: list[dict[str, Any]]
