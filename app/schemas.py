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
    location: str = ""

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
    comment: str = ""


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
    location: str = ""
    mentor_comment: str = ""
    check_in_at_utc: str
    check_out_at_utc: str
    raw_seconds: int
    academic_days: list[dict[str, Any]]


class AdjustmentOut(BaseModel):
    event_id: str
    seconds: int
    reason: str


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


Role = Literal["counselor", "mentor", "auditor"]
SensitiveField = Literal["location", "reason", "mentor_comment"]


class SubjectIn(BaseModel):
    subject_id: str = Field(..., min_length=1, max_length=128)
    org_id: str = Field(..., min_length=1, max_length=128)
    role: Role
    is_active: bool = True


class SubjectOut(BaseModel):
    subject_id: str
    org_id: str
    role: str
    is_active: bool


class EnrollmentIn(BaseModel):
    student_id: str = Field(..., min_length=1, max_length=128)
    org_id: str = Field(..., min_length=1, max_length=128)


class EnrollmentOut(BaseModel):
    student_id: str
    org_id: str


class MentorRelationIn(BaseModel):
    mentor_id: str = Field(..., min_length=1, max_length=128)
    student_id: str = Field(..., min_length=1, max_length=128)


class MentorRelationOut(BaseModel):
    mentor_id: str
    student_id: str
    plan_version: str
    is_active: bool


class GrantIn(BaseModel):
    subject_id: str = Field(..., min_length=1, max_length=128)
    fields: list[SensitiveField] = Field(default_factory=list)
    student_id: str | None = Field(None, min_length=1, max_length=128)
    is_delegation: bool = False
    granted_by: str | None = Field(None, min_length=1, max_length=128)
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def _delegation_requires_actor(self) -> "GrantIn":
        if self.is_delegation and not self.granted_by:
            raise ValueError("delegation requires granted_by")
        return self


class GrantOut(BaseModel):
    grant_id: str
    subject_id: str
    plan_version: str | None
    student_id: str | None
    fields: list[str]
    is_delegation: bool
    granted_by: str | None
    is_revoked: bool
    expires_at: datetime | None
    created_at: datetime
    revoked_at: datetime | None


class GrantRevokeIn(BaseModel):
    actor_id: str = Field(..., min_length=1, max_length=128)
    reason: str = Field(..., min_length=1, max_length=512)


class SimulateIn(BaseModel):
    subject_id: str = Field(..., min_length=1, max_length=128)
    plan_version: str = Field(..., min_length=1, max_length=128)
    student_id: str = Field(..., min_length=1, max_length=128)


class SimulateOut(BaseModel):
    subject_id: str
    role: str
    org_id: str
    plan_version: str
    student_id: str
    decision: Literal["allow", "deny"]
    visible_fields: list[str]
    redacted_fields: list[str]
    reasons: list[str]


class AccessAuditOut(BaseModel):
    id: int
    occurred_at: datetime
    subject_id: str
    action: str
    plan_version: str
    student_id: str | None
    resource: str
    decision: str
    visible_fields: list[str]
    redacted_fields: list[str]
    detail: str


class ExportRequest(BaseModel):
    subject_id: str = Field(..., min_length=1, max_length=128)
    student_ids: list[str] = Field(default_factory=list)
