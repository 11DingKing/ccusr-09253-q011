"""服务端业务模块。"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Plan(Base):
    __tablename__ = "plans"

    plan_version: Mapped[str] = mapped_column(String(128), primary_key=True)
    iana_timezone: Mapped[str] = mapped_column(String(64), nullable=False)
    required_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    __table_args__ = (
        CheckConstraint("required_seconds >= 0", name="ck_plans_required_nonneg"),
    )


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    plan_version: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    student_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("event_id", "plan_version", name="uq_events_event_id_plan"),
        Index("ix_events_plan_student", "plan_version", "student_id"),
    )


class Freeze(Base):
    __tablename__ = "freezes"

    plan_version: Mapped[str] = mapped_column(String(128), primary_key=True)
    freeze_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    snapshot: Mapped[dict] = mapped_column(JSON, nullable=False)
    event_cutoff_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )


class AccessActor(Base):
    """访问主体：机构 + 角色决定基线可见范围。"""

    __tablename__ = "access_actors"

    actor_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    institution_id: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )


class StudentEnrollment(Base):
    """学生与机构/培养方案的归属关系。"""

    __tablename__ = "student_enrollments"

    student_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    plan_version: Mapped[str] = mapped_column(String(128), primary_key=True)
    institution_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )


class MentorAssignmentRow(Base):
    """导师与学生的一对一指导关系（可停用）。"""

    __tablename__ = "mentor_assignment_rows"

    mentor_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    student_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )

    __table_args__ = (
        Index("ix_mentor_assignment_rows_student", "student_id"),
    )


class AccessGrant(Base):
    """字段级访问授权：在基线角色之上追加敏感字段。"""

    __tablename__ = "access_grants"

    grant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    scope_type: Mapped[str] = mapped_column(String(16), nullable=False)
    scope_value: Mapped[str] = mapped_column(String(128), nullable=False)
    fields: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    delegated_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "scope_type IN ('institution', 'plan', 'student')",
            name="ck_access_grants_scope_type",
        ),
        CheckConstraint(
            "status IN ('active', 'revoked')", name="ck_access_grants_status"
        ),
    )


class AccessGrantEvent(Base):
    """授权变更的只追加日志：撤销不删除、不改写历史。"""

    __tablename__ = "access_grant_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    grant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )


class AccessLogEntry(Base):
    """受控读取的访问审计：只追加，永不更新或删除。"""

    __tablename__ = "access_log_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    plan_version: Mapped[str] = mapped_column(String(128), nullable=False)
    student_id: Mapped[str] = mapped_column(String(128), nullable=False)
    freeze_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    visible_fields: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    redacted_fields: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )

    __table_args__ = (
        Index("ix_access_log_plan_student", "plan_version", "student_id"),
    )
