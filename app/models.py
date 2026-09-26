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


class AccessSubject(Base):
    """访问主体：按机构与角色登记的辅导员、导师和审计人员。"""

    __tablename__ = "access_subjects"

    subject_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "role in ('counselor','mentor','auditor')",
            name="ck_access_subjects_role",
        ),
        Index("ix_access_subjects_org_role", "org_id", "role"),
    )


class StudentEnrollment(Base):
    """学生学籍关系：学生隶属于某个机构（培养单位）。"""

    __tablename__ = "student_enrollments"

    student_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )


class MentorRelation(Base):
    """导师与学生的指导关系（限定在培养方案内）。"""

    __tablename__ = "mentor_relations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mentor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    student_id: Mapped[str] = mapped_column(String(128), nullable=False)
    plan_version: Mapped[str] = mapped_column(String(128), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "mentor_id",
            "student_id",
            "plan_version",
            name="uq_mentor_relation",
        ),
        Index("ix_mentor_relations_student", "student_id", "plan_version"),
    )


class AccessGrant(Base):
    """字段级授权与委托；撤销与过期立即影响后续读取。"""

    __tablename__ = "access_grants"

    grant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    plan_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    student_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    fields: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    is_delegation: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    granted_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    is_revoked: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        CheckConstraint(
            "is_delegation = 0 OR granted_by IS NOT NULL",
            name="ck_access_grants_delegation_actor",
        ),
        Index(
            "ix_access_grants_subject_scope",
            "subject_id",
            "plan_version",
            "student_id",
        ),
    )


class AccessAudit(Base):
    """访问审计：只增不改，授权变化不能改写既有审计记录。"""

    __tablename__ = "access_audits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    plan_version: Mapped[str] = mapped_column(String(128), nullable=False)
    student_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    resource: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    visible_fields: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    redacted_fields: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    detail: Mapped[str] = mapped_column(String(512), nullable=False, default="")

    __table_args__ = (
        CheckConstraint(
            "decision in ('allow','deny')", name="ck_access_audits_decision"
        ),
        Index("ix_access_audits_plan", "plan_version", "occurred_at"),
    )
