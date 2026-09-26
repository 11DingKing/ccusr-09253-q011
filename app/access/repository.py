"""访问策略的持久化读取与写入。"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    AccessAudit as AccessAuditModel,
)
from ..models import (
    AccessGrant as AccessGrantModel,
)
from ..models import (
    AccessSubject as AccessSubjectModel,
)
from ..models import (
    MentorRelation as MentorRelationModel,
)
from ..models import (
    StudentEnrollment as EnrollmentModel,
)

SENSITIVE_FIELDS: tuple[str, ...] = ("location", "reason", "mentor_comment")


def _audit_aware(value: datetime | None) -> datetime | None:
    """SQLite 取回的时间可能丢失时区，统一补回 UTC。"""
    if value is None:
        return None
    if value.tzinfo is None:
        from datetime import UTC

        return value.replace(tzinfo=UTC)
    return value


def upsert_subject(
    db: Session,
    *,
    subject_id: str,
    org_id: str,
    role: str,
    is_active: bool,
) -> AccessSubjectModel:
    existing = db.get(AccessSubjectModel, subject_id)
    if existing is None:
        row = AccessSubjectModel(
            subject_id=subject_id,
            org_id=org_id,
            role=role,
            is_active=is_active,
        )
        db.add(row)
    else:
        existing.org_id = org_id
        existing.role = role
        existing.is_active = is_active
        row = existing
    db.commit()
    return row


def get_subject(db: Session, subject_id: str) -> AccessSubjectModel | None:
    return db.get(AccessSubjectModel, subject_id)


def load_policy_data(db: Session) -> dict[str, Any]:
    """一次性加载策略判定所需的全部数据。"""
    subjects = {
        row.subject_id: {
            "subject_id": row.subject_id,
            "org_id": row.org_id,
            "role": row.role,
            "is_active": row.is_active,
        }
        for row in db.execute(select(AccessSubjectModel)).scalars().all()
    }
    enrollments = {
        row.student_id: row.org_id
        for row in db.execute(select(EnrollmentModel)).scalars().all()
    }
    mentor_relations = {
        (row.mentor_id, row.student_id, row.plan_version)
        for row in db.execute(select(MentorRelationModel)).scalars().all()
        if row.is_active
    }
    grants: list[dict[str, Any]] = []
    for row in db.execute(select(AccessGrantModel)).scalars().all():
        grants.append(
            {
                "grant_id": row.grant_id,
                "subject_id": row.subject_id,
                "plan_version": row.plan_version,
                "student_id": row.student_id,
                "fields": tuple(f for f in row.fields.split(",") if f),
                "is_delegation": row.is_delegation,
                "granted_by": row.granted_by,
                "is_revoked": row.is_revoked,
                "expires_at": _audit_aware(row.expires_at),
                "created_at": _audit_aware(row.created_at),
                "revoked_at": _audit_aware(row.revoked_at),
            }
        )
    return {
        "subjects": subjects,
        "enrollments": enrollments,
        "mentor_relations": mentor_relations,
        "grants": grants,
    }


def upsert_enrollment(
    db: Session, *, student_id: str, org_id: str
) -> EnrollmentModel:
    existing = db.get(EnrollmentModel, student_id)
    if existing is None:
        row = EnrollmentModel(student_id=student_id, org_id=org_id)
        db.add(row)
    else:
        existing.org_id = org_id
        row = existing
    db.commit()
    return row


def add_mentor_relation(
    db: Session,
    *,
    mentor_id: str,
    student_id: str,
    plan_version: str,
) -> MentorRelationModel:
    stmt = select(MentorRelationModel).where(
        MentorRelationModel.mentor_id == mentor_id,
        MentorRelationModel.student_id == student_id,
        MentorRelationModel.plan_version == plan_version,
    )
    existing = db.execute(stmt).scalar_one_or_none()
    if existing is None:
        row = MentorRelationModel(
            mentor_id=mentor_id,
            student_id=student_id,
            plan_version=plan_version,
            is_active=True,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row
    existing.is_active = True
    db.commit()
    return existing


def remove_mentor_relation(
    db: Session, *, mentor_id: str, student_id: str, plan_version: str
) -> bool:
    stmt = select(MentorRelationModel).where(
        MentorRelationModel.mentor_id == mentor_id,
        MentorRelationModel.student_id == student_id,
        MentorRelationModel.plan_version == plan_version,
    )
    existing = db.execute(stmt).scalar_one_or_none()
    if existing is None:
        return False
    existing.is_active = False
    db.commit()
    return True


def insert_grant(
    db: Session,
    *,
    grant_id: str,
    subject_id: str,
    plan_version: str | None,
    student_id: str | None,
    fields: str,
    is_delegation: bool,
    granted_by: str | None,
    expires_at: datetime | None,
) -> AccessGrantModel:
    row = AccessGrantModel(
        grant_id=grant_id,
        subject_id=subject_id,
        plan_version=plan_version,
        student_id=student_id,
        fields=fields,
        is_delegation=is_delegation,
        granted_by=granted_by,
        expires_at=expires_at,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def get_grant(db: Session, grant_id: str) -> AccessGrantModel | None:
    return db.get(AccessGrantModel, grant_id)


def revoke_grant(
    db: Session, *, grant_id: str, now: datetime
) -> AccessGrantModel | None:
    row = db.get(AccessGrantModel, grant_id)
    if row is None or row.is_revoked:
        return row
    row.is_revoked = True
    row.revoked_at = now
    db.commit()
    db.refresh(row)
    return row


def list_grants(
    db: Session, *, subject_id: str | None = None
) -> list[AccessGrantModel]:
    stmt = select(AccessGrantModel).order_by(AccessGrantModel.created_at)
    if subject_id is not None:
        stmt = stmt.where(AccessGrantModel.subject_id == subject_id)
    return list(db.execute(stmt).scalars().all())


def append_access_audit(
    db: Session,
    *,
    subject_id: str,
    action: str,
    plan_version: str,
    student_id: str | None,
    resource: str,
    decision: str,
    visible_fields: tuple[str, ...],
    redacted_fields: tuple[str, ...],
    detail: str,
) -> AccessAuditModel:
    row = AccessAuditModel(
        subject_id=subject_id,
        action=action,
        plan_version=plan_version,
        student_id=student_id,
        resource=resource,
        decision=decision,
        visible_fields=",".join(visible_fields),
        redacted_fields=",".join(redacted_fields),
        detail=detail[:512],
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_access_audits(
    db: Session,
    *,
    plan_version: str | None = None,
    subject_id: str | None = None,
    limit: int = 200,
) -> list[AccessAuditModel]:
    stmt = select(AccessAuditModel).order_by(AccessAuditModel.id.desc())
    if plan_version is not None:
        stmt = stmt.where(AccessAuditModel.plan_version == plan_version)
    if subject_id is not None:
        stmt = stmt.where(AccessAuditModel.subject_id == subject_id)
    stmt = stmt.limit(limit)
    return list(db.execute(stmt).scalars().all())
