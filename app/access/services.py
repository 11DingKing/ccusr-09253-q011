"""授权维护、模拟判定、受控查询与访问审计服务。"""

from __future__ import annotations

import copy
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from .. import services as hours_services
from . import repository
from .policy import (
    ROLE_BASE_FIELDS,
    SENSITIVE_FIELDS,
    Decision,
    GrantNotFound,
    PolicyError,
    SubjectNotFound,
)
from .policy import get_policy_store
from .redaction import redact_student


class AccessDeniedError(Exception):
    def __init__(self, detail: str, reasons: list[str] | None = None) -> None:
        super().__init__(detail)
        self.detail = detail
        self.reasons = reasons or []


def _store():
    return get_policy_store()


# ---------------------------------------------------------------------------
# 授权维护
# ---------------------------------------------------------------------------


def register_subject(
    db: Session,
    *,
    subject_id: str,
    org_id: str,
    role: str,
    is_active: bool = True,
) -> dict[str, Any]:
    row = repository.upsert_subject(
        db,
        subject_id=subject_id,
        org_id=org_id,
        role=role,
        is_active=is_active,
    )
    _store().invalidate()
    return {
        "subject_id": row.subject_id,
        "org_id": row.org_id,
        "role": row.role,
        "is_active": bool(row.is_active),
    }


def register_enrollment(db: Session, *, student_id: str, org_id: str) -> dict[str, Any]:
    row = repository.upsert_enrollment(db, student_id=student_id, org_id=org_id)
    _store().invalidate()
    return {"student_id": row.student_id, "org_id": row.org_id}


def add_mentor_relation(
    db: Session, *, plan_version: str, mentor_id: str, student_id: str
) -> dict[str, Any]:
    subject = repository.get_subject(db, mentor_id)
    if subject is None:
        raise SubjectNotFound(f"主体 {mentor_id} 不存在")
    if subject.role != "mentor":
        raise PolicyError("只有导师角色可以建立指导关系")
    row = repository.add_mentor_relation(
        db, mentor_id=mentor_id, student_id=student_id, plan_version=plan_version
    )
    _store().invalidate()
    return {
        "mentor_id": row.mentor_id,
        "student_id": row.student_id,
        "plan_version": row.plan_version,
        "is_active": bool(row.is_active),
    }


def remove_mentor_relation(
    db: Session, *, plan_version: str, mentor_id: str, student_id: str
) -> None:
    repository.remove_mentor_relation(
        db, mentor_id=mentor_id, student_id=student_id, plan_version=plan_version
    )
    _store().invalidate()


def create_grant(
    db: Session,
    *,
    plan_version: str | None,
    subject_id: str,
    fields: list[str],
    student_id: str | None = None,
    is_delegation: bool = False,
    granted_by: str | None = None,
    expires_at: datetime | None = None,
) -> dict[str, Any]:
    if repository.get_subject(db, subject_id) is None:
        raise SubjectNotFound(f"主体 {subject_id} 不存在")
    invalid = [f for f in fields if f not in SENSITIVE_FIELDS]
    if invalid:
        raise PolicyError(f"未知敏感字段：{','.join(invalid)}")
    if is_delegation and not granted_by:
        raise PolicyError("委托必须记录授权人 granted_by")
    if expires_at is not None and expires_at.tzinfo is None:
        raise PolicyError("expires_at 必须带时区")
    grant_id = f"G-{uuid.uuid4().hex[:12]}"
    row = repository.insert_grant(
        db,
        grant_id=grant_id,
        subject_id=subject_id,
        plan_version=plan_version,
        student_id=student_id,
        fields=",".join(sorted(set(fields))),
        is_delegation=is_delegation,
        granted_by=granted_by,
        expires_at=expires_at,
    )
    _store().invalidate()
    return _grant_to_dict(row)


def revoke_grant(
    db: Session, *, grant_id: str, actor_id: str, reason: str
) -> dict[str, Any]:
    row = repository.revoke_grant(
        db, grant_id=grant_id, now=datetime.now(UTC)
    )
    if row is None:
        raise GrantNotFound(f"授权 {grant_id} 不存在")
    _store().invalidate()
    # 撤销动作本身也进入只增访问审计。
    repository.append_access_audit(
        db,
        subject_id=actor_id,
        action="revoke_grant",
        plan_version=row.plan_version or "*",
        student_id=row.student_id,
        resource=f"grant:{grant_id}",
        decision="allow",
        visible_fields=(),
        redacted_fields=tuple(row.fields.split(",")) if row.fields else (),
        detail=reason,
    )
    return _grant_to_dict(row)


def list_grants(db: Session, *, subject_id: str | None = None) -> list[dict[str, Any]]:
    return [_grant_to_dict(r) for r in repository.list_grants(db, subject_id=subject_id)]


def _grant_to_dict(row: Any) -> dict[str, Any]:
    return {
        "grant_id": row.grant_id,
        "subject_id": row.subject_id,
        "plan_version": row.plan_version,
        "student_id": row.student_id,
        "fields": [f for f in row.fields.split(",") if f],
        "is_delegation": bool(row.is_delegation),
        "granted_by": row.granted_by,
        "is_revoked": bool(row.is_revoked),
        "expires_at": row.expires_at,
        "created_at": row.created_at,
        "revoked_at": row.revoked_at,
    }


# ---------------------------------------------------------------------------
# 模拟判定
# ---------------------------------------------------------------------------


def simulate(
    db: Session, *, subject_id: str, plan_version: str, student_id: str
) -> dict[str, Any]:
    decision = _store().evaluate(
        db, subject_id=subject_id, plan_version=plan_version, student_id=student_id
    )
    subject = repository.get_subject(db, subject_id)
    body: dict[str, Any] = {
        "subject_id": subject_id,
        "role": subject.role if subject else "",
        "org_id": subject.org_id if subject else "",
        "plan_version": plan_version,
        "student_id": student_id,
        "decision": decision.decision,
        "visible_fields": sorted(decision.visible_fields),
        "redacted_fields": list(decision.redacted_fields),
        "reasons": decision.reasons,
    }
    return body


# ---------------------------------------------------------------------------
# 受控查询
# ---------------------------------------------------------------------------


def _evaluate_or_deny(
    db: Session,
    *,
    subject_id: str,
    plan_version: str,
    student_id: str,
    action: str,
    resource: str,
) -> Decision:
    """执行判定并写只增审计；拒绝时抛出 AccessDeniedError。"""
    decision = _store().evaluate(
        db, subject_id=subject_id, plan_version=plan_version, student_id=student_id
    )
    repository.append_access_audit(
        db,
        subject_id=subject_id,
        action=action,
        plan_version=plan_version,
        student_id=student_id,
        resource=resource,
        decision=decision.decision,
        visible_fields=tuple(sorted(decision.visible_fields)),
        redacted_fields=decision.redacted_fields,
        detail="；".join(decision.reasons),
    )
    if not decision.allowed:
        raise AccessDeniedError("无权访问该学生记录", decision.reasons)
    return decision


def controlled_student_progress(
    db: Session, *, plan_version: str, student_id: str, subject_id: str
) -> dict[str, Any] | None:
    try:
        result = hours_services.student_progress(db, plan_version, student_id)
    except hours_services.PlanNotFoundError:
        raise
    if result is None:
        return None
    decision = _evaluate_or_deny(
        db,
        subject_id=subject_id,
        plan_version=plan_version,
        student_id=student_id,
        action="read_progress",
        resource=f"progress:{plan_version}/{student_id}",
    )
    return redact_student(result, decision.visible_fields)


def _controlled_students(
    db: Session,
    *,
    plan_version: str,
    students: list[dict[str, Any]],
    subject_id: str,
    action: str,
    resource_prefix: str,
) -> list[dict[str, Any]]:
    """按学生逐一判定、裁剪并审计；无权学生整生排除。"""
    visible_rows: list[dict[str, Any]] = []
    for student in students:
        student_id = student["student_id"]
        decision = _store().evaluate(
            db,
            subject_id=subject_id,
            plan_version=plan_version,
            student_id=student_id,
        )
        repository.append_access_audit(
            db,
            subject_id=subject_id,
            action=action,
            plan_version=plan_version,
            student_id=student_id,
            resource=f"{resource_prefix}:{plan_version}/{student_id}",
            decision=decision.decision,
            visible_fields=tuple(sorted(decision.visible_fields)),
            redacted_fields=decision.redacted_fields,
            detail="；".join(decision.reasons),
        )
        if decision.allowed:
            visible_rows.append(redact_student(student, decision.visible_fields))
    return visible_rows


def controlled_snapshot(
    db: Session, *, plan_version: str, subject_id: str
) -> dict[str, Any]:
    snapshot = hours_services.current_snapshot(db, plan_version)
    data = snapshot.to_dict()
    data["students"] = _controlled_students(
        db,
        plan_version=plan_version,
        students=data["students"],
        subject_id=subject_id,
        action="read_snapshot",
        resource_prefix="snapshot",
    )
    return data


def controlled_freeze(
    db: Session, *, plan_version: str, freeze_id: str, subject_id: str
) -> dict[str, Any]:
    snapshot = hours_services.get_frozen_snapshot(db, plan_version, freeze_id)
    stored = snapshot.to_dict()
    data = copy.deepcopy(stored)
    # 只在深拷贝上裁剪，库内冻结快照保持不变，摘要数字对所有读者一致。
    data["students"] = _controlled_students(
        db,
        plan_version=plan_version,
        students=data["students"],
        subject_id=subject_id,
        action="read_freeze",
        resource_prefix=f"freeze/{freeze_id}",
    )
    _assert_freeze_summary_unchanged(stored, data)
    return data


def controlled_freeze_student(
    db: Session,
    *,
    plan_version: str,
    freeze_id: str,
    student_id: str,
    subject_id: str,
) -> dict[str, Any] | None:
    snapshot = hours_services.get_frozen_snapshot(db, plan_version, freeze_id)
    from ..core.snapshot import explain_student

    student = explain_student(snapshot, student_id)
    if student is None:
        return None
    decision = _evaluate_or_deny(
        db,
        subject_id=subject_id,
        plan_version=plan_version,
        student_id=student_id,
        action="read_freeze_student",
        resource=f"freeze:{plan_version}/{freeze_id}/{student_id}",
    )
    return redact_student(student, decision.visible_fields)


_SUMMARY_KEYS = (
    "confirmed_seconds",
    "pending_seconds",
    "adjustment_seconds",
    "total_seconds",
    "lesson_units",
    "pending_lesson_units",
    "meets_requirement",
)


def _assert_freeze_summary_unchanged(
    stored: dict[str, Any], served: dict[str, Any]
) -> None:
    """裁剪只动文本字段；若摘要数字发生变化则属于程序错误。"""
    stored_map = {s["student_id"]: s for s in stored["students"]}
    for student in served["students"]:
        original = stored_map[student["student_id"]]
        for key in _SUMMARY_KEYS:
            if student.get(key) != original.get(key):
                raise RuntimeError(
                    f"冻结摘要字段 {key} 在裁剪后发生变化，违反冻结一致性"
                )


# ---------------------------------------------------------------------------
# 批量导出
# ---------------------------------------------------------------------------


def export_progress(
    db: Session,
    *,
    plan_version: str,
    subject_id: str,
    student_ids: list[str] | None = None,
) -> dict[str, Any]:
    """批量导出：与受控查询相同的判定、裁剪与审计规则。"""
    snapshot = hours_services.current_snapshot(db, plan_version)
    all_students = snapshot.to_dict()["students"]
    if student_ids:
        wanted = set(student_ids)
        all_students = [s for s in all_students if s["student_id"] in wanted]
    visible_rows = _controlled_students(
        db,
        plan_version=plan_version,
        students=all_students,
        subject_id=subject_id,
        action="export",
        resource_prefix="export",
    )
    return {
        "plan_version": plan_version,
        "subject_id": subject_id,
        "exported_count": len(visible_rows),
        "requested_count": len(all_students),
        "students": visible_rows,
    }


# ---------------------------------------------------------------------------
# 访问审计
# ---------------------------------------------------------------------------


def list_access_audits(
    db: Session,
    *,
    plan_version: str | None = None,
    subject_id: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    rows = repository.list_access_audits(
        db, plan_version=plan_version, subject_id=subject_id, limit=limit
    )
    return [
        {
            "id": r.id,
            "occurred_at": r.occurred_at,
            "subject_id": r.subject_id,
            "action": r.action,
            "plan_version": r.plan_version,
            "student_id": r.student_id,
            "resource": r.resource,
            "decision": r.decision,
            "visible_fields": [f for f in r.visible_fields.split(",") if f],
            "redacted_fields": [f for f in r.redacted_fields.split(",") if f],
            "detail": r.detail,
        }
        for r in rows
    ]


def reload_policy(db: Session) -> None:
    """丢弃进程内策略缓存并从数据库重新加载（模拟重启后的策略加载）。"""
    _store().reload(db)


def role_base_fields() -> dict[str, list[str]]:
    return {role: sorted(fields) for role, fields in ROLE_BASE_FIELDS.items()}
