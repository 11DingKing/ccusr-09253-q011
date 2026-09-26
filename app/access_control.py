"""访问策略维护、受控查询与访问审计的服务层。

策略数据（主体、归属、指导关系、授权）全部持久化在数据库中，每次
请求实时加载并判定，因此授权的新建/撤销/过期立即影响后续读取；
访问审计与授权变更日志只追加，不改写既有记录。
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Iterable, Sequence

from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from . import services
from .compliance.privacy_access import (
    SENSITIVE_FIELDS,
    AccessDecision,
    ActorContext,
    GrantView,
    Role,
    ScopeType,
    decide,
    grant_is_active,
    project_student,
    scope_contains,
)
from .models import (
    AccessActor,
    AccessGrant,
    AccessGrantEvent,
    AccessLogEntry,
    MentorAssignmentRow,
    StudentEnrollment,
)


class AccessError(Exception):
    """访问控制领域错误基类。"""


class ActorNotFoundError(AccessError):
    pass


class GrantNotFoundError(AccessError):
    pass


class AccessDeniedError(AccessError):
    pass


class InvalidGrantError(AccessError):
    pass


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        raise InvalidGrantError("时间必须包含时区")
    return value


# ---------------------------------------------------------------------------
# 主体与关系维护
# ---------------------------------------------------------------------------


def upsert_actor(
    db: Session, *, actor_id: str, role: str, institution_id: str
) -> dict[str, Any]:
    if role not in {r.value for r in Role}:
        raise InvalidGrantError(f"未知角色: {role}")
    stmt = sqlite_insert(AccessActor).values(
        actor_id=actor_id, role=role, institution_id=institution_id
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["actor_id"],
        set_={"role": role, "institution_id": institution_id},
    )
    db.execute(stmt)
    db.commit()
    actor = db.get(AccessActor, actor_id)
    assert actor is not None
    return {"actor_id": actor.actor_id, "role": actor.role, "institution_id": actor.institution_id}


def get_actor(db: Session, actor_id: str) -> dict[str, Any] | None:
    actor = db.get(AccessActor, actor_id)
    if actor is None:
        return None
    return {"actor_id": actor.actor_id, "role": actor.role, "institution_id": actor.institution_id}


def upsert_enrollment(
    db: Session, *, student_id: str, plan_version: str, institution_id: str
) -> dict[str, Any]:
    stmt = sqlite_insert(StudentEnrollment).values(
        student_id=student_id,
        plan_version=plan_version,
        institution_id=institution_id,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["student_id", "plan_version"],
        set_={"institution_id": institution_id},
    )
    db.execute(stmt)
    db.commit()
    return {
        "student_id": student_id,
        "plan_version": plan_version,
        "institution_id": institution_id,
    }


def list_enrollments(db: Session, plan_version: str) -> list[dict[str, Any]]:
    stmt = select(StudentEnrollment).where(
        StudentEnrollment.plan_version == plan_version
    )
    rows = db.execute(stmt).scalars().all()
    return [
        {
            "student_id": row.student_id,
            "plan_version": row.plan_version,
            "institution_id": row.institution_id,
        }
        for row in rows
    ]


def set_mentor_assignment(
    db: Session, *, mentor_id: str, student_id: str, active: bool
) -> dict[str, Any]:
    stmt = sqlite_insert(MentorAssignmentRow).values(
        mentor_id=mentor_id, student_id=student_id, active=active
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["mentor_id", "student_id"],
        set_={"active": active},
    )
    db.execute(stmt)
    db.commit()
    return {"mentor_id": mentor_id, "student_id": student_id, "active": active}


def list_mentor_assignments(
    db: Session, *, mentor_id: str | None = None, student_id: str | None = None
) -> list[dict[str, Any]]:
    stmt = select(MentorAssignmentRow)
    if mentor_id is not None:
        stmt = stmt.where(MentorAssignmentRow.mentor_id == mentor_id)
    if student_id is not None:
        stmt = stmt.where(MentorAssignmentRow.student_id == student_id)
    rows = db.execute(stmt).scalars().all()
    return [
        {"mentor_id": row.mentor_id, "student_id": row.student_id, "active": row.active}
        for row in rows
    ]


# ---------------------------------------------------------------------------
# 授权维护
# ---------------------------------------------------------------------------


def _grant_view(row: AccessGrant) -> GrantView:
    return GrantView(
        grant_id=row.grant_id,
        actor_id=row.actor_id,
        scope_type=row.scope_type,
        scope_value=row.scope_value,
        fields=frozenset(row.fields or []),
        status=row.status,
        expires_at=row.expires_at,
        delegated_by=row.delegated_by,
    )


def _grant_dict(row: AccessGrant) -> dict[str, Any]:
    return {
        "grant_id": row.grant_id,
        "actor_id": row.actor_id,
        "scope_type": row.scope_type,
        "scope_value": row.scope_value,
        "fields": sorted(row.fields or []),
        "delegated_by": row.delegated_by,
        "status": row.status,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
    }


def _append_grant_event(
    db: Session, *, grant_id: str, action: str, actor_id: str, reason: str
) -> None:
    db.add(
        AccessGrantEvent(
            grant_id=grant_id,
            action=action,
            actor_id=actor_id,
            reason=reason,
            occurred_at=_utcnow(),
        )
    )


def create_grant(
    db: Session,
    *,
    grant_id: str,
    actor_id: str,
    scope_type: str,
    scope_value: str,
    fields: Sequence[str],
    delegated_by: str | None = None,
    expires_at: datetime | None = None,
    operator_id: str,
    reason: str = "",
) -> dict[str, Any]:
    """创建字段级授权；委托授权必须落在父授权的作用域与字段子集内。"""
    if db.get(AccessActor, actor_id) is None:
        raise ActorNotFoundError(f"actor '{actor_id}' is not registered")
    if scope_type not in {s.value for s in ScopeType}:
        raise InvalidGrantError(f"未知作用域类型: {scope_type}")
    normalized = sorted({f.strip() for f in fields if f and f.strip()})
    if not normalized:
        raise InvalidGrantError("授权字段不能为空")
    unknown = set(normalized) - set(SENSITIVE_FIELDS)
    if unknown:
        raise InvalidGrantError(f"未知敏感字段: {sorted(unknown)}")
    expires_at = _aware(expires_at)
    now = _utcnow()
    if expires_at is not None and expires_at <= now:
        raise InvalidGrantError("有效期必须晚于当前时间")

    if delegated_by is not None:
        parent_row = db.get(AccessGrant, delegated_by)
        if parent_row is None:
            raise InvalidGrantError(f"父授权 '{delegated_by}' 不存在")
        parent = _grant_view(parent_row)
        child = GrantView(
            grant_id=grant_id,
            actor_id=actor_id,
            scope_type=scope_type,
            scope_value=scope_value,
            fields=frozenset(normalized),
            status="active",
            expires_at=expires_at,
            delegated_by=delegated_by,
        )
        if not grant_is_active(parent, now):
            raise InvalidGrantError("父授权已撤销或过期，不能委托")
        if not scope_contains(parent, child):
            raise InvalidGrantError("委托作用域不能超出父授权")
        if not set(normalized) <= set(parent.fields):
            raise InvalidGrantError("委托字段必须是父授权字段的子集")

    if db.get(AccessGrant, grant_id) is not None:
        raise InvalidGrantError(f"授权 '{grant_id}' 已存在")

    row = AccessGrant(
        grant_id=grant_id,
        actor_id=actor_id,
        scope_type=scope_type,
        scope_value=scope_value,
        fields=normalized,
        delegated_by=delegated_by,
        status="active",
        expires_at=expires_at,
        created_at=now,
    )
    db.add(row)
    _append_grant_event(
        db, grant_id=grant_id, action="create", actor_id=operator_id, reason=reason
    )
    db.commit()
    return _grant_dict(row)


def revoke_grant(
    db: Session, *, grant_id: str, operator_id: str, reason: str = ""
) -> dict[str, Any]:
    """撤销授权：只追加状态与审计事件，不删除、不改写历史记录。"""
    row = db.get(AccessGrant, grant_id)
    if row is None:
        raise GrantNotFoundError(f"grant '{grant_id}' does not exist")
    if row.status == "revoked":
        return _grant_dict(row)
    row.status = "revoked"
    row.revoked_at = _utcnow()
    _append_grant_event(
        db, grant_id=grant_id, action="revoke", actor_id=operator_id, reason=reason
    )
    db.commit()
    return _grant_dict(row)


def list_grants(db: Session, *, actor_id: str | None = None) -> list[dict[str, Any]]:
    stmt = select(AccessGrant).order_by(AccessGrant.grant_id)
    if actor_id is not None:
        stmt = stmt.where(AccessGrant.actor_id == actor_id)
    rows = db.execute(stmt).scalars().all()
    return [_grant_dict(row) for row in rows]


def list_grant_events(db: Session, grant_id: str) -> list[dict[str, Any]]:
    stmt = (
        select(AccessGrantEvent)
        .where(AccessGrantEvent.grant_id == grant_id)
        .order_by(AccessGrantEvent.id)
    )
    rows = db.execute(stmt).scalars().all()
    return [
        {
            "grant_id": row.grant_id,
            "action": row.action,
            "actor_id": row.actor_id,
            "reason": row.reason,
            "occurred_at": row.occurred_at.isoformat() if row.occurred_at else None,
        }
        for row in rows
    ]


# ---------------------------------------------------------------------------
# 判定
# ---------------------------------------------------------------------------


def _load_actor(db: Session, actor_id: str) -> AccessActor:
    actor = db.get(AccessActor, actor_id)
    if actor is None:
        raise ActorNotFoundError(f"actor '{actor_id}' is not registered")
    return actor


def _student_institution(
    db: Session, plan_version: str, student_id: str
) -> str | None:
    row = db.get(StudentEnrollment, (student_id, plan_version))
    return row.institution_id if row is not None else None


def _assigned_student_ids(db: Session, mentor_id: str) -> set[str]:
    stmt = select(MentorAssignmentRow.student_id).where(
        MentorAssignmentRow.mentor_id == mentor_id,
        MentorAssignmentRow.active.is_(True),
    )
    return set(db.execute(stmt).scalars().all())


def decide_for(
    db: Session, *, actor_id: str, plan_version: str, student_id: str
) -> AccessDecision:
    """实时加载策略数据并判定；授权变化立即反映到结果。"""
    actor = _load_actor(db, actor_id)
    stmt = select(AccessGrant).where(AccessGrant.actor_id == actor_id)
    grants = [_grant_view(row) for row in db.execute(stmt).scalars().all()]

    cache: dict[str, GrantView | None] = {}

    def _resolve(grant_id: str) -> GrantView | None:
        if grant_id not in cache:
            row = db.get(AccessGrant, grant_id)
            cache[grant_id] = _grant_view(row) if row is not None else None
        return cache[grant_id]

    return decide(
        ActorContext(
            actor_id=actor.actor_id,
            role=actor.role,
            institution_id=actor.institution_id,
        ),
        plan_version=plan_version,
        student_id=student_id,
        student_institution_id=_student_institution(db, plan_version, student_id),
        assigned_student_ids=_assigned_student_ids(db, actor_id),
        grants=grants,
        now=_utcnow(),
        resolve_grant=_resolve,
    )


# ---------------------------------------------------------------------------
# 访问审计（只追加）
# ---------------------------------------------------------------------------


def _log_access(
    db: Session,
    *,
    actor_id: str,
    action: str,
    plan_version: str,
    student_id: str,
    freeze_id: str | None,
    decision: AccessDecision,
) -> None:
    db.add(
        AccessLogEntry(
            actor_id=actor_id,
            action=action,
            plan_version=plan_version,
            student_id=student_id,
            freeze_id=freeze_id,
            decision="allow" if decision.allowed else "deny",
            visible_fields=sorted(decision.visible_fields),
            redacted_fields=sorted(decision.redacted_fields),
            occurred_at=_utcnow(),
        )
    )


def list_access_logs(
    db: Session,
    *,
    plan_version: str | None = None,
    actor_id: str | None = None,
    student_id: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    stmt = select(AccessLogEntry).order_by(AccessLogEntry.id)
    if plan_version is not None:
        stmt = stmt.where(AccessLogEntry.plan_version == plan_version)
    if actor_id is not None:
        stmt = stmt.where(AccessLogEntry.actor_id == actor_id)
    if student_id is not None:
        stmt = stmt.where(AccessLogEntry.student_id == student_id)
    rows = db.execute(stmt.limit(limit)).scalars().all()
    return [
        {
            "id": row.id,
            "actor_id": row.actor_id,
            "action": row.action,
            "plan_version": row.plan_version,
            "student_id": row.student_id,
            "freeze_id": row.freeze_id,
            "decision": row.decision,
            "visible_fields": list(row.visible_fields or []),
            "redacted_fields": list(row.redacted_fields or []),
            "occurred_at": row.occurred_at.isoformat() if row.occurred_at else None,
        }
        for row in rows
    ]


# ---------------------------------------------------------------------------
# 受控查询与批量导出
# ---------------------------------------------------------------------------


def read_progress(
    db: Session, *, actor_id: str, plan_version: str, student_id: str
) -> dict[str, Any] | None:
    """受控读取单个学生的学时明细；越权访问拒绝并留痕。"""
    services._require_plan(db, plan_version)
    decision = decide_for(
        db, actor_id=actor_id, plan_version=plan_version, student_id=student_id
    )
    _log_access(
        db,
        actor_id=actor_id,
        action="read_progress",
        plan_version=plan_version,
        student_id=student_id,
        freeze_id=None,
        decision=decision,
    )
    db.commit()
    if not decision.allowed:
        raise AccessDeniedError(decision.reason)
    snapshot = services.current_snapshot(db, plan_version)
    student = None
    for item in snapshot.students:
        if item["student_id"] == student_id:
            student = item
            break
    if student is None:
        return None
    return project_student(student, decision.visible_fields)


def _project_snapshot(
    db: Session,
    *,
    actor_id: str,
    plan_version: str,
    freeze_id: str | None,
    students: Iterable[dict[str, Any]],
    action: str,
) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    for student in students:
        sid = student["student_id"]
        decision = decide_for(
            db, actor_id=actor_id, plan_version=plan_version, student_id=sid
        )
        _log_access(
            db,
            actor_id=actor_id,
            action=action,
            plan_version=plan_version,
            student_id=sid,
            freeze_id=freeze_id,
            decision=decision,
        )
        if decision.allowed:
            projected.append(project_student(student, decision.visible_fields))
    db.commit()
    return projected


def read_snapshot(
    db: Session, *, actor_id: str, plan_version: str, freeze_id: str | None = None
) -> dict[str, Any]:
    """受控读取快照：元数据与汇总数字原样保留，仅裁剪明细字段。"""
    services._require_plan(db, plan_version)
    if freeze_id is None:
        snapshot = services.current_snapshot(db, plan_version)
    else:
        snapshot = services.get_frozen_snapshot(db, plan_version, freeze_id)
    data = snapshot.to_dict()
    data["students"] = _project_snapshot(
        db,
        actor_id=actor_id,
        plan_version=plan_version,
        freeze_id=freeze_id,
        students=data["students"],
        action="read_snapshot" if freeze_id is None else "read_freeze",
    )
    return data


def export_plan(
    db: Session,
    *,
    actor_id: str,
    plan_version: str,
    student_ids: Sequence[str] | None = None,
    freeze_id: str | None = None,
) -> dict[str, Any]:
    """批量导出：应用与受控查询完全相同的判定与裁剪规则。"""
    services._require_plan(db, plan_version)
    if freeze_id is None:
        snapshot = services.current_snapshot(db, plan_version)
    else:
        snapshot = services.get_frozen_snapshot(db, plan_version, freeze_id)
    data = snapshot.to_dict()
    students = data["students"]
    if student_ids is not None:
        wanted = set(student_ids)
        students = [s for s in students if s["student_id"] in wanted]

    exported: list[dict[str, Any]] = []
    for student in students:
        sid = student["student_id"]
        decision = decide_for(
            db, actor_id=actor_id, plan_version=plan_version, student_id=sid
        )
        _log_access(
            db,
            actor_id=actor_id,
            action="export",
            plan_version=plan_version,
            student_id=sid,
            freeze_id=freeze_id,
            decision=decision,
        )
        if decision.allowed:
            exported.append(project_student(student, decision.visible_fields))
        else:
            exported.append(
                {
                    "student_id": sid,
                    "visible": False,
                    "redacted_fields": sorted(SENSITIVE_FIELDS),
                }
            )
    db.commit()
    return {
        "plan_version": plan_version,
        "freeze_id": freeze_id,
        "generated_at": data["generated_at"],
        "exported_count": len(exported),
        "students": exported,
    }
