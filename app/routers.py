"""服务端业务模块。"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from . import access_control, services
from .db import get_db
from .schemas import (
    AccessLogOut,
    ActorIn,
    ActorOut,
    DecisionOut,
    DiffOut,
    EnrollmentIn,
    EnrollmentOut,
    EventBatchIn,
    ExportIn,
    ExportOut,
    FreezeIn,
    GrantEventOut,
    GrantIn,
    GrantOut,
    GrantRevokeIn,
    ImportResult,
    MentorAssignmentIn,
    MentorAssignmentOut,
    PlanIn,
    PlanOut,
    SimulateIn,
    SnapshotOut,
    StudentProgressOut,
)

router = APIRouter(prefix="/api")


@router.post("/plans", response_model=PlanOut, status_code=status.HTTP_201_CREATED)
def create_plan(body: PlanIn, db: Session = Depends(get_db)) -> Any:
    return services.ensure_plan(
        db,
        plan_version=body.plan_version,
        iana_timezone=body.iana_timezone,
        required_seconds=body.required_seconds,
    )


@router.get("/plans/{plan_version}", response_model=PlanOut)
def read_plan(plan_version: str, db: Session = Depends(get_db)) -> Any:
    plan = services.get_plan_plain(db, plan_version)
    if plan is None:
        raise HTTPException(status_code=404, detail="plan not found")
    return plan


@router.post(
    "/plans/{plan_version}/events",
    response_model=ImportResult,
    status_code=status.HTTP_201_CREATED,
)
def post_events(
    plan_version: str, body: EventBatchIn, db: Session = Depends(get_db)
) -> Any:
    try:
        return services.import_events(
            db,
            plan_version=plan_version,
            events=[e.model_dump() for e in body.events],
        )
    except services.PlanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/plans/{plan_version}/snapshot",
    response_model=SnapshotOut,
)
def get_snapshot(plan_version: str, db: Session = Depends(get_db)) -> Any:
    try:
        snap = services.current_snapshot(db, plan_version)
        return snap.to_dict()
    except services.PlanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/plans/{plan_version}/students/{student_id}/progress",
    response_model=StudentProgressOut,
)
def get_progress(
    plan_version: str, student_id: str, db: Session = Depends(get_db)
) -> Any:
    try:
        result = services.student_progress(db, plan_version, student_id)
    except services.PlanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="student not found")
    return result


@router.post(
    "/plans/{plan_version}/freezes/{freeze_id}",
    response_model=SnapshotOut,
    status_code=status.HTTP_201_CREATED,
)
def post_freeze(
    plan_version: str,
    freeze_id: str,
    body: FreezeIn,
    db: Session = Depends(get_db),
) -> Any:
    try:
        snap, _ = services.freeze_semester(
            db, plan_version=plan_version, freeze_id=freeze_id
        )
        return snap.to_dict()
    except services.PlanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/plans/{plan_version}/freezes/{freeze_id}",
    response_model=SnapshotOut,
)
def get_freeze(
    plan_version: str, freeze_id: str, db: Session = Depends(get_db)
) -> Any:
    try:
        snap = services.get_frozen_snapshot(db, plan_version, freeze_id)
        return snap.to_dict()
    except services.PlanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except services.FreezeNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/plans/{plan_version}/freezes/{freeze_id}/explain/{student_id}",
    response_model=StudentProgressOut,
)
def explain_freeze_student(
    plan_version: str,
    freeze_id: str,
    student_id: str,
    db: Session = Depends(get_db),
) -> Any:
    try:
        result = services.explain_frozen_student(
            db, plan_version, freeze_id, student_id
        )
    except (services.PlanNotFoundError, services.FreezeNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="student not found")
    return result


@router.get(
    "/plans/{plan_version}/freezes/{freeze_id}/diff/{other_freeze_id}",
    response_model=DiffOut,
)
def get_diff(
    plan_version: str,
    freeze_id: str,
    other_freeze_id: str,
    db: Session = Depends(get_db),
) -> Any:
    try:
        return services.diff_freezes(
            db, plan_version, freeze_id, other_freeze_id
        )
    except (services.PlanNotFoundError, services.FreezeNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# 隐私字段分级访问：授权维护、模拟判定、受控查询与访问审计
# ---------------------------------------------------------------------------

ActorHeader = Annotated[str | None, Header(alias="X-Actor-Id")]


def _require_actor_header(x_actor_id: ActorHeader) -> str:
    if not x_actor_id or not x_actor_id.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-Actor-Id header is required",
        )
    return x_actor_id.strip()


def _map_access_error(exc: access_control.AccessError) -> HTTPException:
    if isinstance(exc, access_control.AccessDeniedError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(
        exc, (access_control.ActorNotFoundError, access_control.GrantNotFoundError)
    ):
        return HTTPException(status_code=404, detail=str(exc))
    return HTTPException(status_code=422, detail=str(exc))


@router.put("/access/actors/{actor_id}", response_model=ActorOut)
def put_actor(actor_id: str, body: ActorIn, db: Session = Depends(get_db)) -> Any:
    try:
        return access_control.upsert_actor(
            db,
            actor_id=actor_id,
            role=body.role,
            institution_id=body.institution_id,
        )
    except access_control.AccessError as exc:
        raise _map_access_error(exc) from exc


@router.get("/access/actors/{actor_id}", response_model=ActorOut)
def get_actor(actor_id: str, db: Session = Depends(get_db)) -> Any:
    actor = access_control.get_actor(db, actor_id)
    if actor is None:
        raise HTTPException(status_code=404, detail="actor not found")
    return actor


@router.put(
    "/access/enrollments/{plan_version}/{student_id}",
    response_model=EnrollmentOut,
)
def put_enrollment(
    plan_version: str,
    student_id: str,
    body: EnrollmentIn,
    db: Session = Depends(get_db),
) -> Any:
    return access_control.upsert_enrollment(
        db,
        student_id=student_id,
        plan_version=plan_version,
        institution_id=body.institution_id,
    )


@router.get(
    "/access/enrollments/{plan_version}",
    response_model=list[EnrollmentOut],
)
def get_enrollments(plan_version: str, db: Session = Depends(get_db)) -> Any:
    return access_control.list_enrollments(db, plan_version)


@router.put(
    "/access/mentor-assignments/{mentor_id}/{student_id}",
    response_model=MentorAssignmentOut,
)
def put_mentor_assignment(
    mentor_id: str,
    student_id: str,
    body: MentorAssignmentIn,
    db: Session = Depends(get_db),
) -> Any:
    return access_control.set_mentor_assignment(
        db, mentor_id=mentor_id, student_id=student_id, active=body.active
    )


@router.get(
    "/access/mentor-assignments",
    response_model=list[MentorAssignmentOut],
)
def get_mentor_assignments(
    mentor_id: str | None = None,
    student_id: str | None = None,
    db: Session = Depends(get_db),
) -> Any:
    return access_control.list_mentor_assignments(
        db, mentor_id=mentor_id, student_id=student_id
    )


@router.post(
    "/access/grants",
    response_model=GrantOut,
    status_code=status.HTTP_201_CREATED,
)
def post_grant(
    body: GrantIn,
    db: Session = Depends(get_db),
    x_actor_id: ActorHeader = None,
) -> Any:
    operator = _require_actor_header(x_actor_id)
    try:
        return access_control.create_grant(
            db,
            grant_id=body.grant_id,
            actor_id=body.actor_id,
            scope_type=body.scope_type,
            scope_value=body.scope_value,
            fields=body.fields,
            delegated_by=body.delegated_by,
            expires_at=body.expires_at,
            operator_id=operator,
            reason=body.reason,
        )
    except access_control.AccessError as exc:
        raise _map_access_error(exc) from exc


@router.post("/access/grants/{grant_id}/revoke", response_model=GrantOut)
def post_revoke_grant(
    grant_id: str,
    body: GrantRevokeIn,
    db: Session = Depends(get_db),
    x_actor_id: ActorHeader = None,
) -> Any:
    operator = _require_actor_header(x_actor_id)
    try:
        return access_control.revoke_grant(
            db, grant_id=grant_id, operator_id=operator, reason=body.reason
        )
    except access_control.AccessError as exc:
        raise _map_access_error(exc) from exc


@router.get("/access/grants", response_model=list[GrantOut])
def get_grants(
    actor_id: str | None = None, db: Session = Depends(get_db)
) -> Any:
    return access_control.list_grants(db, actor_id=actor_id)


@router.get(
    "/access/grants/{grant_id}/events",
    response_model=list[GrantEventOut],
)
def get_grant_events(grant_id: str, db: Session = Depends(get_db)) -> Any:
    return access_control.list_grant_events(db, grant_id)


@router.post("/access/simulate", response_model=DecisionOut)
def post_simulate(body: SimulateIn, db: Session = Depends(get_db)) -> Any:
    """模拟判定：实时评估策略但不产生访问审计记录。"""
    try:
        decision = access_control.decide_for(
            db,
            actor_id=body.actor_id,
            plan_version=body.plan_version,
            student_id=body.student_id,
        )
    except access_control.AccessError as exc:
        raise _map_access_error(exc) from exc
    return decision.to_dict()


@router.get(
    "/access/plans/{plan_version}/students/{student_id}/progress",
    response_model=StudentProgressOut,
)
def get_controlled_progress(
    plan_version: str,
    student_id: str,
    db: Session = Depends(get_db),
    x_actor_id: ActorHeader = None,
) -> Any:
    actor_id = _require_actor_header(x_actor_id)
    try:
        result = access_control.read_progress(
            db, actor_id=actor_id, plan_version=plan_version, student_id=student_id
        )
    except services.PlanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except access_control.AccessError as exc:
        raise _map_access_error(exc) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="student not found")
    return result


@router.get(
    "/access/plans/{plan_version}/snapshot",
    response_model=SnapshotOut,
)
def get_controlled_snapshot(
    plan_version: str,
    db: Session = Depends(get_db),
    x_actor_id: ActorHeader = None,
) -> Any:
    actor_id = _require_actor_header(x_actor_id)
    try:
        return access_control.read_snapshot(
            db, actor_id=actor_id, plan_version=plan_version
        )
    except services.PlanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except access_control.AccessError as exc:
        raise _map_access_error(exc) from exc


@router.get(
    "/access/plans/{plan_version}/freezes/{freeze_id}/snapshot",
    response_model=SnapshotOut,
)
def get_controlled_freeze(
    plan_version: str,
    freeze_id: str,
    db: Session = Depends(get_db),
    x_actor_id: ActorHeader = None,
) -> Any:
    actor_id = _require_actor_header(x_actor_id)
    try:
        return access_control.read_snapshot(
            db, actor_id=actor_id, plan_version=plan_version, freeze_id=freeze_id
        )
    except (services.PlanNotFoundError, services.FreezeNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except access_control.AccessError as exc:
        raise _map_access_error(exc) from exc


@router.post(
    "/access/plans/{plan_version}/export",
    response_model=ExportOut,
)
def post_export(
    plan_version: str,
    body: ExportIn,
    db: Session = Depends(get_db),
    x_actor_id: ActorHeader = None,
) -> Any:
    """批量导出：应用与受控查询相同的判定与字段级裁剪规则。"""
    actor_id = _require_actor_header(x_actor_id)
    try:
        return access_control.export_plan(
            db,
            actor_id=actor_id,
            plan_version=plan_version,
            student_ids=body.student_ids,
            freeze_id=body.freeze_id,
        )
    except (services.PlanNotFoundError, services.FreezeNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except access_control.AccessError as exc:
        raise _map_access_error(exc) from exc


@router.get("/access/audit-logs", response_model=list[AccessLogOut])
def get_audit_logs(
    plan_version: str | None = None,
    actor_id: str | None = None,
    student_id: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db),
) -> Any:
    return access_control.list_access_logs(
        db,
        plan_version=plan_version,
        actor_id=actor_id,
        student_id=student_id,
        limit=limit,
    )
