"""授权维护、模拟判定、受控查询与访问审计 HTTP 接口。"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from . import services as hours_services
from .access import services as access_services
from .db import get_db
from .schemas import (
    AccessAuditOut,
    EnrollmentIn,
    EnrollmentOut,
    ExportRequest,
    GrantIn,
    GrantOut,
    GrantRevokeIn,
    MentorRelationIn,
    MentorRelationOut,
    SimulateIn,
    SimulateOut,
    SubjectIn,
    SubjectOut,
)

router = APIRouter(prefix="/api")


# ---------------------------------------------------------------------------
# 授权维护
# ---------------------------------------------------------------------------


@router.put(
    "/access/subjects",
    response_model=SubjectOut,
    tags=["access"],
)
def put_subject(body: SubjectIn, db: Session = Depends(get_db)) -> Any:
    return access_services.register_subject(
        db,
        subject_id=body.subject_id,
        org_id=body.org_id,
        role=body.role,
        is_active=body.is_active,
    )


@router.put(
    "/access/enrollments",
    response_model=EnrollmentOut,
    tags=["access"],
)
def put_enrollment(body: EnrollmentIn, db: Session = Depends(get_db)) -> Any:
    return access_services.register_enrollment(
        db, student_id=body.student_id, org_id=body.org_id
    )


@router.post(
    "/plans/{plan_version}/mentor-relations",
    response_model=MentorRelationOut,
    status_code=status.HTTP_201_CREATED,
    tags=["access"],
)
def post_mentor_relation(
    plan_version: str, body: MentorRelationIn, db: Session = Depends(get_db)
) -> Any:
    try:
        return access_services.add_mentor_relation(
            db,
            plan_version=plan_version,
            mentor_id=body.mentor_id,
            student_id=body.student_id,
        )
    except access_services.SubjectNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except access_services.PolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.delete(
    "/plans/{plan_version}/mentor-relations/{mentor_id}/{student_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["access"],
)
def delete_mentor_relation(
    plan_version: str, mentor_id: str, student_id: str, db: Session = Depends(get_db)
) -> None:
    access_services.remove_mentor_relation(
        db, plan_version=plan_version, mentor_id=mentor_id, student_id=student_id
    )


@router.post(
    "/plans/{plan_version}/grants",
    response_model=GrantOut,
    status_code=status.HTTP_201_CREATED,
    tags=["access"],
)
def post_grant(
    plan_version: str, body: GrantIn, db: Session = Depends(get_db)
) -> Any:
    try:
        return access_services.create_grant(
            db,
            plan_version=plan_version,
            subject_id=body.subject_id,
            fields=list(body.fields),
            student_id=body.student_id,
            is_delegation=body.is_delegation,
            granted_by=body.granted_by,
            expires_at=body.expires_at,
        )
    except access_services.SubjectNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except access_services.PolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/access/grants/{grant_id}/revoke",
    response_model=GrantOut,
    tags=["access"],
)
def post_revoke_grant(
    grant_id: str, body: GrantRevokeIn, db: Session = Depends(get_db)
) -> Any:
    try:
        return access_services.revoke_grant(
            db, grant_id=grant_id, actor_id=body.actor_id, reason=body.reason
        )
    except access_services.GrantNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/access/grants", response_model=list[GrantOut], tags=["access"])
def get_grants(
    subject_id: str | None = None, db: Session = Depends(get_db)
) -> Any:
    return access_services.list_grants(db, subject_id=subject_id)


# ---------------------------------------------------------------------------
# 模拟判定
# ---------------------------------------------------------------------------


@router.post(
    "/access/simulate",
    response_model=SimulateOut,
    tags=["access"],
)
def post_simulate(body: SimulateIn, db: Session = Depends(get_db)) -> Any:
    return access_services.simulate(
        db,
        subject_id=body.subject_id,
        plan_version=body.plan_version,
        student_id=body.student_id,
    )


@router.post("/access/reload", tags=["access"])
def post_reload(db: Session = Depends(get_db)) -> dict[str, str]:
    """丢弃进程内策略缓存并从数据库重载，用于验证重启后的策略加载。"""
    access_services.reload_policy(db)
    return {"status": "reloaded"}


# ---------------------------------------------------------------------------
# 受控查询
# ---------------------------------------------------------------------------


@router.get(
    "/plans/{plan_version}/students/{student_id}/records",
    tags=["access"],
)
def get_controlled_progress(
    plan_version: str,
    student_id: str,
    subject_id: str = Query(...),
    db: Session = Depends(get_db),
) -> Any:
    try:
        result = access_services.controlled_student_progress(
            db, plan_version=plan_version, student_id=student_id, subject_id=subject_id
        )
    except hours_services.PlanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except access_services.AccessDeniedError as exc:
        raise HTTPException(status_code=403, detail=exc.detail) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="student not found")
    return result


@router.get(
    "/plans/{plan_version}/controlled/snapshot",
    tags=["access"],
)
def get_controlled_snapshot(
    plan_version: str,
    subject_id: str = Query(...),
    db: Session = Depends(get_db),
) -> Any:
    try:
        return access_services.controlled_snapshot(
            db, plan_version=plan_version, subject_id=subject_id
        )
    except hours_services.PlanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/plans/{plan_version}/freezes/{freeze_id}/controlled",
    tags=["access"],
)
def get_controlled_freeze(
    plan_version: str,
    freeze_id: str,
    subject_id: str = Query(...),
    db: Session = Depends(get_db),
) -> Any:
    try:
        return access_services.controlled_freeze(
            db,
            plan_version=plan_version,
            freeze_id=freeze_id,
            subject_id=subject_id,
        )
    except (
        hours_services.PlanNotFoundError,
        hours_services.FreezeNotFoundError,
    ) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/plans/{plan_version}/freezes/{freeze_id}/controlled/students/{student_id}",
    tags=["access"],
)
def get_controlled_freeze_student(
    plan_version: str,
    freeze_id: str,
    student_id: str,
    subject_id: str = Query(...),
    db: Session = Depends(get_db),
) -> Any:
    try:
        result = access_services.controlled_freeze_student(
            db,
            plan_version=plan_version,
            freeze_id=freeze_id,
            student_id=student_id,
            subject_id=subject_id,
        )
    except (
        hours_services.PlanNotFoundError,
        hours_services.FreezeNotFoundError,
    ) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except access_services.AccessDeniedError as exc:
        raise HTTPException(status_code=403, detail=exc.detail) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="student not found")
    return result


# ---------------------------------------------------------------------------
# 批量导出
# ---------------------------------------------------------------------------


@router.post("/plans/{plan_version}/export", tags=["access"])
def post_export(
    plan_version: str, body: ExportRequest, db: Session = Depends(get_db)
) -> Any:
    try:
        return access_services.export_progress(
            db,
            plan_version=plan_version,
            subject_id=body.subject_id,
            student_ids=body.student_ids or None,
        )
    except hours_services.PlanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# 访问审计
# ---------------------------------------------------------------------------


@router.get(
    "/access/audits",
    response_model=list[AccessAuditOut],
    tags=["access"],
)
def get_access_audits(
    plan_version: str | None = None,
    subject_id: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
) -> Any:
    return access_services.list_access_audits(
        db, plan_version=plan_version, subject_id=subject_id, limit=limit
    )
