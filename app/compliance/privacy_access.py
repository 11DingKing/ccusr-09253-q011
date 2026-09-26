"""隐私字段分级访问：机构/角色/学生关系驱动的判定与字段级裁剪。

该模块为纯函数实现，不依赖数据库；服务层负责加载主体、关系与授权后
调用 ``decide`` 得到判定，再用 ``project_student`` 对学时明细做字段级
裁剪。裁剪只影响响应投影，汇总数字与冻结快照的存储内容保持不变。
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Callable, Iterable, Mapping, Sequence

# 受字段级访问控制的敏感字段。
SENSITIVE_FIELDS: tuple[str, ...] = ("location", "reason", "mentor_comment")

LOCATION = "location"
REASON = "reason"
MENTOR_COMMENT = "mentor_comment"


class Role(StrEnum):
    COUNSELOR = "counselor"
    MENTOR = "mentor"
    AUDITOR = "auditor"
    GRANT_ADMIN = "grant_admin"


class ScopeType(StrEnum):
    INSTITUTION = "institution"
    PLAN = "plan"
    STUDENT = "student"


# 各角色的基线敏感字段（未持任何授权时的可见集合）。
BASELINE_FIELDS: Mapping[Role, frozenset[str]] = {
    Role.COUNSELOR: frozenset(),
    Role.MENTOR: frozenset({LOCATION, MENTOR_COMMENT}),
    Role.AUDITOR: frozenset({REASON, MENTOR_COMMENT}),
    Role.GRANT_ADMIN: frozenset(),
}


class PolicyError(ValueError):
    """封装领域状态与业务约束。"""


@dataclass(frozen=True)
class ActorContext:
    actor_id: str
    role: str
    institution_id: str


@dataclass(frozen=True)
class GrantView:
    grant_id: str
    actor_id: str
    scope_type: str
    scope_value: str
    fields: frozenset[str]
    status: str
    expires_at: datetime | None = None
    delegated_by: str | None = None


@dataclass(frozen=True)
class AccessDecision:
    actor_id: str
    student_id: str
    plan_version: str
    allowed: bool
    visible_fields: frozenset[str]
    redacted_fields: frozenset[str]
    sources: tuple[str, ...] = ()
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "student_id": self.student_id,
            "plan_version": self.plan_version,
            "allowed": self.allowed,
            "visible_fields": sorted(self.visible_fields),
            "redacted_fields": sorted(self.redacted_fields),
            "sources": list(self.sources),
            "reason": self.reason,
        }


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def grant_is_active(grant: GrantView, now: datetime) -> bool:
    """授权仅在 active 且未过期时生效；撤销立即生效。"""
    if grant.status != "active":
        return False
    if grant.expires_at is not None and _utc(grant.expires_at) <= _utc(now):
        return False
    return True


def grant_covers(
    grant: GrantView,
    *,
    plan_version: str,
    student_id: str,
    student_institution_id: str | None,
) -> bool:
    """判断授权作用域是否覆盖目标学生（与有效期/状态无关）。"""
    if grant.scope_type == ScopeType.INSTITUTION.value:
        return (
            student_institution_id is not None
            and grant.scope_value == student_institution_id
        )
    if grant.scope_type == ScopeType.PLAN.value:
        return grant.scope_value == plan_version
    if grant.scope_type == ScopeType.STUDENT.value:
        return grant.scope_value == student_id
    return False


def scope_contains(parent: GrantView, child: GrantView) -> bool:
    """委托授权的作用域必须不超出父授权（同类型且取值一致）。"""
    return (
        parent.scope_type == child.scope_type
        and parent.scope_value == child.scope_value
    )


def baseline_scope_allows(
    actor: ActorContext,
    *,
    student_id: str,
    student_institution_id: str | None,
    assigned_student_ids: Iterable[str],
) -> bool:
    """角色基线可见范围：辅导员看本机构，导师看名下学生，审计员看全部。"""
    try:
        role = Role(actor.role)
    except ValueError:
        return False
    if role == Role.AUDITOR:
        return True
    if role == Role.COUNSELOR:
        return (
            student_institution_id is not None
            and student_institution_id == actor.institution_id
        )
    if role == Role.MENTOR:
        return student_id in set(assigned_student_ids)
    return False


def decide(
    actor: ActorContext,
    *,
    plan_version: str,
    student_id: str,
    student_institution_id: str | None,
    assigned_student_ids: Iterable[str],
    grants: Sequence[GrantView],
    now: datetime,
    resolve_grant: Callable[[str], GrantView | None] | None = None,
) -> AccessDecision:
    """对单个学生做访问判定。

    可见字段 = （基线范围允许时的角色基线字段）∪ 覆盖该学生的有效
    授权字段；委托授权沿 ``delegated_by`` 链向上解析，字段取链上各层
    的交集，任一环节失效（撤销/过期/不覆盖目标）则该委托不贡献字段。
    """
    assigned = set(assigned_student_ids)
    grants_by_id = {g.grant_id: g for g in grants}

    def _resolve(grant_id: str) -> GrantView | None:
        if grant_id in grants_by_id:
            return grants_by_id[grant_id]
        if resolve_grant is not None:
            return resolve_grant(grant_id)
        return None

    allowed = baseline_scope_allows(
        actor,
        student_id=student_id,
        student_institution_id=student_institution_id,
        assigned_student_ids=assigned,
    )
    # 角色基线字段仅在基线范围本身允许访问时生效；若访问权完全来自
    # 授权/委托，可见字段只由授权贡献，保证委托的子集约束不被角色
    # 基线悄悄放大。
    fields: set[str] = set()
    if allowed:
        try:
            role = Role(actor.role)
            fields = set(BASELINE_FIELDS.get(role, frozenset()))
        except ValueError:
            fields = set()
    sources: list[str] = []

    def _contribute(grant: GrantView, chain: frozenset[str]) -> set[str]:
        """沿委托链解析授权实际贡献的字段（含环检测）。"""
        if grant.grant_id in chain:
            return set()
        if not grant_is_active(grant, now):
            return set()
        if not grant_covers(
            grant,
            plan_version=plan_version,
            student_id=student_id,
            student_institution_id=student_institution_id,
        ):
            return set()
        if grant.delegated_by is None:
            return set(grant.fields)
        parent = _resolve(grant.delegated_by)
        if parent is None:
            return set()
        parent_fields = _contribute(parent, chain | {grant.grant_id})
        return set(grant.fields) & parent_fields

    for grant in grants:
        if grant.actor_id != actor.actor_id:
            continue
        gained = _contribute(grant, frozenset())
        if gained:
            allowed = True
            fields |= gained
            sources.append(grant.grant_id)

    fields &= set(SENSITIVE_FIELDS)
    redacted = set(SENSITIVE_FIELDS) - fields
    if not allowed:
        fields = set()
        redacted = set(SENSITIVE_FIELDS)
        sources = []
        reason = "no baseline scope or active grant covers this student"
    else:
        reason = "ok"
    return AccessDecision(
        actor_id=actor.actor_id,
        student_id=student_id,
        plan_version=plan_version,
        allowed=allowed,
        visible_fields=frozenset(fields),
        redacted_fields=frozenset(redacted),
        sources=tuple(sorted(sources)),
        reason=reason,
    )


def project_student(
    student: Mapping[str, Any], visible_fields: Iterable[str]
) -> dict[str, Any]:
    """按可见字段裁剪单个学生的学时明细。

    只裁剪 ``checkins`` 中的地点/导师意见与 ``adjustments`` 中的原因；
    汇总数字（学时、课时、达标标记、每日合计）原样保留，保证冻结摘要
    的一致性。返回新字典，不改写输入。
    """
    visible = set(visible_fields) & set(SENSITIVE_FIELDS)
    redacted = sorted(set(SENSITIVE_FIELDS) - visible)
    projected = copy.deepcopy(dict(student))
    for checkin in projected.get("checkins", []):
        if LOCATION not in visible:
            checkin["location"] = None
        if MENTOR_COMMENT not in visible:
            checkin["mentor_comment"] = None
    for adjustment in projected.get("adjustments", []):
        if REASON not in visible:
            adjustment["reason"] = None
    projected["redacted_fields"] = redacted
    return projected


def summary_totals(student: Mapping[str, Any]) -> dict[str, Any]:
    """提取冻结摘要的一致性字段，用于校验裁剪前后未发生变化。"""
    return {
        key: student.get(key)
        for key in (
            "student_id",
            "confirmed_seconds",
            "pending_seconds",
            "adjustment_seconds",
            "total_seconds",
            "lesson_units",
            "pending_lesson_units",
            "meets_requirement",
        )
    }
