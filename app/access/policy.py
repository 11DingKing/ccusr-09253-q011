"""机构、角色与学生关系驱动的字段级访问策略引擎。

角色基线字段：

- 辅导员 (counselor)：地点 location、原因 reason
- 导师 (mentor)：地点 location、导师意见 mentor_comment
- 审计人员 (auditor)：原因 reason、导师意见 mentor_comment

导师只能看到自己指导的学生（按培养方案限定）；辅导员与审计人员只能看到
本机构学生。字段级授权（含委托）可在基线之上叠加敏感字段；撤销或过期后
立即失效。
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from . import repository

SENSITIVE_FIELDS: tuple[str, ...] = repository.SENSITIVE_FIELDS

ROLE_BASE_FIELDS: dict[str, frozenset[str]] = {
    "counselor": frozenset({"location", "reason"}),
    "mentor": frozenset({"location", "mentor_comment"}),
    "auditor": frozenset({"reason", "mentor_comment"}),
}


class PolicyError(ValueError):
    """策略维护请求不合法。"""


class SubjectNotFound(PolicyError):
    pass


class GrantNotFound(PolicyError):
    pass


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        raise PolicyError("expires_at 必须带时区")
    return value.astimezone(UTC)


class Decision:
    """一次字段级访问判定的结果。"""

    def __init__(
        self,
        *,
        decision: str,
        visible_fields: frozenset[str],
        reasons: list[str],
    ) -> None:
        self.decision = decision
        self.visible_fields = visible_fields
        self.reasons = reasons

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    @property
    def redacted_fields(self) -> tuple[str, ...]:
        return tuple(f for f in SENSITIVE_FIELDS if f not in self.visible_fields)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "visible_fields": sorted(self.visible_fields),
            "redacted_fields": list(self.redacted_fields),
            "reasons": list(self.reasons),
        }


class PolicyStore:
    """策略快照缓存。

    授权维护事务提交后调用 :meth:`invalidate`，下一次判定即从数据库重新
    加载，因此授权变化立即影响后续读取；进程重启后缓存为空，会自动从持久
    化数据加载全部策略。
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._data: dict[str, Any] | None = None

    def invalidate(self) -> None:
        with self._lock:
            self._data = None

    def load(self, db: Session) -> dict[str, Any]:
        with self._lock:
            if self._data is None:
                self._data = repository.load_policy_data(db)
            return self._data

    def reload(self, db: Session) -> dict[str, Any]:
        """模拟进程重启：丢弃缓存并从数据库重新加载策略。"""
        self.invalidate()
        return self.load(db)

    def evaluate(
        self,
        db: Session,
        *,
        subject_id: str,
        plan_version: str,
        student_id: str,
        now: datetime | None = None,
    ) -> Decision:
        instant = (now or _utcnow()).astimezone(UTC)
        data = self.load(db)
        subject = data["subjects"].get(subject_id)
        if subject is None:
            return Decision(
                decision="deny",
                visible_fields=frozenset(),
                reasons=[f"主体 {subject_id} 不存在"],
            )
        if not subject["is_active"]:
            return Decision(
                decision="deny",
                visible_fields=frozenset(),
                reasons=[f"主体 {subject_id} 已停用"],
            )

        role = subject["role"]
        org_id = subject["org_id"]
        reasons: list[str] = []

        related = False
        if role == "mentor":
            related = (subject_id, student_id, plan_version) in data[
                "mentor_relations"
            ]
            if related:
                reasons.append("导师指导关系命中")
            else:
                reasons.append("导师与该生在此培养方案下无指导关系")
        else:
            student_org = data["enrollments"].get(student_id)
            if student_org is None:
                reasons.append(f"学生 {student_id} 无学籍记录")
            elif student_org == org_id:
                related = True
                label = "辅导员" if role == "counselor" else "审计人员"
                reasons.append(f"{label}机构关系命中（{org_id}）")
            else:
                reasons.append(
                    f"机构不匹配：主体属于 {org_id}，学生属于 {student_org}"
                )

        visible: set[str] = set()
        if related:
            visible.update(ROLE_BASE_FIELDS[role])

        # 字段级授权 / 委托：基线之上叠加，撤销或过期立即失效。
        for grant in data["grants"]:
            if grant["subject_id"] != subject_id:
                continue
            if grant["is_revoked"]:
                continue
            if grant["expires_at"] is not None and instant >= grant["expires_at"]:
                continue
            if grant["plan_version"] is not None and grant["plan_version"] != plan_version:
                continue
            if grant["student_id"] is not None and grant["student_id"] != student_id:
                continue
            added = [f for f in grant["fields"] if f not in visible]
            visible.update(grant["fields"])
            kind = "委托" if grant["is_delegation"] else "授权"
            scope = grant["student_id"] or "机构范围"
            if added:
                reasons.append(
                    f"{kind} {grant['grant_id']}（{scope}）追加字段：{','.join(added)}"
                )
            else:
                reasons.append(
                    f"{kind} {grant['grant_id']}（{scope}）未追加新字段"
                )

        if not visible:
            return Decision(
                decision="deny", visible_fields=frozenset(), reasons=reasons
            )
        return Decision(
            decision="allow", visible_fields=frozenset(visible), reasons=reasons
        )


_store = PolicyStore()


def get_policy_store() -> PolicyStore:
    return _store
