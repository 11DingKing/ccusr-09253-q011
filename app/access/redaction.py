"""字段级裁剪：地点、原因、导师意见按授权从输出中移除。

裁剪总是作用在深拷贝上；冻结快照存储的原始 JSON、汇总秒数与合规结论
保持不变，因此同一冻结快照无论谁来读取，冻结摘要都是一致的。
"""

from __future__ import annotations

import copy
from typing import Any, Iterable

REDACTED_VALUE = ""

# 敏感字段 -> 它在学生明细中的位置
_CHECKIN_FIELDS = ("location", "mentor_comment")
_ADJUSTMENT_FIELDS = ("reason",)


def _redact_checkin(checkin: dict[str, Any], hidden: Iterable[str]) -> None:
    for field_name in hidden:
        if field_name in _CHECKIN_FIELDS and field_name in checkin:
            checkin[field_name] = REDACTED_VALUE


def _redact_adjustment(adjustment: dict[str, Any], hidden: Iterable[str]) -> None:
    for field_name in hidden:
        if field_name in _ADJUSTMENT_FIELDS and field_name in adjustment:
            adjustment[field_name] = REDACTED_VALUE


def redact_student(
    student: dict[str, Any], visible_fields: Iterable[str]
) -> dict[str, Any]:
    """返回裁剪后的学生明细副本，汇总数字不做任何改动。"""
    result = copy.deepcopy(student)
    visible = set(visible_fields)
    hidden_checkins = [f for f in _CHECKIN_FIELDS if f not in visible]
    hidden_adjustments = [f for f in _ADJUSTMENT_FIELDS if f not in visible]
    for checkin in result.get("checkins", []):
        _redact_checkin(checkin, hidden_checkins)
    for adjustment in result.get("adjustments", []):
        _redact_adjustment(adjustment, hidden_adjustments)
    return result


def redact_snapshot(
    snapshot: dict[str, Any], visible_fields: Iterable[str]
) -> dict[str, Any]:
    """裁剪整份快照（含冻结快照）的明细字段。

    顶层汇总（required_seconds、event_cutoff_id、generated_at 等）与每个
    学生的秒数、学时单元、合规结论均原样保留。
    """
    result = copy.deepcopy(snapshot)
    result["students"] = [
        redact_student(student, visible_fields)
        for student in result.get("students", [])
    ]
    return result
