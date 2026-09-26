"""字段级访问策略：越权、委托、撤销、重启加载与冻结一致性测试。"""

from __future__ import annotations

from tests.conftest import SHANGHAI_PLAN

from app.access.policy import PolicyStore

PLAN = SHANGHAI_PLAN["plan_version"]


def _subject(subject_id, role, org="O1", is_active=True):
    return {
        "subject_id": subject_id,
        "org_id": org,
        "role": role,
        "is_active": is_active,
    }


def _setup_world(client) -> None:
    assert client.post("/api/plans", json=SHANGHAI_PLAN).status_code == 201
    # 机构与角色
    client.put("/api/access/subjects", json=_subject("C1", "counselor"))
    client.put("/api/access/subjects", json=_subject("C2", "counselor", org="O2"))
    client.put("/api/access/subjects", json=_subject("M1", "mentor"))
    client.put("/api/access/subjects", json=_subject("M2", "mentor"))
    client.put("/api/access/subjects", json=_subject("A1", "auditor"))
    # 学籍
    client.put("/api/access/enrollments", json={"student_id": "S1", "org_id": "O1"})
    client.put("/api/access/enrollments", json={"student_id": "S2", "org_id": "O1"})
    client.put("/api/access/enrollments", json={"student_id": "S3", "org_id": "O2"})
    # M1 只指导 S1
    resp = client.post(
        f"/api/plans/{PLAN}/mentor-relations",
        json={"mentor_id": "M1", "student_id": "S1"},
    )
    assert resp.status_code == 201, resp.text

    events = [
        {
            "event_id": "E-01",
            "event_type": "checkin",
            "student_id": "S1",
            "payload": {
                "activity_id": "A1",
                "activity_type": "internship",
                "location": "工程训练中心301",
                "check_in_at": "2024-03-15T08:00:00+08:00",
                "check_out_at": "2024-03-15T12:00:00+08:00",
            },
        },
        {
            "event_id": "E-02",
            "event_type": "mentor_confirm",
            "student_id": "S1",
            "payload": {"checkin_event_id": "E-01", "comment": "实习表现良好"},
        },
        {
            "event_id": "E-03",
            "event_type": "leave_correction",
            "student_id": "S1",
            "payload": {"adjustment_seconds": -1800, "reason": "病假扣减"},
        },
        {
            "event_id": "E-11",
            "event_type": "checkin",
            "student_id": "S2",
            "payload": {
                "activity_id": "A2",
                "activity_type": "regular",
                "location": "教学楼202",
                "check_in_at": "2024-03-16T08:00:00+08:00",
                "check_out_at": "2024-03-16T10:00:00+08:00",
            },
        },
        {
            "event_id": "E-21",
            "event_type": "checkin",
            "student_id": "S3",
            "payload": {
                "activity_id": "A3",
                "activity_type": "regular",
                "location": "外单位场地",
                "check_in_at": "2024-03-16T09:00:00+08:00",
                "check_out_at": "2024-03-16T11:00:00+08:00",
            },
        },
    ]
    resp = client.post(f"/api/plans/{PLAN}/events", json={"events": events})
    assert resp.status_code == 201, resp.text


def _records(client, subject_id, student_id):
    return client.get(
        f"/api/plans/{PLAN}/students/{student_id}/records",
        params={"subject_id": subject_id},
    )


# ---------------------------------------------------------------------------
# 角色基线字段裁剪
# ---------------------------------------------------------------------------


def test_role_baseline_field_redaction(client):
    _setup_world(client)

    counselor = _records(client, "C1", "S1").json()
    assert counselor["checkins"][0]["location"] == "工程训练中心301"
    assert counselor["adjustments"][0]["reason"] == "病假扣减"
    # 辅导员基线看不到导师意见
    assert counselor["checkins"][0]["mentor_comment"] == ""

    mentor = _records(client, "M1", "S1").json()
    assert mentor["checkins"][0]["location"] == "工程训练中心301"
    assert mentor["checkins"][0]["mentor_comment"] == "实习表现良好"
    # 导师基线看不到请假原因
    assert mentor["adjustments"][0]["reason"] == ""

    auditor = _records(client, "A1", "S1").json()
    assert auditor["adjustments"][0]["reason"] == "病假扣减"
    assert auditor["checkins"][0]["mentor_comment"] == "实习表现良好"
    # 审计人员基线看不到地点
    assert auditor["checkins"][0]["location"] == ""

    # 汇总数字对三种角色完全一致
    for view in (counselor, mentor, auditor):
        assert view["confirmed_seconds"] == 4 * 3600
        assert view["adjustment_seconds"] == -1800
        assert view["total_seconds"] == 4 * 3600 - 1800


# ---------------------------------------------------------------------------
# 越权访问
# ---------------------------------------------------------------------------


def test_cross_org_counselor_is_denied_and_audited(client):
    _setup_world(client)
    resp = _records(client, "C2", "S1")  # O2 辅导员访问 O1 学生
    assert resp.status_code == 403

    audits = client.get(
        "/api/access/audits", params={"subject_id": "C2"}
    ).json()
    deny = [a for a in audits if a["decision"] == "deny"]
    assert deny, "越权访问必须记录 deny 审计"
    entry = deny[0]
    assert entry["student_id"] == "S1"
    assert entry["visible_fields"] == []


def test_mentor_without_relation_is_denied(client):
    _setup_world(client)
    # M2 与任何学生都没有指导关系
    assert _records(client, "M2", "S1").status_code == 403
    # M1 是 S1 的导师但不是 S2 的导师
    assert _records(client, "M1", "S1").status_code == 200
    assert _records(client, "M1", "S2").status_code == 403


def test_unknown_subject_and_inactive_subject_denied(client):
    _setup_world(client)
    assert _records(client, "NOBODY", "S1").status_code == 403

    client.put(
        "/api/access/subjects",
        json=_subject("C1", "counselor", is_active=False),
    )
    assert _records(client, "C1", "S1").status_code == 403


def test_controlled_snapshot_excludes_unrelated_students(client):
    _setup_world(client)
    snap = client.get(
        f"/api/plans/{PLAN}/controlled/snapshot",
        params={"subject_id": "M1"},
    ).json()
    ids = {s["student_id"] for s in snap["students"]}
    assert ids == {"S1"}

    snap_counselor = client.get(
        f"/api/plans/{PLAN}/controlled/snapshot",
        params={"subject_id": "C1"},
    ).json()
    assert {s["student_id"] for s in snap_counselor["students"]} == {"S1", "S2"}


# ---------------------------------------------------------------------------
# 委托授权
# ---------------------------------------------------------------------------


def test_delegation_grants_additional_field_scoped_to_student(client):
    _setup_world(client)
    # 委托前：辅导员看不到 S1 的导师意见
    before = _records(client, "C1", "S1").json()
    assert before["checkins"][0]["mentor_comment"] == ""

    resp = client.post(
        f"/api/plans/{PLAN}/grants",
        json={
            "subject_id": "C1",
            "fields": ["mentor_comment"],
            "student_id": "S1",
            "is_delegation": True,
            "granted_by": "A1",
        },
    )
    assert resp.status_code == 201, resp.text

    after = _records(client, "C1", "S1").json()
    assert after["checkins"][0]["mentor_comment"] == "实习表现良好"
    # 委托仅限 S1：S2 仍然裁剪导师意见（S2 本来就没有该字段，但字段裁剪一致）
    s2 = _records(client, "C1", "S2").json()
    assert s2["checkins"][0]["mentor_comment"] == ""

    # 委托不能越过机构边界：C2 仍被整体拒绝
    assert _records(client, "C2", "S1").status_code == 403


def test_delegation_requires_granted_by(client):
    _setup_world(client)
    resp = client.post(
        f"/api/plans/{PLAN}/grants",
        json={
            "subject_id": "C1",
            "fields": ["mentor_comment"],
            "is_delegation": True,
        },
    )
    assert resp.status_code == 422


def test_expired_grant_has_no_effect(client):
    _setup_world(client)
    resp = client.post(
        f"/api/plans/{PLAN}/grants",
        json={
            "subject_id": "C1",
            "fields": ["mentor_comment"],
            "student_id": "S1",
            "expires_at": "2020-01-01T00:00:00+00:00",
        },
    )
    assert resp.status_code == 201
    view = _records(client, "C1", "S1").json()
    assert view["checkins"][0]["mentor_comment"] == ""


# ---------------------------------------------------------------------------
# 授权撤销：立即生效，且既有审计记录不被改写
# ---------------------------------------------------------------------------


def test_revocation_takes_effect_immediately(client):
    _setup_world(client)
    grant = client.post(
        f"/api/plans/{PLAN}/grants",
        json={"subject_id": "C1", "fields": ["mentor_comment"], "student_id": "S1"},
    ).json()

    assert _records(client, "C1", "S1").json()["checkins"][0][
        "mentor_comment"
    ] == "实习表现良好"

    resp = client.post(
        f"/api/access/grants/{grant['grant_id']}/revoke",
        json={"actor_id": "admin-1", "reason": "学期结束收回授权"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["is_revoked"] is True

    # 撤销立即影响后续读取
    assert _records(client, "C1", "S1").json()["checkins"][0][
        "mentor_comment"
    ] == ""


def test_existing_audit_records_survive_revocation(client):
    _setup_world(client)
    grant = client.post(
        f"/api/plans/{PLAN}/grants",
        json={"subject_id": "C1", "fields": ["mentor_comment"], "student_id": "S1"},
    ).json()
    _records(client, "C1", "S1")  # 授权期间的允许访问
    _records(client, "C2", "S1")  # 一次越权拒绝

    client.post(
        f"/api/access/grants/{grant['grant_id']}/revoke",
        json={"actor_id": "admin-1", "reason": "收回"},
    )
    _records(client, "C1", "S1")  # 撤销后的访问

    audits = client.get(
        "/api/access/audits", params={"subject_id": "C1"}
    ).json()
    reads = [a for a in audits if a["action"] == "read_progress"]
    assert len(reads) == 2
    # 审计按 id 倒序：最新一条（撤销后）看不到导师意见
    assert "mentor_comment" not in reads[0]["visible_fields"]
    assert "mentor_comment" in reads[0]["redacted_fields"]
    # 早先的审计记录原样保留，没有被撤销动作改写
    assert "mentor_comment" in reads[1]["visible_fields"]
    assert reads[1]["decision"] == "allow"

    revoke_entries = [a for a in client.get("/api/access/audits").json()
                      if a["action"] == "revoke_grant"]
    assert revoke_entries and revoke_entries[0]["detail"] == "收回"


# ---------------------------------------------------------------------------
# 模拟判定
# ---------------------------------------------------------------------------


def test_simulate_reports_decision_without_mutating_audits(client):
    _setup_world(client)
    resp = client.post(
        "/api/access/simulate",
        json={"subject_id": "C1", "plan_version": PLAN, "student_id": "S1"},
    )
    body = resp.json()
    assert body["decision"] == "allow"
    assert set(body["visible_fields"]) == {"location", "reason"}
    assert "mentor_comment" in body["redacted_fields"]

    cross = client.post(
        "/api/access/simulate",
        json={"subject_id": "C2", "plan_version": PLAN, "student_id": "S1"},
    ).json()
    assert cross["decision"] == "deny"
    assert cross["visible_fields"] == []

    # 模拟不是真实访问，不写访问审计
    audits = client.get("/api/access/audits").json()
    assert all(a["action"] != "simulate" for a in audits)


# ---------------------------------------------------------------------------
# 冻结摘要一致性
# ---------------------------------------------------------------------------


def test_freeze_redaction_keeps_summary_and_stored_snapshot_intact(client):
    _setup_world(client)
    freeze_id = "F-2024S"
    frozen = client.post(
        f"/api/plans/{PLAN}/freezes/{freeze_id}", json={}
    ).json()
    frozen_s1 = next(s for s in frozen["students"] if s["student_id"] == "S1")
    assert frozen_s1["checkins"][0]["location"] == "工程训练中心301"
    stored_total = frozen_s1["total_seconds"]

    # 审计人员视图：地点裁剪，其余敏感字段可见
    served = client.get(
        f"/api/plans/{PLAN}/freezes/{freeze_id}/controlled",
        params={"subject_id": "A1"},
    ).json()
    served_s1 = next(s for s in served["students"] if s["student_id"] == "S1")
    assert served_s1["checkins"][0]["location"] == ""
    assert served_s1["checkins"][0]["mentor_comment"] == "实习表现良好"
    assert served_s1["total_seconds"] == stored_total
    assert served_s1["confirmed_seconds"] == frozen_s1["confirmed_seconds"]
    assert served_s1["meets_requirement"] == frozen_s1["meets_requirement"]

    # 原始冻结读取接口仍返回完整明细，冻结快照未被改写
    raw = client.get(f"/api/plans/{PLAN}/freezes/{freeze_id}").json()
    raw_s1 = next(s for s in raw["students"] if s["student_id"] == "S1")
    assert raw_s1["checkins"][0]["location"] == "工程训练中心301"
    assert raw_s1["total_seconds"] == stored_total

    # 冻结学生级受控读取同样裁剪
    resp = client.get(
        f"/api/plans/{PLAN}/freezes/{freeze_id}/controlled/students/S1",
        params={"subject_id": "C2"},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 批量导出应用相同规则
# ---------------------------------------------------------------------------


def test_batch_export_applies_same_redaction_and_scoping(client):
    _setup_world(client)
    resp = client.post(
        f"/api/plans/{PLAN}/export",
        json={"subject_id": "C1", "student_ids": ["S1", "S2", "S3"]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # O1 辅导员只能导出 O1 学生，越权学生被排除
    assert {s["student_id"] for s in body["students"]} == {"S1", "S2"}
    assert body["exported_count"] == 2
    s1 = next(s for s in body["students"] if s["student_id"] == "S1")
    assert s1["checkins"][0]["location"] == "工程训练中心301"
    assert s1["checkins"][0]["mentor_comment"] == ""

    # 导师导出只能得到自己指导的学生
    mentor_export = client.post(
        f"/api/plans/{PLAN}/export", json={"subject_id": "M1"}
    ).json()
    assert {s["student_id"] for s in mentor_export["students"]} == {"S1"}
    only = mentor_export["students"][0]
    assert only["checkins"][0]["mentor_comment"] == "实习表现良好"
    assert only["adjustments"][0]["reason"] == ""

    # 导出动作逐条进入访问审计，包括被排除的越权学生
    audits = client.get("/api/access/audits").json()
    exports = [a for a in audits if a["action"] == "export"]
    assert {a["student_id"] for a in exports} == {"S1", "S2", "S3"}
    assert any(a["decision"] == "deny" and a["student_id"] == "S3" for a in exports)


# ---------------------------------------------------------------------------
# 重启后的策略加载
# ---------------------------------------------------------------------------


def test_policy_survives_cache_restart(client, db):
    _setup_world(client)
    client.post(
        f"/api/plans/{PLAN}/grants",
        json={
            "subject_id": "C1",
            "fields": ["mentor_comment"],
            "student_id": "S1",
            "is_delegation": True,
            "granted_by": "A1",
        },
    )

    # 通过 HTTP 接口丢弃进程内缓存（模拟重启）
    assert client.post("/api/access/reload").status_code == 200
    view = _records(client, "C1", "S1").json()
    assert view["checkins"][0]["mentor_comment"] == "实习表现良好"

    # 全新的 PolicyStore 实例（等价于新进程冷启动）从数据库加载策略
    fresh = PolicyStore()
    decision = fresh.evaluate(
        db, subject_id="C1", plan_version=PLAN, student_id="S1"
    )
    assert decision.allowed
    assert "mentor_comment" in decision.visible_fields

    # 冷启动后撤销状态同样从数据库恢复
    grants = client.get("/api/access/grants", params={"subject_id": "C1"}).json()
    grant_id = grants[0]["grant_id"]
    client.post(
        f"/api/access/grants/{grant_id}/revoke",
        json={"actor_id": "admin-1", "reason": "收回"},
    )
    fresh2 = PolicyStore()
    decision2 = fresh2.evaluate(
        db, subject_id="C1", plan_version=PLAN, student_id="S1"
    )
    assert "mentor_comment" not in decision2.visible_fields


def test_mentor_relation_removal_blocks_subsequent_reads(client):
    _setup_world(client)
    assert _records(client, "M1", "S1").status_code == 200
    resp = client.delete(f"/api/plans/{PLAN}/mentor-relations/M1/S1")
    assert resp.status_code == 204
    assert _records(client, "M1", "S1").status_code == 403
