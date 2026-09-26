"""隐私字段分级访问：越权、委托、撤销、导出与重启加载的端到端测试。"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app import access_control
from app.models import AccessGrant, Base
from tests.conftest import SHANGHAI_PLAN

PV = SHANGHAI_PLAN["plan_version"]
HEADERS_C1 = {"X-Actor-Id": "C1"}
HEADERS_M1 = {"X-Actor-Id": "M1"}
HEADERS_M2 = {"X-Actor-Id": "M2"}
HEADERS_A1 = {"X-Actor-Id": "A1"}
HEADERS_ADMIN = {"X-Actor-Id": "G1"}


def _create_plan(client):
    resp = client.post("/api/plans", json=SHANGHAI_PLAN)
    assert resp.status_code == 201, resp.text


def _import_events(client):
    resp = client.post(
        f"/api/plans/{PV}/events",
        json={
            "events": [
                {
                    "event_id": "E-01",
                    "event_type": "checkin",
                    "student_id": "S1",
                    "payload": {
                        "activity_id": "A1",
                        "activity_type": "internship",
                        "check_in_at": "2024-03-15T08:00:00+08:00",
                        "check_out_at": "2024-03-15T12:00:00+08:00",
                        "location": "实训楼A-301",
                    },
                },
                {
                    "event_id": "E-02",
                    "event_type": "mentor_confirm",
                    "student_id": "S1",
                    "payload": {
                        "checkin_event_id": "E-01",
                        "comment": "表现优秀，同意计入",
                        "mentor_id": "M1",
                    },
                },
                {
                    "event_id": "E-03",
                    "event_type": "leave_correction",
                    "student_id": "S1",
                    "payload": {"adjustment_seconds": -900, "reason": "迟到十五分钟"},
                },
                {
                    "event_id": "E-11",
                    "event_type": "checkin",
                    "student_id": "S2",
                    "payload": {
                        "activity_id": "A2",
                        "activity_type": "regular",
                        "check_in_at": "2024-03-15T08:00:00+08:00",
                        "check_out_at": "2024-03-15T09:00:00+08:00",
                        "location": "图书馆二层",
                    },
                },
                {
                    "event_id": "E-12",
                    "event_type": "leave_correction",
                    "student_id": "S2",
                    "payload": {"adjustment_seconds": 600, "reason": "补录加班"},
                },
            ]
        },
    )
    assert resp.status_code == 201, resp.text


def _register_actors(client):
    for actor_id, role, institution in (
        ("C1", "counselor", "INST-1"),
        ("M1", "mentor", "INST-1"),
        ("M2", "mentor", "INST-1"),
        ("A1", "auditor", "INST-9"),
        ("G1", "grant_admin", "INST-0"),
    ):
        resp = client.put(
            f"/api/access/actors/{actor_id}",
            json={"role": role, "institution_id": institution},
        )
        assert resp.status_code == 200, resp.text


def _setup_relations(client):
    assert client.put(
        f"/api/access/enrollments/{PV}/S1", json={"institution_id": "INST-1"}
    ).status_code == 200
    assert client.put(
        f"/api/access/enrollments/{PV}/S2", json={"institution_id": "INST-2"}
    ).status_code == 200
    assert client.put(
        "/api/access/mentor-assignments/M1/S1", json={"active": True}
    ).status_code == 200


@pytest.fixture
def seeded(client):
    _create_plan(client)
    _import_events(client)
    _register_actors(client)
    _setup_relations(client)
    return client


def _progress(client, student, headers):
    return client.get(
        f"/api/access/plans/{PV}/students/{student}/progress", headers=headers
    )


# ---------------------------------------------------------------------------
# 基线角色矩阵与越权
# ---------------------------------------------------------------------------


def test_counselor_baseline_redacts_all_sensitive_fields(seeded):
    resp = _progress(seeded, "S1", HEADERS_C1)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # 汇总数字保持完整（冻结摘要一致性）。
    assert body["total_seconds"] == 4 * 3600 - 900
    assert body["confirmed_seconds"] == 4 * 3600
    assert body["adjustment_seconds"] == -900
    checkin = body["checkins"][0]
    assert checkin["location"] is None
    assert checkin["mentor_comment"] is None
    assert body["adjustments"][0]["reason"] is None
    assert body["redacted_fields"] == ["location", "mentor_comment", "reason"]


def test_counselor_cannot_read_other_institution_student(seeded):
    resp = _progress(seeded, "S2", HEADERS_C1)
    assert resp.status_code == 403
    # 越权访问也会留下审计记录。
    logs = seeded.get(
        "/api/access/audit-logs", params={"actor_id": "C1", "student_id": "S2"}
    ).json()
    assert len(logs) == 1
    assert logs[0]["decision"] == "deny"
    assert logs[0]["action"] == "read_progress"


def test_mentor_baseline_sees_location_and_comment_but_not_reason(seeded):
    resp = _progress(seeded, "S1", HEADERS_M1)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    checkin = body["checkins"][0]
    assert checkin["location"] == "实训楼A-301"
    assert checkin["mentor_comment"] == "表现优秀，同意计入"
    assert checkin["confirmed_by"] == "M1"
    assert body["adjustments"][0]["reason"] is None
    assert body["redacted_fields"] == ["reason"]


def test_mentor_cannot_read_unassigned_student(seeded):
    assert _progress(seeded, "S2", HEADERS_M1).status_code == 403


def test_mentor_assignment_deactivation_removes_access(seeded):
    assert seeded.put(
        "/api/access/mentor-assignments/M1/S1", json={"active": False}
    ).status_code == 200
    assert _progress(seeded, "S1", HEADERS_M1).status_code == 403


def test_auditor_sees_reason_and_comment_but_not_location(seeded):
    resp = _progress(seeded, "S2", HEADERS_A1)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["checkins"][0]["location"] is None
    assert body["adjustments"][0]["reason"] == "补录加班"
    assert body["redacted_fields"] == ["location"]


def test_unknown_actor_and_missing_header_are_rejected(seeded):
    assert _progress(seeded, "S1", {"X-Actor-Id": "NOBODY"}).status_code == 404
    assert _progress(seeded, "S1", {}).status_code == 401


def test_grant_admin_has_no_data_access(seeded):
    assert _progress(seeded, "S1", HEADERS_ADMIN).status_code == 403


def test_raw_endpoints_remain_uncontrolled(seeded):
    """既有接口保持原语义，返回完整明细。"""
    body = seeded.get(f"/api/plans/{PV}/students/S1/progress").json()
    assert body["checkins"][0]["location"] == "实训楼A-301"
    assert body["checkins"][0]["mentor_comment"] == "表现优秀，同意计入"
    assert body["adjustments"][0]["reason"] == "迟到十五分钟"


# ---------------------------------------------------------------------------
# 授权：扩大字段、撤销与过期立即生效
# ---------------------------------------------------------------------------


def _create_grant(client, grant_id, actor_id, scope_type, scope_value, fields, **kw):
    payload = {
        "grant_id": grant_id,
        "actor_id": actor_id,
        "scope_type": scope_type,
        "scope_value": scope_value,
        "fields": fields,
    }
    payload.update(kw)
    return client.post("/api/access/grants", json=payload, headers=HEADERS_ADMIN)


def test_grant_widens_fields_and_revoke_applies_immediately(seeded):
    assert _progress(seeded, "S1", HEADERS_C1).json()["checkins"][0]["location"] is None

    resp = _create_grant(seeded, "G-01", "C1", "institution", "INST-1", ["location"])
    assert resp.status_code == 201, resp.text
    # 授权立即生效。
    body = _progress(seeded, "S1", HEADERS_C1).json()
    assert body["checkins"][0]["location"] == "实训楼A-301"
    assert body["redacted_fields"] == ["mentor_comment", "reason"]

    # 撤销立即生效，且授权记录与变更历史保留（不改写既有审计）。
    revoked = seeded.post(
        "/api/access/grants/G-01/revoke", json={"reason": "到期回收"}, headers=HEADERS_ADMIN
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    body = _progress(seeded, "S1", HEADERS_C1).json()
    assert body["checkins"][0]["location"] is None

    grants = seeded.get("/api/access/grants", params={"actor_id": "C1"}).json()
    assert len(grants) == 1 and grants[0]["status"] == "revoked"
    events = seeded.get("/api/access/grants/G-01/events").json()
    assert [e["action"] for e in events] == ["create", "revoke"]
    assert events[1]["reason"] == "到期回收"


def test_expired_grant_no_longer_applies(seeded, db):
    expires = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    assert _create_grant(
        seeded, "G-EXP", "C1", "student", "S1", ["location"], expires_at=expires
    ).status_code == 201
    assert _progress(seeded, "S1", HEADERS_C1).json()["checkins"][0]["location"] == "实训楼A-301"

    # 时间推进到有效期之后（直接落库，避免测试等待）。
    row = db.get(AccessGrant, "G-EXP")
    row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    db.commit()
    assert _progress(seeded, "S1", HEADERS_C1).json()["checkins"][0]["location"] is None


def test_grant_validation_rejects_unknown_field_and_scope(seeded):
    resp = _create_grant(seeded, "G-BAD", "C1", "student", "S1", ["salary"])
    assert resp.status_code == 422
    resp = _create_grant(seeded, "G-BAD2", "C1", "galaxy", "INST-1", ["location"])
    assert resp.status_code == 422
    resp = _create_grant(seeded, "G-BAD3", "GHOST", "student", "S1", ["location"])
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 委托
# ---------------------------------------------------------------------------


def test_delegation_inherits_parent_scope_and_fields(seeded):
    # 父授权：导师 M1 对学生 S1 拥有地点字段。
    assert _create_grant(
        seeded, "G-P", "M1", "student", "S1", ["location"]
    ).status_code == 201
    # M1 把地点字段委托给未分配该学生的导师 M2。
    resp = _create_grant(
        seeded, "G-D", "M2", "student", "S1", ["location"], delegated_by="G-P"
    )
    assert resp.status_code == 201, resp.text

    decision = seeded.post(
        "/api/access/simulate",
        json={"actor_id": "M2", "plan_version": PV, "student_id": "S1"},
    ).json()
    assert decision["allowed"] is True
    assert decision["visible_fields"] == ["location"]
    assert decision["sources"] == ["G-D"]

    body = _progress(seeded, "S1", HEADERS_M2).json()
    assert body["checkins"][0]["location"] == "实训楼A-301"
    assert body["checkins"][0]["mentor_comment"] is None

    # 父授权被撤销后，委托授权立即失效。
    seeded.post("/api/access/grants/G-P/revoke", json={}, headers=HEADERS_ADMIN)
    assert _progress(seeded, "S1", HEADERS_M2).status_code == 403


def test_delegation_cannot_exceed_parent(seeded):
    assert _create_grant(
        seeded, "G-P", "M1", "student", "S1", ["location"]
    ).status_code == 201
    # 字段超出父授权子集。
    resp = _create_grant(
        seeded, "G-D1", "M2", "student", "S1", ["reason"], delegated_by="G-P"
    )
    assert resp.status_code == 422
    # 作用域超出父授权。
    resp = _create_grant(
        seeded, "G-D2", "M2", "student", "S2", ["location"], delegated_by="G-P"
    )
    assert resp.status_code == 422
    # 父授权不存在。
    resp = _create_grant(
        seeded, "G-D3", "M2", "student", "S1", ["location"], delegated_by="G-NOPE"
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 模拟判定
# ---------------------------------------------------------------------------


def test_simulate_reflects_policy_and_writes_no_audit(seeded):
    before = seeded.get("/api/access/audit-logs").json()
    decision = seeded.post(
        "/api/access/simulate",
        json={"actor_id": "C1", "plan_version": PV, "student_id": "S1"},
    )
    assert decision.status_code == 200, decision.text
    body = decision.json()
    assert body["allowed"] is True
    assert body["visible_fields"] == []
    assert body["redacted_fields"] == ["location", "mentor_comment", "reason"]

    denied = seeded.post(
        "/api/access/simulate",
        json={"actor_id": "C1", "plan_version": PV, "student_id": "S2"},
    ).json()
    assert denied["allowed"] is False

    after = seeded.get("/api/access/audit-logs").json()
    assert len(after) == len(before)


# ---------------------------------------------------------------------------
# 冻结摘要一致性
# ---------------------------------------------------------------------------


def test_frozen_snapshot_summary_consistent_under_redaction(seeded):
    frozen = seeded.post(f"/api/plans/{PV}/freezes/F-01", json={})
    assert frozen.status_code == 201, frozen.text
    raw = seeded.get(f"/api/plans/{PV}/freezes/F-01").json()
    raw_s1 = next(s for s in raw["students"] if s["student_id"] == "S1")
    assert raw_s1["checkins"][0]["location"] == "实训楼A-301"

    controlled = seeded.get(
        f"/api/access/plans/{PV}/freezes/F-01/snapshot", headers=HEADERS_C1
    )
    assert controlled.status_code == 200, controlled.text
    body = controlled.json()
    # 快照元数据与汇总数字与冻结内容一致。
    assert body["generated_at"] == raw["generated_at"]
    assert body["event_cutoff_id"] == raw["event_cutoff_id"]
    ctrl_s1 = next(s for s in body["students"] if s["student_id"] == "S1")
    for key in (
        "confirmed_seconds",
        "pending_seconds",
        "adjustment_seconds",
        "total_seconds",
        "lesson_units",
        "meets_requirement",
        "daily",
    ):
        assert ctrl_s1[key] == raw_s1[key]
    # 仅明细字段被裁剪。
    assert ctrl_s1["checkins"][0]["location"] is None
    assert ctrl_s1["adjustments"][0]["reason"] is None
    # 其他机构的学生不出现在裁剪结果中。
    assert {s["student_id"] for s in body["students"]} == {"S1"}

    # 既有冻结记录未被改写。
    raw_again = seeded.get(f"/api/plans/{PV}/freezes/F-01").json()
    assert raw_again == raw


# ---------------------------------------------------------------------------
# 批量导出
# ---------------------------------------------------------------------------


def test_export_applies_same_rules_as_controlled_reads(seeded):
    resp = seeded.post(
        f"/api/access/plans/{PV}/export", json={}, headers=HEADERS_C1
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["exported_count"] == 2
    by_id = {s["student_id"]: s for s in body["students"]}
    # 与受控单读结果一致。
    single = _progress(seeded, "S1", HEADERS_C1).json()
    assert by_id["S1"]["checkins"] == single["checkins"]
    assert by_id["S1"]["adjustments"] == single["adjustments"]
    assert by_id["S1"]["redacted_fields"] == single["redacted_fields"]
    # 越权学生在导出中被标记为不可见，不泄露明细。
    assert by_id["S2"]["visible"] is False
    assert "checkins" not in by_id["S2"]

    # 导出同样写入访问审计。
    logs = seeded.get(
        "/api/access/audit-logs", params={"actor_id": "C1"}
    ).json()
    export_logs = [log for log in logs if log["action"] == "export"]
    assert {log["student_id"] for log in export_logs} == {"S1", "S2"}
    decisions = {log["student_id"]: log["decision"] for log in export_logs}
    assert decisions == {"S1": "allow", "S2": "deny"}


def test_export_subset_and_frozen_source(seeded):
    seeded.post(f"/api/plans/{PV}/freezes/F-01", json={})
    resp = seeded.post(
        f"/api/access/plans/{PV}/export",
        json={"student_ids": ["S2"], "freeze_id": "F-01"},
        headers=HEADERS_A1,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["freeze_id"] == "F-01"
    assert [s["student_id"] for s in body["students"]] == ["S2"]
    assert body["students"][0]["adjustments"][0]["reason"] == "补录加班"
    assert body["students"][0]["checkins"][0]["location"] is None


# ---------------------------------------------------------------------------
# 访问审计
# ---------------------------------------------------------------------------


def test_audit_logs_are_append_only(seeded):
    _progress(seeded, "S1", HEADERS_C1)
    _progress(seeded, "S1", HEADERS_M1)
    logs = seeded.get("/api/access/audit-logs", params={"plan_version": PV}).json()
    assert len(logs) == 2
    assert [log["decision"] for log in logs] == ["allow", "allow"]
    assert logs[0]["actor_id"] == "C1"
    assert logs[0]["redacted_fields"] == ["location", "mentor_comment", "reason"]
    assert logs[1]["visible_fields"] == ["location", "mentor_comment"]
    assert all(log["occurred_at"] for log in logs)
    # 审计接口只读：不提供更新或删除。
    assert seeded.put("/api/access/audit-logs", json={}).status_code == 405
    assert seeded.delete("/api/access/audit-logs").status_code == 405


# ---------------------------------------------------------------------------
# 重启后的策略加载
# ---------------------------------------------------------------------------


def test_policy_loaded_from_storage_after_restart(tmp_path):
    """策略持久化在数据库中，全新引擎/会话（模拟重启）后判定一致。"""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    url = f"sqlite:///{tmp_path}/restart.db"

    def _session():
        engine = create_engine(url, future=True)
        Base.metadata.create_all(engine)
        return engine, sessionmaker(bind=engine, future=True)()

    engine1, session1 = _session()
    access_control.upsert_actor(
        session1, actor_id="C1", role="counselor", institution_id="INST-1"
    )
    access_control.upsert_enrollment(
        session1, student_id="S1", plan_version="P1", institution_id="INST-1"
    )
    access_control.create_grant(
        session1,
        grant_id="G-01",
        actor_id="C1",
        scope_type="student",
        scope_value="S1",
        fields=["location"],
        operator_id="G1",
        reason="初始授权",
    )
    session1.close()
    engine1.dispose()

    # “重启”后：授权仍然生效。
    engine2, session2 = _session()
    decision = access_control.decide_for(
        session2, actor_id="C1", plan_version="P1", student_id="S1"
    )
    assert decision.allowed is True
    assert decision.visible_fields == frozenset({"location"})
    # 撤销同样持久化。
    access_control.revoke_grant(
        session2, grant_id="G-01", operator_id="G1", reason="复核回收"
    )
    session2.close()
    engine2.dispose()

    engine3, session3 = _session()
    decision = access_control.decide_for(
        session3, actor_id="C1", plan_version="P1", student_id="S1"
    )
    # 基线仍允许本机构学生，但授权字段已随撤销失效。
    assert decision.allowed is True
    assert decision.visible_fields == frozenset()
    events = access_control.list_grant_events(session3, "G-01")
    assert [e["action"] for e in events] == ["create", "revoke"]
    session3.close()
    engine3.dispose()
