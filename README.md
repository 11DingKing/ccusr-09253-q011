# 实训学时合规与冻结服务

该服务汇聚学员签到、导师确认和请假修正事件，按培养方案与时区重放学时状态，并保存可追溯的学期冻结快照。项目还提供导师分配、证明材料、豁免复核、规则版本、名额、通知和数据留存等领域模块，供后续业务扩展时复用统一的状态与审计约束。

## 隐私字段分级访问

辅导员、导师和审计人员查看学时记录时遵循机构、角色和学生关系驱动的访问策略，对签到地点（`location`）、请假原因（`reason`）和导师意见（`mentor_comment`）做字段级裁剪：

- **基线角色矩阵**：辅导员可见本机构学生（无敏感字段）；导师可见名下学生的地点与导师意见；审计人员可见全部学生的原因与导师意见。
- **授权（grant）**：按机构/方案/学生三级作用域追加敏感字段，支持委托（字段必须是父授权的子集且作用域不超出父授权）；撤销与过期立即影响后续读取，授权变更只追加审计事件，不改写历史。
- **受控查询与导出**：`/api/access/...` 下的查询、冻结快照读取和批量导出应用同一套判定与裁剪规则；裁剪只作用于明细字段，汇总数字与冻结快照的存储内容保持一致。
- **访问审计**：每次受控读取（含拒绝）都追加访问日志，接口只读，不提供更新或删除。

主要接口：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| PUT/GET | `/api/access/actors/{id}` | 维护/查询访问主体（角色 + 机构） |
| PUT/GET | `/api/access/enrollments/{plan}/{student}` | 维护/查询学生归属 |
| PUT/GET | `/api/access/mentor-assignments[...]` | 维护/查询导师-学生关系 |
| POST/GET | `/api/access/grants` | 创建/查询授权（需 `X-Actor-Id` 操作人） |
| POST | `/api/access/grants/{id}/revoke` | 撤销授权（保留记录与变更历史） |
| GET | `/api/access/grants/{id}/events` | 授权变更审计 |
| POST | `/api/access/simulate` | 模拟判定（不写访问审计） |
| GET | `/api/access/plans/{plan}/students/{id}/progress` | 受控单学生查询 |
| GET | `/api/access/plans/{plan}/snapshot`、`/api/access/plans/{plan}/freezes/{id}/snapshot` | 受控快照查询 |
| POST | `/api/access/plans/{plan}/export` | 批量导出（同一套裁剪规则） |
| GET | `/api/access/audit-logs` | 访问审计查询（只读） |

受控接口通过 `X-Actor-Id` 请求头识别访问主体；未携带返回 401，未注册返回 404，越权返回 403。既有 `/api/plans/...` 接口保持原语义，不做裁剪。

## 运行方式

默认数据保存在项目目录的 SQLite 文件中。安装依赖后执行 `uvicorn app.main:app --host 127.0.0.1 --port 8000`，健康检查地址为 `/health`，业务接口位于 `/api`。

## 测试

```bash
python3 -m pytest -q
```

## 编译检查

```bash
python3 -m compileall -q app tests
```

测试覆盖事件幂等导入、跨时区与跨日学时合并、实习确认、负向修正、冻结快照和差异查询，以及字段级访问控制的越权拒绝、委托、授权撤销/过期、冻结摘要一致性、批量导出与重启后的策略加载；运行过程中不需要单独的数据库或网络服务。
