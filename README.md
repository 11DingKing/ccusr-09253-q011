# 实训学时合规与冻结服务

该服务汇聚学员签到、导师确认和请假修正事件，按培养方案与时区重放学时状态，并保存可追溯的学期冻结快照。项目还提供导师分配、证明材料、豁免复核、规则版本、名额、通知和数据留存等领域模块，供后续业务扩展时复用统一的状态与审计约束。

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

测试覆盖事件幂等导入、跨时区与跨日学时合并、实习确认、负向修正、冻结快照和差异查询；运行过程中不需要单独的数据库或网络服务。

## 机构、角色与学生关系驱动的字段级访问

签到事件载荷支持 `location`（地点），导师确认支持 `comment`（导师意见），请假修正携带 `reason`（原因）。这三类敏感字段按访问策略裁剪：

| 角色 | 关系约束 | 默认可见字段 |
| --- | --- | --- |
| 辅导员 counselor | 同机构学生 | `location`、`reason` |
| 导师 mentor | 培养方案内指导关系 | `location`、`mentor_comment` |
| 审计人员 auditor | 同机构学生 | `reason`、`mentor_comment` |

- 授权维护：`PUT /api/access/subjects`（主体/机构/角色）、`PUT /api/access/enrollments`（学籍）、`POST /api/plans/{plan}/mentor-relations`（指导关系）、`POST /api/plans/{plan}/grants`（字段授权与委托，可设 `expires_at`）、`POST /api/access/grants/{id}/revoke`（撤销）。
- 模拟判定：`POST /api/access/simulate` 返回 allow/deny、可见与裁剪字段及命中原因，不写访问审计。
- 受控查询：`GET .../students/{sid}/records?subject_id=`、`.../controlled/snapshot`、`.../freezes/{fid}/controlled`；裁剪只作用于深拷贝，冻结摘要秒数与合规结论对所有读者一致，库内冻结快照不被改写。
- 批量导出：`POST /api/plans/{plan}/export` 应用与逐条查询相同的关系判定、字段裁剪和逐生审计，越权学生整生排除。
- 访问审计：`GET /api/access/audits` 只增记录每次受控访问（含 deny）；授权撤销立即影响后续读取，但不会改写既有审计记录。
- 授权变更即时失效策略缓存；`POST /api/access/reload` 丢弃进程内缓存并从数据库重载，进程重启后策略同样从持久化数据自动加载。
