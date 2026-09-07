# SH-MESH-002：实现确定性成员归约与恢复摘要

- **状态（status）**: pending
- **优先级（priority）**: P1
- **负责人（owner）**: 当前实现者；范围与风险决定由仓库负责人负责
- **创建日期（createdAt）**: 2026-09-07
- **关联计划（relatedPlan）**: [PLAN-016](../plan/PLAN-016.md)
- **链接（links）**: [主计划](../../../ns/docs/plan/PLAN-218.md)、[唯一契约](../../../ns/docs/plan/PLAN-218-mesh-contract.md)

## 目标（Goal）

提供无 IO 的历史验证、权限归约、canonical compact state 编码和摘要计算，供 relay 与 NS 镜像复用契约。

## 范围（Scope）

[control](../../crates/control/src/lib.rs) 内新 Mesh 纯逻辑模块及 fixtures；仅必要时补 [common](../../crates/common/src/lib.rs) 的纯类型，不把 NS 本地 policy 或 NSGW 存储引入公共库。

本轮只建立/审查计划资产，未授权修改上述实现。未来实现的直接验证闭包限证明本任务验收所需的同仓 test、fixture、helper 和最小内部 seam；内部 seam 用测试构建隔离或既有稳定接口，并验证正常路径等价，不扩展公共 API、权限或部署策略。任务完成前在此记录实际新增路径及其证明的条件。

## 依赖与实施边界（Dependencies）

依赖 [SH-MESH-001](SH-MESH-001.md) 的稳定 wire 类型/向量。

本任务是独立验证与未来提交边界；不授权暂存、提交或推送，不修改其它任务的实现。

## 验收标准（Acceptance Criteria）

- [ ] add/evict/admins 按 seq 连续归约且历史权限判定一致。
- [ ] 成员资格撤销水位不因旧 incarnation、新 timestamp 或 vouch 降低。
- [ ] canonical state 对同一语义状态生成相同字节与摘要。
- [ ] 管理员 revision 竞态和同时间 addr/capability 冲突确定性收敛。
- [ ] 不规范编码、摘要不匹配、未知版本与数值溢出被拒绝。

## 实现说明（Implementation Notes）

所有产品/协议语义引用唯一契约；不在任务中重定义默认值或另建状态机。实现顺序先纯逻辑和离线验证，再完成依赖已满足的真实接线。

## 验证（Verification）

当前 macOS：`cargo test --locked -p control`；增加独立的事件排列/重复/缺口、权限转换、digest 输入边界向量，记录实际定向用例。`just fmt-check`、`just lint`，交付关联计划当前平台 QA。

门禁阶段：implementation；交付时执行关联计划当前平台适用 merge 检查。当前没有实现或测试新增，实际运行结果：未执行，证据 `assumed`。新增测试后、首次执行前记录精确命令/过滤器、用例列表及预期断言；零匹配、skip、单纯编译不能证明行为通过。记录实际权限、制品/环境、退出状态、主体断言、清理结果和证据路径。仅在当前平台执行，不将未运行的 Linux/Windows 记为通过。

## 状态日志（Status Log）

- 2026-09-07：按已批准方案创建；计划资产审查完成，实现状态仍 pending。
