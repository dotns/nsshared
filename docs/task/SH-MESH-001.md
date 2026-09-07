# SH-MESH-001：定义 Mesh wire 类型与兼容向量

- **状态（status）**: pending
- **优先级（priority）**: P1
- **负责人（owner）**: 当前实现者；范围与风险决定由仓库负责人负责
- **创建日期（createdAt）**: 2026-09-07
- **关联计划（relatedPlan）**: [PLAN-016](../plan/PLAN-016.md)
- **链接（links）**: [主计划](../../../ns/docs/plan/PLAN-218.md)、[唯一契约](../../../ns/docs/plan/PLAN-218-mesh-contract.md)

## 目标（Goal）

冻结并实现 Mesh 新 API、原始签名输入和跨仓黄金向量，使两套 control 在相同输入下互操作。

## 范围（Scope）

[control API](../../crates/control/src/api.rs)、[envelope](../../crates/control/src/envelope.rs)、control 新 Mesh 模块及其 fixtures；不改 managed envelope 既有签名输入。无 relay 状态或网络副作用。

本轮只建立/审查计划资产，未授权修改上述实现。未来实现的直接验证闭包限证明本任务验收所需的同仓 test、fixture、helper 和最小内部 seam；内部 seam 用测试构建隔离或既有稳定接口，并验证正常路径等价，不扩展公共 API、权限或部署策略。任务完成前在此记录实际新增路径及其证明的条件。

## 依赖与实施边界（Dependencies）

无实现前置依赖；契约 C1/C2 已给定边界，当前 ready-to-implement。公开类型/编码向量通过审查和大小验证后，NS 镜像与 NSGW 接线才依赖它。

本任务是独立验证与未来提交边界；不授权暂存、提交或推送，不修改其它任务的实现。

## 验收标准（Acceptance Criteria）

- [ ] 所有基线和扩展 API 均有完整字段编号、类型、可选项与签名向量。
- [ ] 最大合法请求与响应均能按规定 framing 传输，1201-byte Mesh datagram 被拒绝。
- [ ] 身份、网络/域、时间、请求绑定和回执字段篡改均被拒绝。
- [ ] 活凭据过期边界与历史记录校验规则分别通过定向测试。
- [ ] managed envelope 固定向量未改变。

## 实现说明（Implementation Notes）

字段表和原始十六进制 fixture 是新 wire 的执行契约，不只用 serde round-trip 作证明。独立期望字节与已签固定向量能发现双端一致但同样错误的编码；NS 复制相同向量，不复制临时输出。共享 fixtures 不包含真实 secrets。

## 验证（Verification）

当前 macOS：`cargo test --locked -p control`；定向 Mesh 向量测试需要实际创建，记录过滤器。用最大32成员/admin、最大字符串/u64和嵌套 envelope 的真实编码计算大小；分开发送原文和回执仍须能重组且不提前提交。仓库已有 `just fmt-check`、`just lint`；本任务不运行 native/TUN。

门禁阶段：implementation；交付时执行关联计划当前平台适用 merge 检查。当前没有实现或测试新增，实际运行结果：未执行，证据 `assumed`。新增测试后、首次执行前记录精确命令/过滤器、用例列表及预期断言；零匹配、skip、单纯编译不能证明行为通过。记录实际权限、制品/环境、退出状态、主体断言、清理结果和证据路径。仅在当前平台执行，不将未运行的 Linux/Windows 记为通过。

## 状态日志（Status Log）

- 2026-09-07：按已批准方案创建；计划资产审查完成，实现状态仍 pending。
