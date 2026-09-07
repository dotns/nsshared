# SH-MESH-001：定义 Mesh wire 类型与兼容向量

- **状态（status）**: in progress
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

第二块首次验证入口：`cargo test --locked -p control --test mesh_recovery_wire`。
用例：`mesh_query_matches_independent_integer_map_vector`、
`mesh_payload_rejects_ambiguous_and_unbounded_encodings`、
`mesh_receipt_binds_every_result_field_and_relay_key`、
`mesh_restore_proof_binds_upload_identity_and_dimensions`、
`mesh_recovery_messages_fit_real_envelopes_and_enforce_limits`。
覆盖独立字段字节、未知可选字段、重复/非定长/非最短 CBOR、签名绑定、
恢复维度与真实 envelope 长度；随后运行 `just fmt-check`、`just lint`。
嵌套 receipt 是数据结构，不新增可调用的 relay API；status 编码为
0=committed、1=result_unavailable、2=conflict，非成功必须不含 seq/receipt。
字段编号由 `mesh/recovery.rs` 逐项声明；Option 明确编码为 null。
payload 接受任意 map 字段顺序，要求定长容器和最短整数编码；原始签名材料
由 envelope/持久记录保存，不用解码后的重新编码值代替。
第二块结果：5 个行为测试全部通过，`just fmt-check` 和 `just lint` 退出 0；
证据 `locally checked`，Linux 普通用户，无产品持久状态或网络副作用。
完整原设计 mailbox API、管理记录及跨仓向量仍待后续块完成。

2026-09-07 实现首块：新增 `crates/control/src/mesh/{mod,framing,validity}.rs`
和 `crates/control/tests/mesh_transport.rs`。实际宿主为 Linux，以下仅形成本地逻辑证据，
不替代主计划要求的 macOS 原生验收。首次执行入口为
`cargo test --locked -p control --test mesh_transport`，用例：
`mesh_udp_size_and_magic_boundaries`（1200/1201 字节与 magic）、
`mesh_wss_has_separate_control_and_wg_limits`（控制/WG 分帧与独立上限）、
`mesh_live_time_boundaries_do_not_renew_history`（精确到期、skew、溢出与历史验证）、
`mesh_signatures_bind_domain_identity_and_original_payload`（请求/响应域、身份与原始字节绑定）。
另运行 `cargo test --locked -p control envelope::tests`、`just fmt-check`、`just lint`。
本块不创建 socket、临时持久状态或本机网络对象，清理不适用。
完整 API 字段、双签名与固定向量仍属于后续块，验收项保持未勾选。

首块实际结果：4 个 `mesh_transport` 测试和 24 个 `envelope::tests` 全部通过；
`just fmt-check`、`just lint` 退出 0。lint 首次因 Cargo 缓存写权限失败，
提升后因磁盘空间失败；仅清理本轮 `target/debug/incremental` 后重试原入口通过。
证据 `locally checked`；使用普通用户构建/测试，提升只用于缓存写入和格式化，
没有产品网络或特权操作。具体断言保存在上述测试文件；历史验收不因此整项关闭。

当前 macOS：`cargo test --locked -p control`；定向 Mesh 向量测试需要实际创建，记录过滤器。用最大32成员/admin、最大字符串/u64和嵌套 envelope 的真实编码计算大小；分开发送原文和回执仍须能重组且不提前提交。仓库已有 `just fmt-check`、`just lint`；本任务不运行 native/TUN。

门禁阶段：implementation；交付时执行关联计划当前平台适用 merge 检查。当前没有实现或测试新增，实际运行结果：未执行，证据 `assumed`。新增测试后、首次执行前记录精确命令/过滤器、用例列表及预期断言；零匹配、skip、单纯编译不能证明行为通过。记录实际权限、制品/环境、退出状态、主体断言、清理结果和证据路径。仅在当前平台执行，不将未运行的 Linux/Windows 记为通过。

## 状态日志（Status Log）

- 2026-09-07：按已批准方案创建；计划资产审查完成，实现状态仍 pending。
