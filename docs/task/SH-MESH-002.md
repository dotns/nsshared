# SH-MESH-002：实现确定性成员归约与恢复摘要

- **状态（status）**: in progress
- **优先级（priority）**: P1
- **负责人（owner）**: B：Relay 服务与共享协议负责人；范围与风险决定由仓库负责人负责
- **创建日期（createdAt）**: 2026-09-07
- **关联计划（relatedPlan）**: [PLAN-016](../plan/PLAN-016.md)
- **链接（links）**: [主计划](../../../ns/docs/plan/PLAN-218.md)、[唯一契约](../../../ns/docs/plan/PLAN-218-mesh-contract.md)

## 目标（Goal）

提供无 IO 的历史验证、权限归约、canonical compact state 编码和摘要计算，供 relay 与 NS 镜像复用契约。

## 范围（Scope）

[control](../../crates/control/src/lib.rs) 内新 Mesh 纯逻辑模块及 fixtures；仅必要时补 [common](../../crates/common/src/lib.rs) 的纯类型，不把 NS 本地 policy 或 NSGW 存储引入公共库。

初始规划仅建立/审查计划资产；2026-09-10 双设备修订同样仅修改计划资产。后续执行以主计划最新范围和用户当时授权为准。直接验证闭包限证明本任务验收所需的同仓 test、fixture、helper 和最小内部 seam；内部 seam 用测试构建隔离或既有稳定接口，并验证正常路径等价，不扩展公共 API、权限或部署策略。任务完成前在此记录实际新增路径及其证明的条件。

## 依赖与实施边界（Dependencies）

依赖 [SH-MESH-001](SH-MESH-001.md) 的稳定 wire 类型/向量。

本任务保留独立验证与提交/回滚边界；本次计划修订不授权实现或 Git 写操作，后续执行遵循主计划及用户当时授权。

2026-09-10 双设备归属：B 独占 shared 纯归约/摘要和向量，A 镜像并验证 NS 结果。既有 add/admins/evict 证据保持原范围；vouch 水位转换需先冻结语义，不以纯函数测试冒称恢复运行路径通过。
共享写入、旧执行任务接管、稳定版本和资源隔离统一见
[主计划分工](../../../ns/docs/plan/PLAN-218.md#双设备分工与交接)，块内及跨仓验证安排见
[联合验证](../../../ns/docs/plan/PLAN-218.md#双设备联合验证安排)。不以任务整体状态替代所需接口的
交付证据，不因分工改变下列验收项或原始验证结果。

## 验收标准（Acceptance Criteria）

- [x] add/evict/admins 按 seq 连续归约且历史权限判定一致。
- [ ] 成员资格撤销水位不因旧 incarnation、新 timestamp 或 vouch 降低。
- [x] canonical state 对同一语义状态生成相同字节与摘要。
- [x] 管理员 revision 竞态和同时间 addr/capability 冲突确定性收敛。
- [x] 不规范编码、摘要不匹配、未知版本与数值溢出被拒绝。

## 实现说明（Implementation Notes）

所有产品/协议语义引用唯一契约；不在任务中重定义默认值或另建状态机。实现顺序先纯逻辑和离线验证，再完成依赖已满足的真实接线。

## 验证（Verification）

2026-09-09 evict 归约块已验证：负责人已选择实际移除成员时同时移除其管理员资格，
管理员集为空恢复平等成员；因移除而实际改变管理员集时 revision 加 1，否则不增加。
显式 admins 原文的既有 revision 规则不变。范围仅 `mesh/membership.rs` 与
`tests/mesh_membership.rs`，不接网关持久事务或客户端网络流程。
先运行 `CARGO_INCREMENTAL=0 cargo test --locked --offline -p control --test mesh_membership -- --list`，
随后同入口行为测试、`cargo test --locked --offline -p control mesh_` 与既有 fmt/lint。
新增精确用例：
`mesh_membership_evictions_preserve_new_incarnations_and_never_clear_watermarks`、
`mesh_membership_evictions_revision_only_changed_admin_sets_and_restore_equal_rights`、
`mesh_membership_evictions_use_preceding_authority_and_sequence_mutual_removals`、
`mesh_membership_evictions_bound_context_capacity_and_exhausted_incarnations`。
实际 `--list` 匹配 10 项（原 6 加新 4），定向行为 10 passed、0 failed/ignored，
2.79 秒；完整 `cargo test --locked --offline -p control mesh_` 49 passed、
0 failed/ignored，包含 29 组既有独立向量。`just fmt-check` 与
`CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true just lint` 均退出 0，源码首次门禁通过。
证据 `verified` 限纯签名归约，覆盖水位保留、重新加入后的旧代次保护、管理员转换、
互相撤销顺序、无权记录消费 seq、缺口/溢出及身份容量。关闭完整 add/evict/admins
历史归约及输入拒绝两项；vouch 恢复路径不降低水位的验收仍需直接接线证据，
不由本块推断通过。NS 镜像正在同步，尚未取得其独立门禁和连续重放结果。

add/admins 独立归约块首次入口：
`CARGO_INCREMENTAL=0 cargo test --locked --offline -p control --test mesh_membership`。
在前一 canonical 状态上判断历史权限，严格连续 seq、管理员 revision、完整 signing/WG
绑定与地址复算；旧 incarnation 不覆盖新成员，也不删除撤销水位。有效回执下的无权或
过时记录只消费 seq，字段/容量/上下文错误拒绝；不处理待决定的 evict 管理员转换。
当前 Linux 定向测试 6 passed，0 failed/ignored，用例为
`mesh_membership_adds_preserve_watermarks_and_only_advance_incarnations`、
`mesh_membership_admin_revision_races_and_last_admin_removal_are_deterministic`、
`mesh_membership_admins_resolve_retained_full_keys_without_restoring_membership`、
`mesh_membership_never_grants_nonmembers_or_nonadmins_historical_management_rights`、
`mesh_membership_rejects_wrong_context_gaps_overflow_and_field_bindings`、
`mesh_membership_enforces_member_and_retained_identity_capacity_without_partial_results`。
`CARGO_INCREMENTAL=0 cargo test --locked --offline -p control mesh_`：45 passed，
0 failed/ignored；`just fmt-check` 和 `CARGO_INCREMENTAL=0 just lint` 均退出 0。
证据 `verified`，纯内存；管理员完整 key 只从前态解析，不从指纹构造身份。
覆盖批准、非管理员、已离开成员、revision 竞态、显式 admins 记录清空最后管理员、
重放/缺口/溢出、地址与 WG 冲突和成员/身份容量。保留已有非成员管理员不恢复其成员
资格；该输入测试不决定 evict 是否移除管理员，完整权限与撤销验收仍未闭合。

genesis 独立块首次入口：
`CARGO_INCREMENTAL=0 cargo test --locked --offline -p control --test mesh_genesis`。
复算原始 register 的 seq=0 初始成员集合，检查双签名及创建回执绑定；预期覆盖
独立固定摘要、旧时间历史验证、重签后的错误网络/nonce/作者/WG/incarnation、
错误 receipt 摘要/seq/relay、尾随/截断/过长/过深输入。不据此开放状态覆盖或 runtime。
当前 Linux：定向入口 4 passed，0 failed/ignored，用例为
`mesh_genesis_recomputes_independent_initial_state_and_historical_receipt`、
`mesh_genesis_rejects_resigned_receipt_aliases_and_wrong_relay`、
`mesh_genesis_requires_member_signature_and_bound_network_proof`、
`mesh_genesis_rejects_truncated_trailing_and_excessive_input`。
复用独立 register-create 原文，显式拼接 134 字节初始状态，并使用 Perl Digest::SHA
独立计算固定摘要；未把仅有 wire 合法性的 synthetic receipt 当成创建证明。
`CARGO_INCREMENTAL=0 cargo test --locked --offline -p control mesh_`：39 passed，
0 failed/ignored；`just fmt-check` 和 `CARGO_INCREMENTAL=0 just lint` 均退出 0。
证据 `verified`，纯内存，无网络/持久状态副作用；创建材料不授予覆盖已知高 seq 的权限。

owner 记录独立块首次入口：
`CARGO_INCREMENTAL=0 cargo test --locked --offline -p control --test mesh_owner_records`。
新增 peer-only `mesh.addr`/`mesh.capability` payload、历史签名/当前成员绑定验证与
同时间原文摘要归并；唯一字段契约见主计划 C6。预期覆盖重复与重排、非 owner 签名、
网络/种类/incarnation/WG 作用域、未知 flags/salt 溢出、尾随/过深/过长输入、地址复算。
当前 Linux 定向入口 4 passed，0 failed/ignored；用例为
`mesh_owner_records_verify_independent_vectors_and_recompute_addresses`、
`mesh_owner_records_converge_across_duplicate_and_reordered_versions`、
`mesh_owner_records_reject_forgery_revocation_and_cross_scope_replacement`、
`mesh_owner_records_bound_schema_lengths_and_nested_input`。
独立 oracle 与固定向量增加至 29 组；
`CARGO_INCREMENTAL=0 cargo test --locked --offline -p control mesh_`：35 passed，
0 failed/ignored；`just fmt-check` 和 `CARGO_INCREMENTAL=0 just lint` 均退出 0。
证据 `verified`，纯内存，无网络或持久状态副作用。不关闭管理员 revision 或完整
归约验收，不将成员间原文注册为 relay mailbox 接口，不将历史签名视为业务就绪。

历史原文/回执绑定块首次入口：
`CARGO_INCREMENTAL=0 cargo test --locked -p control --test mesh_history`。
新增 `mesh/history.rs` 和定向测试，预期覆盖 add 双签名、evict/admins 原文签名、
原字节摘要、作者/操作/网络绑定、连续 seq 与溢出、种类混淆、历史寿命和伪造回执。
验证类型只表明原文真实性，不授予成员或管理权限；归约仍须读取前一状态。
当前 Linux 定向测试 4 passed，具体用例：
`mesh_history_preserves_original_add_and_authenticates_expired_records`、
`mesh_history_rejects_receipt_aliases_gaps_overflow_and_wrong_relay`、
`mesh_history_rejects_forged_originals_and_kind_confusion`、
`mesh_history_bounds_originals_and_rejects_trailing_envelope_data`。
首轮 lint 拒绝大枚举变体，改为 Box 承载 add 后重跑定向入口仍 4 passed；
`CARGO_INCREMENTAL=0 cargo test --locked -p control mesh_`：31 passed，0 failed/ignored；
`just fmt-check` 与 `CARGO_INCREMENTAL=0 just lint` 均退出 0。
验证包含原字节借用不变、伪造原文/回执、已重签的错误关联字段、尾随和过深嵌套拒绝。
证据 `verified`，纯内存，无网络和持久状态副作用；未据此关闭权限归约验收。

canonical state 独立块首次入口：`cargo test --locked -p control --test mesh_compact_state`。
用例 `mesh_compact_state_matches_independent_binary_and_digest`、
`mesh_compact_state_rejects_order_duplicates_versions_and_truncation`、
`mesh_compact_state_checks_capacities_and_incarnation_watermarks`。
新增 `mesh/compact.rs` 与定向测试，覆盖 C5 固定顺序、长度、排序、摘要和容量；
使用结构化字段与标准字节读取，不保存原文/理由/地址/policy。随后运行 Mesh 回归、
fmt/lint。当前 Linux 已执行上述定向入口，3 passed；随后
`CARGO_INCREMENTAL=0 cargo test --locked -p control mesh_`：27 passed，
0 failed/ignored。`just fmt-check`、`just lint` 均退出 0。独立固定字段字节与
hashlib 摘要向量一致，全部截断前缀、重复/乱序 key、版本、容量和 anchor 不匹配
均被拒绝。证据 `verified`，纯内存，无网络或持久状态副作用。

2026-09-09 上述管理员撤销及 revision 规则已由负责人选择，解除该决策阻断；
实现/验证见本节 evict 结果，仍不表示 vouch 或跨仓任务闭合。

当前 macOS：`cargo test --locked -p control`；增加独立的事件排列/重复/缺口、权限转换、digest 输入边界向量，记录实际定向用例。`just fmt-check`、`just lint`，交付关联计划当前平台 QA。

门禁阶段：implementation；交付时执行关联计划当前平台适用 merge 检查。
canonical 编码/摘要、owner 收敛及 add/evict/admins 连续归约已有上述证据；vouch 恢复
接线对水位的保护、跨仓及计划交付门尚未闭合。上述 Linux 纯逻辑结果不替代 macOS/Windows
或真实端到端验收。

## 状态日志（Status Log）

- 2026-09-09：evict 归约及管理员连带移除已验证，49 项 Mesh 回归与 fmt/lint 通过；vouch/跨仓保持未闭合。
- 2026-09-07：按已批准方案创建；计划资产审查完成，实现状态仍 pending。
- 2026-09-07：canonical state 编码、摘要与有界解码已验证；任务继续 in progress。
- 2026-09-08：owner 地址/能力记录的签名、成员绑定和确定性合并已验证；管理员归约继续待完成。
- 2026-09-08：genesis 双签名、初始状态摘要与创建回执绑定已验证；完整权限归约仍未闭合。
- 2026-09-08：add/admins 连续归约、历史权限和 revision 竞态已验证；evict 待负责人决定。
