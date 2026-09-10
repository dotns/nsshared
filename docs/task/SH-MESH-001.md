# SH-MESH-001：定义 Mesh wire 类型与兼容向量

- **状态（status）**: in progress
- **优先级（priority）**: P1
- **负责人（owner）**: B：Relay 服务与共享协议负责人；范围与风险决定由仓库负责人负责
- **创建日期（createdAt）**: 2026-09-07
- **关联计划（relatedPlan）**: [PLAN-016](../plan/PLAN-016.md)
- **链接（links）**: [主计划](../../../ns/docs/plan/PLAN-218.md)、[唯一契约](../../../ns/docs/plan/PLAN-218-mesh-contract.md)

## 目标（Goal）

冻结并实现 Mesh 新 API、原始签名输入和跨仓黄金向量，使两套 control 在相同输入下互操作。

## 范围（Scope）

[control API](../../crates/control/src/api.rs)、[envelope](../../crates/control/src/envelope.rs)、control 新 Mesh 模块及其 fixtures；不改 managed envelope 既有签名输入。无 relay 状态或网络副作用。

初始规划仅建立/审查计划资产；2026-09-10 双设备修订同样仅修改计划资产。后续执行以主计划最新范围和用户当时授权为准。直接验证闭包限证明本任务验收所需的同仓 test、fixture、helper 和最小内部 seam；内部 seam 用测试构建隔离或既有稳定接口，并验证正常路径等价，不扩展公共 API、权限或部署策略。任务完成前在此记录实际新增路径及其证明的条件。

## 依赖与实施边界（Dependencies）

已冻结的 C1/C2 类型与向量无额外实现前置，按实际证据复用；WSS 外层及赢家查询等新增语义仍需主计划所列决定与契约交接。公开类型/编码向量通过直接验证后，NS 镜像与 NSGW 才消费相应增量；不把本任务整体标为 ready-to-implement。

本任务保留独立验证与提交/回滚边界；本次计划修订不授权实现或 Git 写操作，后续执行遵循主计划及用户当时授权。

2026-09-10 双设备归属：B 独占 shared wire/API/固定向量，向 A 交付供 NS-MESH-001 镜像的稳定输入；同一 B 负责 NSGW 消费。新增外层或赢家查询先由 A 落实负责人选择的唯一契约，再实现和验证。
共享写入、旧执行任务接管、稳定版本和资源隔离统一见
[主计划分工](../../../ns/docs/plan/PLAN-218.md#双设备分工与交接)，块内及跨仓验证安排见
[联合验证](../../../ns/docs/plan/PLAN-218.md#双设备联合验证安排)。不以任务整体状态替代所需接口的
交付证据，不因分工改变下列验收项或原始验证结果。

## 验收标准（Acceptance Criteria）

- [ ] 所有基线和扩展 API 均有完整字段编号、类型、可选项与签名向量。
- [ ] 最大合法请求与响应均能按规定 framing 传输，1201-byte Mesh datagram 被拒绝。
- [x] 身份、网络/域、时间、请求绑定和回执字段篡改均被拒绝。
- [x] 活凭据过期边界与历史记录校验规则分别通过定向测试。
- [x] managed envelope 固定向量未改变。
- [x] 契约 C1/C7 的身份指纹、IPv4/IPv6 domain 和盐边界有固定向量。

## 实现说明（Implementation Notes）

字段表和原始十六进制 fixture 是新 wire 的执行契约，不只用 serde round-trip 作证明。独立期望字节与已签固定向量能发现双端一致但同样错误的编码；NS 复制相同向量，不复制临时输出。共享 fixtures 不包含真实 secrets。

## 验证（Verification）

2026-09-10 PIN 优先接缝已实现并验证：新增
`KeyEnvelope::sign_grant(&KeyGrant, signer) -> Result<KeyEnvelope, mesh::Error>`。
签名器沿用 `FnOnce(&[u8]) -> [u8; 64]`；先由带擦除 Drop 的 envelope 持有秘密，
再读取时钟、取得 fresh nonce 和调用签名器，错误或 unwind 不经过裸 Vec 所有权。
Grant/完整帧序列化输出从创建起由 SecretBox 持有。复用既有 response 签名输入，
C6.3 字段、签名域、固定向量、权限及 Managed 行为均未改变。
生产改动为 `envelope.rs` 的 crate 内签发 helper、`mesh/key_exchange.rs` 及
`mesh/key_exchange/framing.rs`；NS 镜像由 A 消费稳定提交，不在本机写 NS。

首次 `CARGO_INCREMENTAL=0 cargo test --locked --offline -p control mesh_key_ -- --list`
编译 1m58s，准确枚举 9 项；随后完整 `cargo test --locked --offline -p control`
在同一 `CARGO_INCREMENTAL=0` 下编译 1m49s，445 单元、55 Mesh 集成、23 既有契约
均通过，0 failed/ignored。三项新增测试覆盖 fresh nonce/实时验签、原独立完整帧
及 signing-input 向量、注入时钟错误/签名器真实 unwind 后重试。
`CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true just fmt-check lint` 通过，Clippy 38.16s。
没有执行 workspace 全量 QA，没有修改依赖/锁文件或固定 fixture。

原始输出在 Git 外：`/tmp/mesh-b-key-signing-control.log`（SHA256
`d2c83814a99df03829b82acaf4cef395b011a515a8ab0f8b3ebefd721814a2c7`），
`/tmp/mesh-b-key-signing-static.log`（SHA256
`f8577ed04766c4d277a2c036da2c49077bbb13364bd6c1f80599e63f82270be2`）。
本机 Linux 普通用户，纯 codec/签名，无产品持久或网络资源；cleanup 不适用。
证据 verified 限上述行为；秘密擦除由 guard 所有权和 Drop 源码审查支持，测试
不读取释放后的内存、不宣称通用 CBOR 解码器内部临时分配完全擦除。
实际 WG/Vault、跨仓镜像及完整 PIN e2e 仍由后续任务关闭。

2026-09-09 负责人选择首次入网与 WG 私钥交付补充，唯一字段/边界见主契约 C6.3。
新增并注册 `mesh/key_exchange.rs`、`key_exchange/framing.rs` 和六项直接测试，
复用原五种 C6、已有 envelope 签名域及严格 CBOR；两种 key API 仅用于 WG。
`fixtures/mesh-key-v1` 独立 oracle 的两份完整帧向量分别为 473/528 字节，生成后
结构化比对一致，SHA256 `ec7134d6efd8d5810ef951c67840bbace463e25f0dcdd64de67877fad0c07bd6`。
`CARGO_INCREMENTAL=0 cargo test --locked --offline -p control mesh_key_ -- --list`
首次编译 2m14s，准确枚举六项新测试。随后完整 control 测试 442 项单元、55 项
Mesh 集成、23 项既有契约全部通过，0 failed/ignored；六项新测试均实际通过。
单元制品 SHA256 `543492822783e32fc59e4cbcd477e838aae9c608bdebdb464af77310926a126f`。
`cargo fmt --all -- --check` 与离线 `just lint`（workspace/all-targets Clippy，37.14s）
通过，独立审查未发现确定协议缺陷。证据 verified 限纯 codec/固定向量，不宣称
通用 CBOR 解析内部临时副本完全擦除。既有 secrecy 依赖复用，无版本或锁文件变更。
NS 镜像、实际
权限/WG epoch/nonce 消费、Vault 安装、完整 PIN bootstrap 和 live-e2e 均待后续验证。

2026-09-09 新选 C6 同步协议块（共享实现已验证，跨仓门禁待完成）：在既有 WG 账本帧边界内新增版本化
Digest/Pull/Records/Done/DoneAck，历史原文与规范回执摘要链、owner 胜者快照共同
构成版本。生产范围为 `mesh/sync.rs`、`sync/digest.rs` 与原 codec 私有显式 limit
复用入口；既有 1200-byte 控制 API 不放宽。完整帧包含 u32 BE 长度头最多 65536
字节，页最多 24 项、owner 总数最多 64；解析不是鉴权，摘要不是已持久或 Ready。
新增 `tests/mesh_sync.rs` 七项 `mesh_sync_` 测试与 `fixtures/mesh-sync-v1` 十个
独立固定向量。`CARGO_INCREMENTAL=0 cargo test --locked --offline -p control
--test mesh_sync -- --list` 编译 33.36s，通过并匹配七项；随后 `cargo test --locked
--offline -p control mesh_` 编译 1m32s，56 项通过，含七项新测试（4.82s）。
再运行完整 `CARGO_INCREMENTAL=0 cargo test --locked --offline -p control`：436 项
单元、55 项 Mesh 集成和 23 项既有契约集成全部通过，0 failed/ignored；新七项
再次通过（4.39s）。`CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true just fmt-check lint`
通过，Clippy 39.55s。固定向量与独立 oracle 在实际产品测试中逐项核对，不以生成
成功替代产品测试。唯一契约 C6.1/C6.2 已补详细字段与摘要；NS 七文件已机械镜像，
除既有测试 cfg 头外逐字节一致，但对应 Cargo 门禁尚未执行，跨仓验收保持开放。
真实流分片/拼接、双向确认、写盘后完成与两 TCP 槽调度由 NS runtime 块验证，
本块仅完整单帧编解码、认证记录摘要与固定字节，不宣称 Linux live-e2e 通过。

第五块首次入口：`cargo test --locked -p control --test mesh_identity`，
用例 `mesh_fingerprints_and_addresses_match_independent_blake2s_vectors`、
`mesh_fingerprint_and_address_bindings_reject_ambiguous_values`、
`mesh_address_allocation_bounds_attempts_and_collision_order`。
新增 `mesh/identity.rs` 和定向测试，独立 Python hashlib 的 20/15/4-byte BLAKE2s
结果冻结为测试常量，区别于截断 256-bit digest；盐签名编码仍按 payload u64，
地址派生按 C7 使用 u32 BE，超过 u32 的 wire 盐拒绝。
复用锁文件已有 `blake2 0.10.6` 并显式声明 control 直接依赖；MIT/Apache-2.0、
纯 Rust、无新增 TLS/provider/native 构建，关闭不必要默认 feature。通过 Cargo
离线解析仅更新直接依赖边，再执行 Mesh 回归、fmt/lint、deny/shear。
首次执行前证据 `assumed`；本块无持久状态/socket/权限副作用。
为满足 C5 的完整公钥 canonical state，accept 追加第 15 字段 `joiner_pub`，
纳入网络签名，并校验其 C1 指纹与 joiner_id 一致；JoinBinding 同时核对完整公钥。
27 组独立向量仅 accept 原文/签名随该字段更新，Managed 向量保持不变。
独立 oracle 现纳入正常测试编译和 lint，新增
`mesh_independent_oracle_matches_checked_in_vectors`；不在测试中重写 fixture。
11 个当前受影响定向测试通过，Clippy 的可合并 if 已按建议修复后原门禁通过。
`just deny` 退出 0（既有 yanked/duplicate/wildcard 警告保留，不升级无关依赖）；
`just shear` 在接线 oracle 后无问题。最终完整 control 回归及 fmt/shear 再次执行中。
第五块最终结果：完整 control 回归退出 0，436 个单元测试、23 个 Mesh 集成测试、
23 个既有契约集成测试通过，零失败/忽略；fmt/lint/deny/shear 全部退出 0。
证据 `locally checked`，本任务纯协议范围闭合。实际跨仓复制/互操作、relay runtime、
macOS 原生网络与共享仓最终质量门仍由对应任务/计划保留，不由本任务 done 替代。

第四块首次入口：`cargo test --locked -p control --test mesh_handshake` 和
`cargo test --locked -p control mesh_cookie_matches_independent_hmac_input`。
用例覆盖 cookie 来源/key/request/初始 expiry、当前/上一时间桶、重启密钥轮换，
WSS challenge 的连接/origin/双公钥/签名绑定与精确 30 秒失效；消费型接口防止再次验签。
新增 `mesh/handshake.rs` 与 `tests/mesh_handshake.rs`，随后执行既有 Mesh 回归和 fmt/lint。
首次执行前结果为 `assumed`；仅纯逻辑，真实 WSS 连接与 pending 分配顺序由 relay 任务验证。
固定向量入口：`cargo test --locked -p control --test mesh_golden_vectors`，
用例 `mesh_fixed_vectors_cover_every_api_and_preserve_original_envelopes`、
`mesh_fixed_payloads_decode_with_semantic_and_internal_signature_checks`。
`tests/fixtures/mesh-v1/oracle.rs` 独立使用 CBOR/签名库，不调用生产 control 编码器，
产出 `vectors.json` 的固定原文、签名输入和 payload 字节；测试覆盖 API 集合、
字段语义、内外签名、身份/domain 篡改、真实 framing 大小及 Managed envelope 不变。
第四块定向结果：27 组固定向量的 2 个测试、3 个握手行为测试与已有 14 个 Mesh 测试
全部通过；独立 HMAC 输入测试 1 项通过。cookie 固定 MAC 另以 OpenSSL 复算一致；
最初缺失 xxd 的管道输出已丢弃，改用直接 printf 二进制输入重新核验。
字段编号/类型/可选项清单见 `tests/fixtures/mesh-v1/README.md`。
新增固定测试最初的 Rust 借用错误已修复，未修改生产验证语义；后续定向测试退出 0。
`just fmt-check`、`just lint` 已通过；提交前再次执行完整 `cargo test --locked -p control`
以及包含最终固定 MAC 断言的 fmt/lint。实际 Linux 普通用户，无产品状态/网络副作用。
最终结果：完整 control 测试退出 0（436 个单元测试、19 个 Mesh 集成测试、
23 个既有 contract 集成测试；0 个 doctest 不作为新增行为证据）。最终 fmt/lint
均退出 0，证据 `locally checked`。上述 API 级验收闭合；回读唯一契约发现
C1/C7 的指纹和地址派生义务尚无对应勾选项，已在原验收区补列，任务保持 in progress。

第三块首次入口：`cargo test --locked -p control --test mesh_mailbox_wire`，
用例 `mesh_accept_preserves_dual_signatures_and_join_binding`、
`mesh_network_proof_and_vouch_bind_registration_nonce`、
`mesh_management_originals_are_authenticated_and_bounded`、
`mesh_mailbox_vectors_and_registration_budget`、`mesh_origin_and_pin_reject_ambiguous_inputs`。
覆盖原设计 API、最大名称/origin/admins/整数、独立 cookie 字节、双签名与身份/时间绑定。
新增 `mesh/mailbox.rs` 明确字段编号；join 在原字段后增加稳定 request_id，
registered 在原字段后增加独立 slot_status、受限 anchor 与创建凭据。
evict body 在原字段后保存完整 member_pub，vouch 最后携带独立 domain 签名。
这些字段落实契约 C2/C4/C5，不改变 Managed envelope。随后运行既有 Mesh 测试、
`just fmt-check` 和 `just lint`；第三块 5 个测试与已有 9 个 Mesh 测试全部通过，
fmt/lint 均退出 0，证据 `locally checked`。无产品网络/持久状态副作用。
跨仓所需的完整固定签名 fixture 及 WSS hello/cookie 认证向量仍待闭合。

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
- 2026-09-07：wire、身份/地址、认证、固定向量及本地验证闭合；任务 done。
