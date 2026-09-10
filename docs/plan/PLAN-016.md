# PLAN-016：Mesh v1 共享 wire 与确定性状态契约

- **状态（status）**: in progress
- **负责人（owner）**: B：Relay 服务与共享协议负责人；A 统筹跨仓验收；范围、风险与发布决定由仓库负责人负责
- **创建日期（createdAt）**: 2026-09-07
- **目标（target）**: 完成本仓 Mesh v1 实现并提供当前平台验证证据
- **实施分支（branch）**: `feat/mesh-mode`
- **链接（links）**: [主计划 PLAN-218](../../../ns/docs/plan/PLAN-218.md)、[唯一契约](../../../ns/docs/plan/PLAN-218-mesh-contract.md)、[SH-MESH-001](../task/SH-MESH-001.md)、[SH-MESH-002](../task/SH-MESH-002.md)

## 目标（Goal）

交付 control/common 的 Mesh v1 能力，承接主计划分配给本仓的实现边界；与另两仓使用匹配 wire 和固定向量。

## 非目标（Non-Goals）

2026-09-10 双设备修订仅修改计划资产，不启动实现、暂存、提交或推送。未来实现不修改 deploy、独立 docs、NSD、App、移动或 FFI，不新增 relay 运维 CLI/永久账本服务，不合并 NS 本地库与 ns-shared 拓扑。

## 权威上下文（Authoritative Context）

本地规则：用户提供的一般仓库规则（本仓未发现 AGENTS.md）。权威产品设计、**docs 基线 `0d1f03e75572fe780ce9af3c402e0fb8106e5767`**、三仓代码 hash、已选 D1–D9 和验证范围例外均见 [主计划](../../../ns/docs/plan/PLAN-218.md)。本计划不复制第二套 wire/存储/恢复定义。

本仓从干净 main 仅快进拉取并创建分支；source reviewed only，不能据复用候选推断新能力已实现。现有无关 plan/task 保留其状态与范围。

## 范围与任务（Scope / Tasks）

| 顺序 | 任务 | 状态 | 依赖 |
| --- | --- | --- | --- |
| 10 | [SH-MESH-001](../task/SH-MESH-001.md) | in progress | 见任务的依赖和独立边界 |
| 20 | [SH-MESH-002](../task/SH-MESH-002.md) | in progress | 见任务的依赖和独立边界 |

各任务保留独立验收、实现块与提交/回滚边界，已交付块按实际证据复用。本计划归
大任务 B，仓库写入、共享接口、首次接管及稳定版本交接统一遵循
[主计划双设备分工](../../../ns/docs/plan/PLAN-218.md#双设备分工与交接)。默认 B 负责
`nsgw`/`ns-shared`、A 负责 `ns`；负责人已补充允许 B 在预期不冲突、不重复时
修改、提交和普通推送 NS。A 当前持续修改 NS 源码，B 跨仓写入前先交接具体文件。

B 交付 shared wire、归约、固定向量及直接验证，供 B 的 NSGW 和 A 的 NS 镜像消费；公开语义变更按主计划先统一契约；NS 写入沿上述归属及负责人明确例外执行。
开放决定仅阻断依赖块，不等待另一大任务整体完成才推进稳定接口内的工作。
本次不改变任务状态、验收勾选、既有证据或下一期范围；历史准备阶段描述不作为
当前设备已就绪或完整能力已交付的证据。后续执行以主计划最新范围、当时用户授权
和实际块就绪条件为准。

## 行为契约与能力矩阵（Behavior / Capability Matrix）

| 能力 | 支持/必需性 | 失败语义 | 证据 |
| --- | --- | --- | --- |
| 本仓任务分配的 Mesh 协议/状态能力 | 主计划契约 C1–C9；required | 未通过原签名/权限/寿命/摘要/容量验证不得改变权威状态 | reviewed only |
| Managed 兼容 | 当前默认配置和控制流保持；required | 不静默选择 standalone 或弱化身份校验 | reviewed only |
| 跨仓一致 | 相同向量和版本；required | 不匹配显式拒绝，不宣称混合版本互操作 | reviewed only |

## 平台与失败矩阵（Platform / Failure Matrix）

当前宿主 macOS；本仓逻辑/文件/socket 测试使用私有临时目录和端口，普通用户运行。只有实际需要的特权命令才最小 sudo，记录身份与清理，不预先增加系统权限。Linux/macOS 各自原生验证；Windows native 仅 release。shared 纯函数不以单元测试替代 relay 或 NS 原生网络证据。

| 失败 | 处理 | 跟踪 |
| --- | --- | --- |
| wire/签名/seq/摘要不一致 | 拒绝相应消息，不扩大副作用 | 对应任务与契约 C2/C4/C5 |
| IO/容量/恢复材料不足 | 保留原有可信状态；报告错误或等待，不伪造成功 | 对应任务 |
| 缺当前平台必需验证能力 | 保留未关闭验收，完成其它独立块 | 对应任务验证段落 |
| 非当前平台未执行 | 不报告 native 通过，不注册新的 gate | 主计划 deferred coverage |

## 验证矩阵（Validation Matrix）

| 范围 | 命令/方法 | 预期 | 阶段 | 当前证据 |
| --- | --- | --- | --- | --- |
| 计划资产 | 相对链接、索引/编号、状态、依赖、文件范围、whitespace | 完整一致且只改计划资产 | implementation | locally checked |
| 任务逻辑 | 当前平台执行 `just fmt-check`、`just lint` 与 control 定向测试；交付执行 `just qa` 当前平台适用项。 | 定向场景真实执行；零匹配/skip 不算通过 | implementation / merge | assumed |
| 跨仓 | [NS-MESH-007](../../../ns/docs/task/NS-MESH-007.md)；本仓任务保留原始server/codec证据 | 正常与故障场景均满足主契约 | implementation / merge | assumed |

未新增测试入口在首次实现执行前由任务填写精确命令和实际测试列表。实际结果保存于任务，不在本计划复制日志。此轮未执行产品测试或 sudo。

双设备验证遵循 [主计划联合验证安排](../../../ns/docs/plan/PLAN-218.md#双设备联合验证安排)。
B 在块内运行本仓既有检查，向 A 交付精确版本/feature/环境、实际结果、未验证项和
清理证据；本期范围仍是 Unix 非出口 Mesh。B 优先使用 Linux，实际设备能力执行时
确认；准备阶段 macOS 描述不证明本次已取得原生证据。
本仓实现及必需块内检查交付后即可进入相应集成交接，不要求本计划先 `done`；
本计划的跨仓退出项由 NS-MESH-007 匹配三仓版本的结果关闭。A 维护 NS 验收汇总，
B 维护本仓原始证据并链接联合结果；最终 Linux live-e2e 的既定实现前置、macOS
原生义务和 full/slim/适用 QA 均不因分工取消。本次未运行验证或改变完成态。

## 决策、暂缓与回滚（Decisions / Deferred / Rollback）

### 2026-09-10 B 协议提案交接（逐项选择）

接管基线：NS `d3ce46ac`、NSGW `6902115`、shared `7242cd7`，均为
`feat/mesh-mode`；A 随后交付 NS `81246bd8`，B 尚未消费该版本。旧 Linux 执行
任务最后状态为 interrupted，B 接管时三仓无 Git lock；NS 工作树干净，未观察到
其它 NS 写入任务。本轮 B 只写 NSGW/shared；历史临时草稿不作为实现输入。
本段区分已选项和待审核候选，不构成第二套协议。
负责人选择语义后由 A 或明确获授权的 B 更新唯一契约并给出稳定 NS commit，再实现公开类型、
完整帧固定向量与 NSGW 接线；A 负责 NS 镜像。每次交接包含三仓版本及拒绝边界。

- **WSS 外层**：负责人于本日 B 对话已选择：服务端独立 32-byte binary
  challenge，客户端独立既有 WssHello CBOR binary 回复，成功后才允许既有
  control/WG framing。保持连接/origin/双 key 绑定、30 秒期限和一次性消费；
  认证前其它 binary/text 应拒绝。C2 已按补充授权在 NS `c884f3a9` 同步，
  A 已确认读取；独立固定向量及实际 WSS 运行接线分别验证，选择不等于已实现。
- **恢复响应**：C2/C5 与 shared 现状已有 RestoreBegin/Chunk/Finish 请求，但没有
  对应结果 payload；finish 的“返回已固定状态”不足以决定 ACK 和重试关联。
  建议增加签名 `mesh.restore.result`，CBOR 编号候选为
  `1 network_pub:bytes32, 2 request_id:bytes16, 3 uploader_pub:bytes32,
  4 anchor_seq:u64, 5 state_digest:bytes32, 6 phase:u64,
  7 chunk_index:optional u64, 8 status:u64`。phase 候选为 begin=0/chunk=1/finish=2，
  index 仅 chunk 存在；status 候选为 accepted=0/installed=1/incomplete=2/
  conflict=3/busy=4，合法组合由 A 冻结。响应沿既有 envelope 关联请求 nonce；
  只有验证过 uploader/候选绑定才回复。installed 只在持久 CAS 后返回；同锚点
  重试可确认既有安装，更高状态只报 conflict，不降低锚点或泄露完整 current。
  待负责人/A 确认逐块 ACK 还是其它恢复反馈策略，以及结果组合与授权边界；
  不复用管理 CommitResult 冒充恢复回执，不新增 relay 账本下载。
- **discovery 文档（已选）**：负责人本日已采纳本提案，NS `4ddc6968` 唯一契约
  C1.1 已同步；类型/向量与真实服务仍分块验证。对象字段为
  `version:"mesh_trust.v1", relay_origin:string,
  relay_key:{current:lowercase hex32,next:optional lowercase hex32},
  udp_port:u16,wss_port:optional u16,capabilities:string[]`；端口须非零，
  origin 使用既有 canonical 规则；current 来自实际持久 relay identity。
  `next` 仅有已配置轮换材料时出现，不在本块新增轮换策略。
  仅声明实际就绪的 udp/wss 能力，未知版本、重复或矛盾字段拒绝；消费端按 C1.1
  和共享固定向量核对字段、可选编码及有限能力，不能自行扩展。slim 不开启 TLS/discovery，既有显式
  不支持行为保留；不把 full 的 UDP-only 阶段误报为完整 WSS 支持。

request winner 查询的授权范围和 vouch 的 seq/digest/anchor/旧水位转换仍按
主计划开放项单独选择，不能由上述 framing 提案隐式决定。D2 的控制/注册心跳
方案已由负责人在 B 对话选定，C5 已在 NS `c884f3a9` 同步；不影响 shared 现有 wire。
该段证据为 `reviewed only`：已对照固定设计基线、C2/C5 和当前 recovery 类型，
未修改协议实现、向量或 NS 文件，未运行产品验证。

无新增负责人决策项；主计划 D1–D9 为 selected，未验证不标 resolved。主计划的当前平台范围由负责人明确授权，现有质量门定义不变。若聚合 QA 涉及未授权目标，只报告实际运行的当前平台子项；不能报完整 QA 通过。Linux、Windows native 与独立 docs 待审核同步统一在 [主计划](../../../ns/docs/plan/PLAN-218.md) 跟踪；不作为本轮计划准备退出条件。

未来回退先停止新 Mesh 功能并清理其拥有的运行对象，保留密钥、锚点与回执；旧程序不能忽略未知 schema 或重置 seq。Managed 默认配置不承担 Mesh state 迁移。共享 wire 变更必须连同兼容向量评审，禁止单端静默降级。

## 退出标准（Exit Criteria）

- [ ] SH-MESH-001 当前范围的验收与实际证据已闭合。
- [ ] SH-MESH-002 当前范围的验收与实际证据已闭合。
- [ ] 本仓当前平台适用质量检查已记录实际结果。
- [ ] 本仓与 NS 的跨仓兼容场景已有证据链接。
- [ ] 设计偏离与剩余发布验证范围已按主计划记录。

## 计划级验证结果（Plan-level Verification Results）

2026-09-09：负责人新选 C6.3 的 WG-only 密钥请求/交付已补 codec、完整签名帧
固定向量及六项测试。完整 control（442 单元/55 Mesh 集成/23 既有契约）和 fmt/lint
均通过，详见[任务验证](../task/SH-MESH-001.md#验证verification)。仅关闭本共享
协议块；NS 镜像、实际权限与密钥安装、完整入网及跨仓/native 验收保持开放。

2026-09-09：负责人新选 C6 版本化同步方案已实现共享 wire/摘要与十个固定向量；
七项新增、完整 control（436 单元/55 Mesh 集成/23 既有契约）及 fmt/lint 均通过。
唯一契约已补 C6.1/C6.2，NS 镜像漂移检查通过、Cargo 门禁仍待完成，故任务及对应
退出项保持开放，见[任务验证](../task/SH-MESH-001.md#验证verification)。当前本机
Linux 优先，不把原准备阶段 macOS 描述当作当前原生证据。

2026-09-09：负责人明确 evict 连带管理员移除及实际变化时 revision 加 1 的规则，
该决策阻断解除；纯归约块已通过 10 项定向、49 项 Mesh 回归与 fmt/lint，
见[任务验证](../task/SH-MESH-002.md#验证verification)。本机 Linux 验证优先；
vouch 水位保护的直接接线证据、NS 镜像及计划级交付检查仍未完成，不关闭退出项。

2026-09-08：add/admins 独立归约块完成，见[任务验证](../task/SH-MESH-002.md#验证verification)。
Linux 45 项 Mesh 回归与 fmt/lint 通过；历史权限、成员水位保留、管理员 revision
竞态与容量边界已有直接证据。evict 管理员转换仍待决定，完整任务、跨仓及 native
验收未闭合，继续推进不依赖该决定的实现块。

2026-09-08：genesis 独立块完成，见[任务验证](../task/SH-MESH-002.md#验证verification)。
Linux 39 项 Mesh 回归与 fmt/lint 通过；创建材料和回执复算已有直接证据，
不替代连续权限归约、relay 持久化、跨仓或 native 验收。

2026-09-08：SH-MESH-002 owner 独立块完成，见[任务验证](../task/SH-MESH-002.md#验证verification)。
Linux 35 项 Mesh 回归、29 组独立固定向量及 fmt/lint 通过；管理员权限归约、
跨仓互操作和 native 验收仍未闭合，任务与计划继续 in progress。

2026-09-07：SH-MESH-001 纯协议范围闭合，见任务最终验证：固定 27 组协议向量，
独立身份/地址结果，完整 control 回归（436 单元 + 23 Mesh + 23 既有契约）
及 fmt/lint/deny/shear 均成功。实际环境 Linux，证据 `locally checked`。
SH-MESH-002、跨仓互操作、计划级质量门及 macOS native 仍未闭合，计划继续执行。

2026-09-07 实现已由后续调用授权。SH-MESH-001 的 framing/时间校验首块和
Managed envelope 回归取得 Linux 本地证据，见[任务验证](../task/SH-MESH-001.md#验证verification)。
完整 wire、归约、跨仓兼容及 macOS 验收仍未闭合，退出标准保持未勾选。

2026-09-07：计划资产经过连续审查修订；链接、索引、状态、checklist 和文件范围检查通过，证据 `locally checked`。实现和行为证据未取得，任务均 pending，退出条件未勾选。Git 写操作仅限已授权的前置 main/ff-only/分支准备，无后续 Git 写操作。
