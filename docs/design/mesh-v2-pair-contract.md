# Mesh v2 节点配对契约

本契约承接 [PLAN-223](../../../ns/docs/plan/PLAN-223.md) B1，由 shared control
定义，NS control 镜像使用相同源码和向量。现有 v2 allocation、双用途 IPv6
及短名派生保持不变。登记不是关系授权，静态凭据也不是业务 Ready。

## 格式与身份

- 新消息使用 `mesh.v2.*` API 和独立整数 CBOR map schema `2`；嵌套 pair
  记录同样使用 schema `2`。既有 allocation 内部保持原 schema `1`。
  未知字段、旧 pair schema、重复字段、非规范编码、额外尾部及过大输入拒绝。
- Relay 控制继续使用 `ControlEnvelope` 的签名、来源绑定、nonce、时间与载体
  验证；UDP/WSS framing 的 1200 字节限制不变。转投递保留原始端点签名 envelope，
  不以 Relay 重签代替端点签名。
- `MeshV2NodeIdentity` 保存完整 signing 与 WG 公钥。短名、地址、PIN 和指纹展示
  不能替代它。`MeshV2PairBinding` 的 first/second 按 signing 公钥字节升序排列，
  不表示申请者与批准者；同 signing 或同 WG 的自配对拒绝。
- realm 为 `SHA256("nsmesh-v2-realm\0" || authority_pub)`。authority_pub 必须来自
  本节点已认证并持久固定的登记信任。相同 DNS 根不意味着相同 authority。
  多 Relay 仅在共享该逻辑权威时同域；不得因连接恢复或签名密钥轮换默默改写 realm。

## 最短配对路径

1. `MeshV2PinSet`（`mesh.v2.pin.set`）：已认证登记节点管理自己的 PIN，TTL 为
   0 时关闭，否则上限 3600 秒。`MeshV2PinResult` 绑定请求 nonce/realm；PIN
   使用既有 `AB-12345678` 格式，附独立随机 generation 和绝对到期时间。
   每节点一份活动 PIN；轮换/关闭不改变其它节点及已有关系。Debug 隐藏 PIN。
2. `MeshV2PairLookup`（`mesh.v2.pair.lookup`）：完整申请者身份、realm、PIN、
   随机 request_id 和可选 return-route cookie。Relay 仅对已认证、已登记且通过
   来源/限流门的节点查找；未知/关闭/过期 PIN 不返回身份目录。
   UDP 首次使用现有原始 `Cookie` payload 应答（无签名 envelope），nonce 匹配
   请求；重试保留 request_id、携带 cookie，并换新的 envelope nonce。cookie 只
   证明来源可回传，不能作为身份/权限；WSS 使用已认证连接而不需要 UDP cookie。
   `MeshV2PairTarget` 返回准确目标身份、allocation、PIN generation 和有效期，
   绑定原 nonce/request_id/realm。客户端核对目标完整身份后才保存申请意图。
3. `MeshV2PairRequest`（`mesh.v2.pair.request`）：申请者签名的定向意图，包含
   双方完整身份、realm、operation_id、申请者自己的 generation、目标 PIN generation
   及 issued/expires。最长 120 秒。Relay 与目标 owner 都核对期限和 PIN generation。
   轮换/关闭先发生则尚未批准的旧申请失效；已经持久批准的操作按原绑定恢复。
4. 目标 owner 检查 deny 优先、容量、申请的一次性回答和本地撤销 floor；明确同意后
   持久保存准备状态，再产生 `MeshV2PairOffer`（`mesh.v2.pair.offer`）。它填入
   目标自己的 generation，签署完整 binding，并额外签署 PIN/期限等申请上下文。
   `verify_request` 将 offer 与申请者本地保存的原 request 逐字段绑定。
5. 申请者 owner 在锁内重新检查同一意图、身份、代次和策略，保存完整双签
   `MeshV2PairGrant` 后发送 `MeshV2PairApproved`（`mesh.v2.pair.approved`）。
   目标只在仍有匹配的本地批准/准备状态时提交完整 grant；单凭外来旧 grant
   不能创建丢失的本地授权。双方重新打开业务前均执行下一节的 session 流程。
6. `MeshV2PairRejected`（`mesh.v2.pair.rejected`）只结束准确 operation/peer 的
   一次申请。reason：0 拒绝、1 过期、2 策略暂停、3 deny、4 容量、5 已处理、
   6 并发操作被替代、7 当前不可用。拒绝不会隐式拉黑或撤销其它关系。

已持久准备的 offer 可在新的认证 envelope 中重新投递；Relay 验证原签名和原签发
时间处的期限，不因自己的临时申请缓存丢失永久阻止恢复。接收端必须保留准确的
本地申请/批准意图并重新检查 floor，才可调用
`offer.verify_request(&saved_request, offer.issued_at)` 恢复原操作；没有该本地材料
不能恢复。对新的申请/首次批准仍使用实际当前时间。

重复请求按 `(realm, 完整双方身份, operation_id)` 幂等，不创建第二条关系。
反向同时申请由两端 owner 采用同一规则：尚未产生持久批准时保留 signing 公钥
较小端发起的请求；一旦有持久准备/有效 grant，先收敛该操作，不能替换其授权。
同身份不同操作不可覆盖现有准备状态。超时/取消不证明远端未提交；已批准的准备
材料保留到完整提交，或通过持久撤销该代次明确失效。未批准申请可到期清理。

## 撤销、重开及 WG 持有证明

- 两个 generation 分别由对应端点对该 pair 持久管理，从 1 开始。撤销 floor
  单调记录已撤销到的本端/对端代次；有效 binding 的两端 generation 必须各自
  严格大于本地保留 floor。撤销/重新授权更新关系代次；普通 down/up 不更新。
  本地只允许当前准确 grant digest，不能以同代次的其它 operation 替换它。
- `MeshV2PairRevocation`（`mesh.v2.pair.revoke`）由任一端点单签，包含 realm、
  完整双方身份与该 owner 的 revoked_through。本地 remove 先持久化 floor 并撤回
  收发权限，再通知对端；通知失败单独报告。GC 不删除这些 floor。
- `MeshV2PairHello`（`mesh.v2.pair.hello`）只对本地有效且双签的 grant 产生，
  签署 realm、完整双方身份、grant digest 和本运行中新生成的随机 32 字节挑战。
- `MeshV2PairSession`（`mesh.v2.pair.session`）签署 grant digest、发送者、双方
  新鲜挑战、能力及 WG proof。WG proof 为
  `HMAC-SHA256(X25519(local_WG_secret, bound_peer_WG_pub), session_transcript)`；
  必须由本地 WG 密钥计算，不接收对端提供的 shared secret。全零 DH 结果拒绝。
  `sign`/`verify` 只接收该计算结果，调用者负责保密、清理与正确公钥来源。
  Relay 的 `verify_sender` 仅核对发送者签名和准确 grant，用于定向投递；它不验证
  WG possession，不得用它替代端点的完整 `verify` 或宣布业务 Ready。
- 产生 session proof 前必须已持久保存完整 grant；验证使用本地准确 grant、
  当前双方挑战、当前 policy/floor，再检查签名和 WG proof。匹配业务代次才安装
  精确 peer 路由。该协议无需用户重新批准有效关系，且不能用旧 owner 结果恢复业务。
  活动两端仍须在对应 WG 数据路径证明真正握手与业务质量，session 通过不是 Ready。
- 能力位：1 原生 IPv6，2 userspace IPv4 翻译；0 合法但不代表业务可用，未知位拒绝。
  每次 capability 或 challenge 变化重新验证 session，不把历史链路类型当作当前观察。

## 有界投递与消费者义务

`MeshV2PairPoll`（`mesh.v2.pair.poll`）只读取已认证节点自己的收件项，并可确认一个
delivery_id。`MeshV2PairDelivery`（`mesh.v2.pair.delivery`）每次最多投递一个原始
签名 envelope，空收件箱不带 ID 或正文；原始正文最多 850 字节。消费方验证原始
消息与本地状态后才确认。投递不是自动批准，Relay 也不成为 overlay WG peer。
定向发送的接收确认也使用 `MeshV2PairDelivery`，nonce 匹配该发送请求，正文/ID
均为空；此确认仅证明 Relay 接收了投递，不表示对端已批准、落盘或上线。

本文件冻结共享表示及端点核验接缝。Relay 的 cookie/rate/容量/持久注册、队列生命周期、
实际动态路由和 NS 的持久事务/owner/CLI 仍须分别实现并联合验证；它们未因本契约存在
而闭合。B1 的 NS 镜像向量一致性须由 NS 主任务验收，B2–B5 的真实场景不能由 codec
单测替代。固定向量与负例在 [pair/tests.rs](../../crates/control/src/mesh/pair/tests.rs)。

## 本块验证

2026-09-13，Linux：`cargo test --locked -p control --lib mesh::pair` 实际执行 9 项，
全部通过，无 ignored。覆盖双方签名、真实 X25519、完整申请绑定、撤销 floor、旧协议／
未知字段／非规范顺序拒绝、当前挑战及反射负例、PIN 脱敏和 UDP/WSS 封装大小。
`just fmt-check`、`just lint` 通过。证据为 `locally checked`；本块不创建宿主网络
资源，cleanup 不适用。尚未验证 NS 镜像、真实 PIN 服务、双端持久化或原生业务。

### Authorized peer directory

`MeshV2PairDirectoryQuery` (`mesh.v2.pair.directory`) carries realm, caller
`node`, full `target` identity and `grant_digest`. Its `verify_grant` checks
both grant signatures and the exact two identities. A relay only answers from
its current verified grant projection and committed target allocation; it does
not expose a name search or public identity enumeration. After relay restart,
endpoints first re-submit their saved `MeshV2PairApproved` under a fresh signed
envelope. Directory reads do not renew that projection.

`MeshV2PairDirectoryResult` (`mesh.v2.pair.directory.result`) carries the
request envelope nonce, realm, full target identity, grant digest and allocation.
After checking the pinned relay's enclosing signature, consumers call
`verify_query` with the exact pending query and nonce, then recheck local current
relation/revocation state before publishing DNS or routes. Allocation WG key
and addresses must validate against the exact target. This result contains no
live session capabilities and grants no business permission.

The directory contract test checks query/grant and response/nonce/identity
mismatches, invalid allocation and closed-map decoding. All 10 pairing contract
tests pass; consumer transport and native DNS acceptance remain separate gates.
