# 20261021-1355-authentication-source-scope Authentication source scope

- **status**: completed
- **createdAt**: 2026-10-21 13:55
- **priority**: P1

## Description

Require exact authentication source selection and nodes-only registration authority, including Equal. Independent bytes cover per-scope acceptance and swapped-source refusal without runtime or I/O.

## ActiveForm

共享 codec 与独立向量已验证；跨仓行为验收由 C05 继续。

## Dependencies

- **blocked by**: none
- **blocks**: none

## Notes

Investigation and approved implementation are described in the matching plan. Verification completed.

## Acceptance results

- Registration comparison requires nodes in the accepted Network, including initial and Equal enrollment. Correctly signed egress and other-Network registration bindings are refused.
- Authentication requests require the exact five-field tuple with a canonical realm and bounded scope selector; old arity, invalid purpose, malformed selector and invalid scope bounds are refused.
- Independent Python fixtures cover separate nodes and egress authentication in one Network with independent pending nonces, retained bindings and swapped-scope/realm refusal. Existing nested signature, correlation, source replacement, delayed publication and immutable-clear checks remain.
- Failing-first evidence: `cargo test -p nsshared-proto --test source_selection_vectors source_selection_fence --locked` failed with `Cbor(ArrayLength { expected: 4, actual: 5 })` before the request codec changed.
- The focused source-selection and control-exchange suites passed all 11 tests. `just fmt-check lint` passed before testing.
- `just self-check feat/l8-account-profile` passed at `dececf6`: 41 check-selection tests, 500 tests passed with zero skipped, doctests and documentation checks passed. Only these acceptance records changed afterward.
- Specifications, profile and review request describe the incompatible request delta. AuthenticationResponse and SignedSourceBinding bytes remain unchanged. NSD N04 adoption, producer-owned vectors and real interoperability remain outstanding.


## 2026-10-28 C05 精确注册条件补充

用户已批准补齐 shared 认证的 Node、credential incarnation、Account activation 条件；保持 I/K，复用现有 receipt，不把 source generation 当作 Account activation。本块复用既有认证交换计划，不重做源选择或网关协议。当前 `main` 基线为 `6b5490ec834e80cbe33f60cb9ac7a0fbb7aad4d6`，任务分支 `feat/account-readmission`。

`AuthenticationRequest.registration` 为 `Option<RegistrationCondition>`，条件由三个非零 16 字节标识组成。请求固定六字段；owned Connector 必须带条件，非 Account Gateway 可显式 null，由服务端已认证的记录判断。旧五字段直接拒绝。共享库负责结构与规范编码，NSD 负责同一事务内当前 Account、shared custody 与条件比较；NS/NSGW 直接消费者同步采用。后者的生产 ABA/并发验收归 C05，不能由 codec 通过替代。

- [x] 规范、纯 codec、公开导出与独立向量一致；拒绝旧 arity、空/错误长度/零值/多余条件字段。
- [x] 每个精确条件独立保留，不影响 I/K、source selector 或正常 source 更新语义。
- [x] 定向 Account 契约、受影响 crate 默认与 unstable-account 编译/lint、文档和向量生成检查通过。

首次失败：更新独立向量后，`cargo test --locked -p nsshared-control --features unstable-account --test account control_exchange_vectors` 在 `authentication` 用例失败，旧 codec 拒绝新增字段（1 failed、131 filtered）。最终 Account 契约测试 133/133 通过；`just dev-check` 的默认及 unstable-account 全目标 Clippy、fmt 通过；42 份向量再生成检查、定向 typos、diff 检查与受影响 crate 的 rustdoc（deny warnings）通过。未重复全量 QA；NS/NSD/NSGW 的精确版本接入及同 I/K ABA 验收仍由 C05 执行，未据此宣称完成。
