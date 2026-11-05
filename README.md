# masked-infer

[English below](#masked-infer-en)

路线 2「自研密态推理」的独立开源引擎代码库：面向主流开源大模型的掩码隐状态变换引擎，
可作为 Higress 生态密态安全层的可集成后端引擎。其核心原理为线性/非线性分离、
OTP 一次一密加法掩码、普通 GPU 满速盲算、密钥留可信环境；同类范式已有商用产品采用，
本库的开源生态位相对稀缺，主攻企业侧网关集成场景。本库仅提供可集成的引擎代码，
服务形态由集成方决定。

## 状态

- **阶段 0 骨架与阶段 1（CA-1 / CA-2 解耦 + 5 包迁入）已完成；阶段 2–4 待执行。**
- 模块路径 `github.com/FengYang/masked-infer`；`<org>` 默认取主仓 origin 所属账号
  `FengYang`，CI 变量 `SUB_ORG` 可覆写（见方案 §7）。
- `go 1.26.0`；`go.mod` 零 `require`、零 `replace`、零第三方依赖。
- 仓库只做本地 commit 留痕：无 remote、无 tag、未推送任何远端。

## 模块边界与落地状态

| 目录 | 职责 | 落地状态 |
|---|---|---|
| `core/` | 纯计算内核（QuantizedMatrix / CipherLinear / MaskImage / Unmask / Decode / int128·Mod64），含 CUDA / 昇腾 dlopen 后端 | 已落地（阶段 1）：10 个 `.go` + `.h` / `.cu` / `.cpp` 各 1 |
| `plan/` | TensorKey + 权重构建 | 已落地（阶段 1）：8 个 `.go` |
| `ref/` | 去量化参照前向（数值对拍基准） | 待迁移（阶段 2） |
| `demo/` | 合成小模型演示 | 已落地（阶段 1）：4 个 `.go` |
| `adapterkit/` | 跨模型 SDK：safetensors 解析、RoPE / GQA 助手、可信域 ops | 规划中，尚未建包 |
| `adapters/` | 具体模型适配 zoo（`qwen/` 为首个，后续 `llama/` 等按模型增长） | `qwen/` 已落地（阶段 1）：12 个 `.go` |
| `masklite/` | 纯标准库掩码流（CA-1） | 已落地（阶段 1）：`masklite.go` / `memzero.go` / `masklite_test.go` + `testdata/stream.golden` |
| `step/` | route2step 引擎侧协议部分（`step_exec` 协议，不含通用 TEE 运行时信封） | 待迁移（阶段 3） |
| `backend/` | `MaskedInferenceBackend` 接口与构造器（方案 §4.2，接口定义在新库侧） | 待建（阶段 4） |

## 依赖方向与固定不变量

- **依赖方向：网关 → 新库**。网关（主仓 `security-ai-gateway`）定义薄接入层并消费
  本库引擎；本库不得反向 import 网关的 `orchestrator` / `cryptop` / `cipher/mask`，
  由 G1 门禁强制（含 `_test.go` 闭包，防 `go mod tidy` 把主仓裸名写进 `go.mod`）。
- **INV-1 词表归网关**：Tokenizer / Embedding / LM head / argmax 采样留在网关（①）；
  本库是与词表无关的掩码隐状态变换引擎（吃网关加掩后的 embedding，吐掩码末层隐状态）。
- **INV-3 信任锚归网关**：密钥管理 / 远程证明 / attestation 在网关 `cryptop`，不进本库；
  `tee-infer-service` 为路由无关的通用可信运行时，不迁入本库，以宿主身份 import 本库引擎。
- **CUDA 与昇腾双一等公民**：`ACCEL_BACKEND_LIB=cuda` / `ascend` 两条构建轨道并列，
  cgo / !cgo 双版本 build tag 迁移时不得丢失（方案 §6-#2、CI matrix）。
- `cipher/mask` 采取受控双份：主仓原样保留，本库 `masklite` 自带纯标准库实现，两侧由
  G2 golden 逐字节比对兜底；主仓 `cipher/mask` 变更须重跑 golden 并两侧同批评审。

## 门禁与 CI

- **G1**（阶段 0 起常驻）：`scripts/gate_g1.sh`，`GOWORK=off` 下
  `go list -test -deps -f '{{.ImportPath}}' ./...`，禁止主仓裸名前缀、
  `github.com/<org>/security-ai-gateway/` 前缀与 `github.com/emmansun/gmsm` 命中。
- **G2**（阶段 1 起常驻）：`masklite` 单测对 `masklite/testdata/stream.golden` 逐字节断言；
  真机侧 `scripts/verify_golden_against_main.go` 引用主仓 `cipher/mask.NewStreamDomain` 复核。
  阶段 1 起 `masklite/*.go` 已落地，G2 由单元测试常驻守护，不再只是向量文件。
- `.github/workflows/ci.yml`：所有 job 显式 `GOWORK=off`，Go `1.26.0`；
  `g1` / `g2` / `test`（`go vet` + `go test`）/ `build`（CGO_ENABLED 0/1）/
  `accel`（cuda + ascend，🖥 待环境就绪，本轮禁用）五个 job。
- **复验脚本分层（跨 §5 全部阶段共用，非阶段 0 专用、不另写新脚本）**：
  `bash scripts/verify_all.sh` 是**本地静态段（默认）**，适用阶段 0–4 全部阶段，覆盖
  gofmt / G1 逻辑自检 / import 闭包三项真门禁 / 国密红线 / 许可自洽 / 仓库可 clone 留证，
  结论统一以 `[STATIC-PASS]` 标注；`bash scripts/verify_all.sh -baseline` 供阶段 3/4
  import 改写前做闭包 4 项计数强比对（默认弱校验，计数漂移不判红）。
- `bash scripts/verify_all.sh -remote` 是 **§5.1 门控 1–5 的共用真机入口**（阶段 1/3/4 复用
  同一脚本同一段），**仅在阶段 1+ 且 Go 1.26 真机可用时执行**：新库侧 `GOWORK=off`、
  主仓侧在 `go.work` workspace 内；所有 `go test -run` 均配 `-v` 与 `=== RUN` 实跑守卫。
- **阶段 0 / 1 只跑静态段**：真机段（`go build`、G1 真机判绿、cgo/!cgo 与 CUDA/昇腾双构建、
  门控 1–5）一律标「🖥 待环境就绪（未取证）」；静态段 `[STATIC-PASS]` 不得冒充门控判绿。

## 联调说明

主仓侧 `go.work` 由执行人**本地创建、不提交、不进 CI**（本库 `.gitignore` 已列出
`go.work` / `go.work.sum`；主仓 `.gitignore` 不作任何改动）。CI 一律 `GOWORK=off`，
`replace` 不进 `go.mod`。

## 许可

Apache-2.0，见 `LICENSE` / `NOTICE` / `SBOM/`。

---

<a id="masked-infer-en"></a>

## masked-infer (EN)

An independent open-source engine repository for Route 2 masked inference: a
vocabulary-agnostic masked-hidden-state transformation engine for mainstream
open-weight LLMs, designed as an integrable backend engine for the Higress
ecosystem's confidential-computing security layer. Its core principle is
linear/non-linear separation, one-time-pad additive masking, full-speed blind
compute on commodity GPUs, and keys retained in the trusted environment.
Commercial products already employ the same paradigm; the open-source niche for
this integration scenario is relatively scarce. This repository ships engine
code only; the service form is decided by the integrating party.

### Status

- **Stage 0 skeleton and Stage 1 (CA-1 / CA-2 decoupling plus the 5-package
  migration) are complete; Stages 2–4 are pending.**
- Module path `github.com/FengYang/masked-infer`; `<org>` defaults to `FengYang`
  (owner of the main repository origin) and can be overridden by CI variable `SUB_ORG`.
- `go 1.26.0`; `go.mod` has zero `require`, zero `replace`, zero third-party dependencies.
- Local-only commit: no remote, no tag, nothing pushed.

### Package boundaries and landing status

Landed in Stage 1: `core/` (10 `.go` files plus one each of `.h` / `.cu` / `.cpp`),
`core/trustedops/` (7 `.go`), `plan/` (8 `.go`), `demo/` (4 `.go`),
`adapters/qwen/` (12 `.go`) and `masklite/` (`masklite.go`, `memzero.go`,
`masklite_test.go` plus `testdata/stream.golden`).
Still pending: `ref/` (Stage 2), `step/` (Stage 3) and `backend/` (Stage 4).
`adapterkit/` is planned but not created yet.

### Boundaries and invariants

- **Dependency direction: gateway → this repository.** The gateway consumes the
  engine through a thin integration layer. This repository must never import the
  gateway's `orchestrator` / `cryptop` / `cipher/mask`; G1 enforces this over the
  test-inclusive dependency closure.
- **INV-1**: Tokenizer / Embedding / LM head / argmax sampling stay in the gateway.
- **INV-3**: Key management, remote attestation and the trust anchor stay in the
  gateway's `cryptop`. `tee-infer-service` is a route-agnostic trusted runtime and
  is not migrated here; it acts as a host importing this engine.
- **CUDA and Ascend are both first-class**: `ACCEL_BACKEND_LIB=cuda` and `ascend`
  are parallel build tracks, with cgo / !cgo build tags preserved during migration.
- `cipher/mask` is a controlled duplicate: the gateway package stays unchanged,
  while this repository ships a pure-stdlib `masklite` (Stage 1 / CA-1); G2 golden
  vectors lock byte-for-byte equivalence.

### Gates

- **G1** (`scripts/gate_g1.sh`, always on since Stage 0): under `GOWORK=off`,
  `go list -test -deps -f '{{.ImportPath}}' ./...` must contain no main-repo
  prefix, no `github.com/<org>/security-ai-gateway/` prefix and no
  `github.com/emmansun/gmsm`.
- **G2** (always on since Stage 1): `masklite` tests assert the golden vectors
  byte-for-byte; the real-machine tool `scripts/verify_golden_against_main.go`
  cross-checks against the gateway's `cipher/mask.NewStreamDomain`.
- CI: `.github/workflows/ci.yml`, all jobs set `GOWORK=off`, Go `1.26.0`,
  with `g1`, `g2`, `test` (`go vet` + `go test`), `build` (CGO_ENABLED 0/1) and
  `accel` (cuda + ascend, 🖥 environment-pending, disabled in this round) jobs.
- One verification script, shared across all stages (not Stage-0-only, no separate
  script): `bash scripts/verify_all.sh` runs the local static segment by default
  (valid for every stage, results tagged `[STATIC-PASS]`); the `-baseline` mode
  re-checks the import-closure counters before Stage 3/4 import rewrites;
  `bash scripts/verify_all.sh -remote` is the shared entry point for §5.1 gates 1–5,
  executable only from Stage 1 onward with a Go 1.26 machine. Stages 0 and 1 run the
  static segment only; every machine-side item remains 🖥 environment-pending (no
  evidence collected), and `[STATIC-PASS]` must never be read as a gate 1–5 pass.

### Workspace note

The gateway-side `go.work` is created locally by the executor, **not committed**
and not used in CI. This repository's `.gitignore` lists `go.work` / `go.work.sum`;
the gateway's `.gitignore` is not modified. CI runs with `GOWORK=off`; no `replace`
directive is used.

### License

Apache-2.0 — see `LICENSE`, `NOTICE`, `SBOM/`.
