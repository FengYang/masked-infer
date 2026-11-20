# masked-infer

> 中文版 ｜ [English](./README.en.md)

路线 2「自研密态推理」的独立开源引擎代码库：面向主流开源大模型的掩码隐状态变换引擎，
可作为 Higress 生态密态安全层的可集成后端引擎。其核心原理为线性/非线性分离、
OTP 一次一密加法掩码、普通 GPU 满速盲算、密钥留可信环境；同类范式已有商用产品采用，
本库的开源生态位相对稀缺，主攻企业侧网关集成场景。本库仅提供可集成的引擎代码，
服务形态由集成方决定。

## 本代码库的优势（为什么值得关注与采用）

1. **不依赖专用硬件的密态推理**：线性/非线性分离 + OTP 一次一密加法掩码，推理在普通 GPU/CPU 上满速"盲算"，密钥始终留在可信环境——不需要机密计算实例或特定 TEE 硬件。
2. **词表无关、按模型扩展**：与 Tokenizer / Embedding / LM head / 采样完全解耦（INV-1），输入加掩 embedding、输出掩码末层隐状态；`adapters/qwen/` 为首个适配器，适配 zoo 按模型增长（`llama/` 等后续加入）。
3. **零第三方依赖、易审计**：`go.mod` 零 `require`、零 `replace`、零第三方依赖；核心掩码流 `masklite` 纯 Go 标准库实现——依赖面小，供应链与审计面就小。
4. **CUDA 与昇腾双一等公民，不锁厂商**：线性算子统一 C ABI（`accel_cipher_linear_int128`），`ACCEL_BACKEND_LIB=cuda` / `ascend` 双构建轨道并列，CPU 路径已真机取证。
5. **数值正确性可对拍验证**：`ref/` 去量化参照前向作数值基准；G2 golden 对掩码流逐字节锁定；真机取证 `MaxAbsDiff≈1.3e-5`、`Top1=3/3`、282 步端到端 `top-1=23811`（证据见下文"门禁与 CI"）。
6. **边界清晰、集成面小**：依赖方向单向（宿主 → 本库，G1 import 闭包门禁强制）；密钥管理 / 远程证明 / 信任锚不进本库（INV-3）；对外仅 `backend.MaskedInferenceBackend` 一个接口，服务形态由集成方决定。
7. **开源、可复现、合规友好**：Apache-2.0 + `NOTICE` + `SBOM/`；CI 全程 `GOWORK=off`，门禁脚本（`scripts/verify_all.sh`）可本地复跑——结论不依赖口头承诺。

**一句话**：如果你要在不采购专用机密计算硬件的前提下，把"用户数据与模型权重对推理后端不可见"的密态推理集成进自己的网关或服务，masked-infer 提供一个零依赖、可对拍验证、不锁硬件厂商的引擎起点。

## 状态

- 引擎内核（`core/`）、权重构建（`plan/`）、去量化参照前向（`ref/`）、合成小模型演示（`demo/`）、Qwen 适配器（`adapters/qwen/`）、纯标准库掩码流（`masklite/`）与后端接口（`backend/`）均已落地。
- 模块路径 `github.com/FengYang/masked-infer`；`go 1.26.0`；`go.mod` 零 `require`、零 `replace`、零第三方依赖。

## 模块边界与落地状态

| 目录 | 职责 | 落地状态 |
|---|---|---|
| `core/` | 纯计算内核（QuantizedMatrix / CipherLinear / MaskImage / Unmask / Decode / int128·Mod64），含 CUDA / 昇腾 dlopen 后端 | 已落地：10 个 `.go` + `.h` / `.cu` / `.cpp` 各 1 |
| `plan/` | TensorKey + 权重构建 | 已落地：8 个 `.go` |
| `ref/` | 去量化参照前向（数值对拍基准） | 已落地：plain_forward.go / plain_forward_test.go |
| `demo/` | 合成小模型演示 | 已落地：4 个 `.go` |
| `adapters/` | 具体模型适配 zoo（`qwen/` 为首个，后续 `llama/` 等按模型增长） | `qwen/` 已落地：12 个 `.go` |
| `masklite/` | 纯标准库掩码流 | 已落地：`masklite.go` / `memzero.go` / `masklite_test.go` + `testdata/stream.golden` |
| `backend/` | `MaskedInferenceBackend` 接口与构造器 | 已落地：`backend/backend.go` |

## 依赖方向与固定不变量

- **依赖方向单向：宿主 → 本库**。宿主定义薄接入层并消费本库引擎；本库不反向依赖宿主实现，
  由 G1 门禁强制（含 `_test.go` 闭包）。
- **INV-1 词表无关**：Tokenizer / Embedding / LM head / argmax 采样由宿主持有；
  本库是与词表无关的掩码隐状态变换引擎（吃加掩后的 embedding，吐掩码末层隐状态）。
- **INV-3 信任锚归宿主**：密钥管理 / 远程证明 / attestation 不进本库；
  本库引擎可被通用可信运行时以宿主身份 import。
- **CUDA 与昇腾双一等公民**：`ACCEL_BACKEND_LIB=cuda` / `ascend` 两条构建轨道并列，
  cgo / !cgo 双版本 build tag 并存（CI matrix）。
- **`cipher/mask` 与 `masklite`**：本库自带纯标准库掩码流实现 `masklite`，
  与参照实现由 G2 golden 逐字节比对锁定一致。

## 门禁与 CI

- **G1**：`scripts/gate_g1.sh`，`GOWORK=off` 下对 `go list -test -deps -f '{{.ImportPath}}' ./...`
  全量依赖闭包检查，守护"宿主 → 本库"的单向依赖方向。
- **G2**：`masklite` 单测对 `masklite/testdata/stream.golden` 逐字节断言；
  真机侧 `scripts/verify_golden_against_main.go` 可对照参照实现复核。
- `.github/workflows/ci.yml`：所有 job 显式 `GOWORK=off`，Go `1.26.0`；
  `g1` / `g2` / `test`（`go vet` + `go test`）/ `build`（CGO_ENABLED 0/1）/
  `accel`（cuda + ascend）五个 job。
- `bash scripts/verify_all.sh` 为本地复验入口（覆盖 gofmt / G1 / import 闭包 /
  许可自洽等静态门禁），`-remote` 为真机模式。
- **真机取证（Go 1.26，CPU 路径）**：`go build ./...` / `go vet ./...` RC=0；
  G2 对拍 `MaxAbsDiff=1.355e-05` / `1.329e-05`、`Top1=3/3`；
  端到端 282 步 `top-1=23811`（PASS）。

## 许可

Apache-2.0，见 `LICENSE` / `NOTICE` / `SBOM/`。
