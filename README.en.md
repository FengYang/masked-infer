# masked-infer

> English ｜ [中文](./README.md)

An independent open-source engine repository for Route 2 masked inference: a
vocabulary-agnostic masked-hidden-state transformation engine for mainstream
open-weight LLMs, designed as an integrable backend engine for the Higress
ecosystem's confidential-computing security layer. Its core principle is
linear/non-linear separation, one-time-pad additive masking, full-speed blind
compute on commodity GPUs, and keys retained in the trusted environment.
Commercial products already employ the same paradigm; the open-source niche for
this integration scenario is relatively scarce. This repository ships engine
code only; the service form is decided by the integrating party.

## Why masked-infer (key advantages)

1. **Confidential inference without dedicated hardware**: linear/non-linear separation plus OTP additive masking lets inference run at full speed as "blind compute" on commodity GPUs/CPUs, with keys retained in the trusted environment — no confidential-computing instances or specific TEE hardware required.
2. **Vocabulary-agnostic, extensible per model**: fully decoupled from Tokenizer / Embedding / LM head / sampling (INV-1) — masked embeddings in, masked final hidden states out; `adapters/qwen/` is the first adapter, with the adapter zoo growing per model (`llama/` etc. to follow).
3. **Zero third-party dependencies, easy to audit**: `go.mod` has zero `require`, zero `replace`, zero third-party dependencies; the core mask stream `masklite` is a pure Go standard-library implementation — a small dependency surface means a small supply-chain and audit surface.
4. **CUDA and Ascend as equal first-class citizens, no vendor lock-in**: linear operators go through one C ABI (`accel_cipher_linear_int128`), with `ACCEL_BACKEND_LIB=cuda` / `ascend` as parallel build tracks; the CPU path is real-machine evidenced.
5. **Verifiable numerical correctness**: `ref/` dequantized reference forward serves as the numerical baseline; G2 golden vectors lock the mask stream byte-for-byte; real-machine evidence shows `MaxAbsDiff≈1.3e-5`, `Top1=3/3`, and 282-step end-to-end `top-1=23811` (see "Gates" below).
6. **Clean boundaries, small integration surface**: one-way dependency direction (host → this repository, enforced by the G1 import-closure gate); key management / remote attestation / trust anchor stay out of this repository (INV-3); a single external interface, `backend.MaskedInferenceBackend`, and the service form is decided by the integrator.
7. **Open source, reproducible, compliance-friendly**: Apache-2.0 + `NOTICE` + `SBOM/`; CI runs entirely with `GOWORK=off`, and gate scripts (`scripts/verify_all.sh`) can be rerun locally — conclusions never rest on verbal claims.

**In one sentence**: if you need to integrate confidential inference — where user data and model weights stay invisible to the inference backend — into your own gateway or service without buying dedicated confidential-computing hardware, masked-infer is a zero-dependency, numerically verifiable, hardware-vendor-neutral engine to start from.

## Status

- The engine core (`core/`), weight construction (`plan/`), dequantized reference
  forward (`ref/`), synthetic small-model demo (`demo/`), the Qwen adapter
  (`adapters/qwen/`), the pure-stdlib mask stream (`masklite/`) and the backend
  interface (`backend/`) are all landed.
- Module path `github.com/FengYang/masked-infer`; `go 1.26.0`; `go.mod` has
  zero `require`, zero `replace`, zero third-party dependencies.

## Package boundaries and landing status

Landed packages: `core/` (10 `.go` files plus one each of `.h` / `.cu` / `.cpp`),
`plan/` (8 `.go`), `ref/` (dequantized reference forward, numerical baseline),
`demo/` (4 `.go`), `adapters/qwen/` (12 `.go`), `masklite/`
(`masklite.go`, `memzero.go`, `masklite_test.go` plus `testdata/stream.golden`)
and `backend/` (`backend/backend.go`, the `MaskedInferenceBackend` interface and
constructors).

## Boundaries and invariants

- **One-way dependency direction: host → this repository.** The host defines the
  thin integration layer and consumes the engine; this repository never imports
  host implementations, enforced by G1 over the test-inclusive dependency closure.
- **INV-1**: Tokenizer / Embedding / LM head / argmax sampling stay with the host;
  this repository is a vocabulary-agnostic masked-hidden-state transformation
  engine (masked embeddings in, masked final hidden states out).
- **INV-3**: Key management, remote attestation and the trust anchor stay out of
  this repository; the engine is importable by a generic trusted runtime acting
  as the host.
- **CUDA and Ascend are both first-class**: `ACCEL_BACKEND_LIB=cuda` and `ascend`
  are parallel build tracks, with cgo / !cgo build tags preserved (CI matrix).
- `cipher/mask` and `masklite`: this repository ships a pure-stdlib `masklite`,
  with G2 golden vectors locking byte-for-byte equivalence against the reference
  implementation.

## Gates

- **G1** (`scripts/gate_g1.sh`): under `GOWORK=off`, the full dependency closure
  from `go list -test -deps -f '{{.ImportPath}}' ./...` guards the one-way
  "host → this repository" dependency direction.
- **G2**: `masklite` tests assert the golden vectors (`masklite/testdata/stream.golden`)
  byte-for-byte; the real-machine tool `scripts/verify_golden_against_main.go`
  cross-checks against the reference implementation.
- CI: `.github/workflows/ci.yml`, all jobs set `GOWORK=off`, Go `1.26.0`,
  with `g1`, `g2`, `test` (`go vet` + `go test`), `build` (CGO_ENABLED 0/1) and
  `accel` (cuda + ascend) jobs.
- `bash scripts/verify_all.sh` is the local re-verification entry point
  (covering gofmt / G1 / import closure / license consistency static gates);
  `-remote` is the real-machine mode.
- **Real-machine evidence (Go 1.26, CPU path)**: `go build ./...` / `go vet ./...`
  return RC=0; the G2 cross-check shows `MaxAbsDiff=1.355e-05` / `1.329e-05` with
  `Top1=3/3`; the end-to-end run of 282 steps yields `top-1=23811` (PASS).

## License

Apache-2.0 — see `LICENSE`, `NOTICE`, `SBOM/`.
