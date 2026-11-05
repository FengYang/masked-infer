#!/usr/bin/env bash
# verify_all.sh —— §5 阶段 0 一键复验（本地静态段 + 🖥 真机段）。
#
# ⚠ 真机 192.168.31.248 SSH 当前不可用，真机段未取证；
#   **禁止把本地静态段 PASS 冒充门控 1–5 PASS**。
#   本机仅 go1.20.3，无法编译 go 1.26.0 模块；编译/真机类验收一律标
#   「🖥 待环境就绪（未取证）」，环境恢复后用 `bash scripts/verify_all.sh -remote` 一键跑。
#
# 用法：
#   bash scripts/verify_all.sh            # 本地静态段（本机可执行，无需 Go 1.26）
#   bash scripts/verify_all.sh -remote    # 🖥 真机段（本轮不执行；须在真机 + go.work workspace 内）
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

MAIN_REPO="${MAIN_REPO:-$REPO_ROOT/../security-ai-gateway}"
GOFMT="${GOFMT:-gofmt}"
TMP_DIR="$(mktemp -d)"
# Git Bash 的 mktemp 可能返回 C:\... 形式；转成 POSIX 路径才能作为 PATH 条目注入假 go。
if command -v cygpath >/dev/null 2>&1; then
  TMP_DIR="$(cygpath -u "$TMP_DIR")"
fi
trap 'rm -rf "$TMP_DIR"' EXIT

pass() { printf '  [PASS] %s\n' "$1"; }
skip() { printf '  [SKIP] %s\n' "$1"; }
die() {
  printf '  [FAIL] %s\n' "$1" >&2
  exit 1
}

field() {
  grep -m1 "\"$1\"" "$2" 2>/dev/null | sed -E 's/[^0-9]*([0-9]+).*/\1/' || true
}

# ---------------------------------------------------------------------------
# 本地静态段：不依赖 Go 1.26、不联网、不写被扫描仓库
# ---------------------------------------------------------------------------
run_static() {
  echo "== 本地静态段 =="

  # (a) gofmt -l 零输出
  mapfile -t go_files < <(find . -name '*.go' -not -path './.git/*' -type f | sort)
  if [ "${#go_files[@]}" -eq 0 ]; then
    die "未找到 .go 文件"
  fi
  fmt_out="$("$GOFMT" -l "${go_files[@]}")"
  if [ -n "$fmt_out" ]; then
    die "gofmt -l 非零输出: $fmt_out"
  fi
  pass "gofmt -l 零输出（${#go_files[@]} 个 .go 文件）"

  # (b) 三个 scripts/*.go 首行为 //go:build ignore
  for f in scripts/gen_stream_golden.go scripts/verify_golden_against_main.go scripts/check_import_closure.go; do
    [ -f "$f" ] || die "缺少 $f"
    first="$(head -n 1 "$f")"
    [ "$first" = "//go:build ignore" ] || die "$f 首行不是 //go:build ignore: $first"
  done
  pass "3 个 scripts/*.go 均带 //go:build ignore"

  # (c) go.mod 零 require / 零 replace / 版本与 module 路径
  [ "$(head -n 1 go.mod)" = "module github.com/FengYang/masked-infer" ] || die "go.mod module 行不符"
  grep -q '^go 1\.26\.0$' go.mod || die "go.mod 版本不是 1.26.0"
  if grep -qE '^(require|replace)' go.mod; then
    die "go.mod 含 require / replace 块"
  fi
  pass "go.mod 无 require / replace，module 与 go 版本正确"

  # (d) G1 脚本逻辑自检：用临时目录里的假 go 注入 deps.txt，不改动门禁脚本本身
  fake_bin="$TMP_DIR/fakebin"
  mkdir -p "$fake_bin"
  cat > "$fake_bin/go" <<'FAKEGO'
#!/usr/bin/env bash
cat "${G1_FAKE_DEPS:?G1_FAKE_DEPS unset}"
exit "${G1_FAKE_EXIT:-0}"
FAKEGO
  chmod +x "$fake_bin/go"
  printf '%s\n' 'security-ai-gateway/gateway/cryptop' 'fmt' > "$TMP_DIR/deps_fail.txt"
  printf '%s\n' 'github.com/FengYang/masked-infer/core' 'crypto/hmac' > "$TMP_DIR/deps_pass.txt"
  : > "$TMP_DIR/deps_empty.txt"

  rc=0
  G1_FAKE_DEPS="$TMP_DIR/deps_fail.txt" G1_FAKE_EXIT=0 PATH="$fake_bin:$PATH" GOWORK=off \
    bash scripts/gate_g1.sh > "$TMP_DIR/g1_a.txt" 2>&1 || rc=$?
  if [ "$rc" -ne 1 ] || ! grep -q 'G1 FAIL' "$TMP_DIR/g1_a.txt"; then
    die "G1 场景 A（含主仓裸名）未判 FAIL / exit 1；rc=$rc out=$(cat "$TMP_DIR/g1_a.txt")"
  fi
  pass "G1 场景 A：security-ai-gateway/gateway/cryptop → exit 1 + G1 FAIL"

  rc=0
  G1_FAKE_DEPS="$TMP_DIR/deps_pass.txt" G1_FAKE_EXIT=0 PATH="$fake_bin:$PATH" GOWORK=off \
    bash scripts/gate_g1.sh > "$TMP_DIR/g1_b.txt" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ] || ! grep -q 'G1 PASS' "$TMP_DIR/g1_b.txt"; then
    die "G1 场景 B（仅新库包）未判 PASS；rc=$rc out=$(cat "$TMP_DIR/g1_b.txt")"
  fi
  pass "G1 场景 B：github.com/FengYang/masked-infer/core → exit 0 + G1 PASS"

  rc=0
  G1_FAKE_DEPS="$TMP_DIR/deps_empty.txt" G1_FAKE_EXIT=42 PATH="$fake_bin:$PATH" GOWORK=off \
    bash scripts/gate_g1.sh > "$TMP_DIR/g1_c.txt" 2>&1 || rc=$?
  if [ "$rc" -eq 0 ] || grep -q 'G1 PASS' "$TMP_DIR/g1_c.txt"; then
    die "G1 场景 C（go list 失败）被吞掉而静默判绿；rc=$rc out=$(cat "$TMP_DIR/g1_c.txt")"
  fi
  pass "G1 场景 C：假 go list 退出 42 → 门禁同码失败，set -e 未被吞掉（未输出 G1 PASS）"

  # (e) check_import_closure.go 基线复核（纯标准库，go1.20 可跑）
  if [ -d "$MAIN_REPO" ] && [ -f scripts/closure-baseline.json ]; then
    GO111MODULE=off go run scripts/check_import_closure.go \
      -root "$MAIN_REPO" -mode baseline -out "$TMP_DIR/closure-recheck.json" \
      > "$TMP_DIR/closure-recheck.log" 2>&1 || die "基线复核失败: $(cat "$TMP_DIR/closure-recheck.log")"
    for key in total_go_files total_test_go_files total_import_lines total_group_hits; do
      a="$(field "$key" scripts/closure-baseline.json)"
      b="$(field "$key" "$TMP_DIR/closure-recheck.json")"
      [ -n "$a" ] && [ "$a" = "$b" ] || die "基线复核 $key 不一致: baseline=$a recheck=$b"
    done
    pass "import 闭包基线复核一致（go_files=$(field total_go_files scripts/closure-baseline.json), import_lines=$(field total_import_lines scripts/closure-baseline.json)）"
  else
    skip "主仓或基线报告不存在，跳过闭包复核（CI GOWORK=off 场景）"
  fi

  # (f) 国密红线：新库零 SM2/SM3/SM4 自实现
  if grep -rE --exclude-dir=.git 'func sm[234]' . > "$TMP_DIR/sm_hits.txt"; then
    die "国密红线命中: $(cat "$TMP_DIR/sm_hits.txt")"
  fi
  pass "国密红线 grep -rE 'func sm[234]' 零命中"

  # (g) 白名单：除 verify_golden_against_main.go 外，.go 文件零主仓/gmsm 字面量
  cross="$(grep -rnE --include='*.go' --exclude-dir=.git 'security-ai-gateway|emmansun/gmsm' . \
    | grep -v 'scripts/verify_golden_against_main.go' || true)"
  if [ -n "$cross" ]; then
    die "白名单外 .go 文件命中主仓/gmsm 字面量: $cross"
  fi
  pass "白名单外 .go 文件零 'security-ai-gateway' / 'emmansun/gmsm' 命中（真机复核脚本白名单已在报告说明）"

  # (h) golden 头部与用例完整性
  golden=masklite/testdata/stream.golden
  [ -f "$golden" ] || die "缺少 $golden"
  grep -q '^# schema: masked-infer/g2-stream-golden/v1$' "$golden" || die "golden 缺 schema 行"
  grep -q '^# gen_cmd: ' "$golden" || die "golden 缺 gen_cmd 行"
  grep -qE '^# main_commit: [0-9a-f]{40}$' "$golden" || die "golden 缺 40hex main_commit"
  grep -qE '^# cases: base \| domain_sep \| large_modulus$' "$golden" || die "golden 缺 cases 行"
  case_count="$(grep -c '^case=' "$golden")"
  [ "$case_count" -eq 3 ] || die "golden case 段数 $case_count != 3"
  pass "stream.golden 头部齐全，3 类用例完整"

  # (i) 主仓禁碰路径与生产代码零改动
  if [ -d "$MAIN_REPO/.git" ]; then
    main_status="$(git -C "$MAIN_REPO" status --porcelain)"
    extra="$(printf '%s\n' "$main_status" | grep -vE '^\?\? go\.work/?$' | grep -v '^$' || true)"
    [ -z "$extra" ] || die "主仓除未跟踪 go.work 外存在改动: $extra"
    forbidden="$(printf '%s\n' "$main_status" | grep -E 'docs/P1-8-|gateway/wasm/otpmask-plugin|gateway/attest-verify|deploy/higress|\.patch' || true)"
    [ -z "$forbidden" ] || die "禁碰路径出现在主仓 status: $forbidden"
    pass "主仓 git status 仅含未跟踪 go.work；P1-8 禁碰路径零命中"
  else
    skip "主仓 git 目录不存在，跳过主仓 status 检查"
  fi

  # (j) 新库无 remote / 无 tag
  if [ -d .git ]; then
    [ -z "$(git remote -v)" ] || die "新库存在 remote: $(git remote -v)"
    [ -z "$(git tag -l)" ] || die "新库存在 tag: $(git tag -l)"
    pass "新库 git remote -v 为空、无 tag"
  else
    skip "新库尚未 git init，跳过 remote/tag 检查"
  fi

  echo "本地静态段 PASS"
}

# ---------------------------------------------------------------------------
# 🖥 真机段：本轮不执行（192.168.31.248 SSH 不可用 / 本机 go1.20.3）
#   - 新库侧全部 GOWORK=off；主仓侧必须在 go.work workspace 内，**勿加 GOWORK=off**
#   - 门控 1–5 只有在本段实际跑通后才可判 PASS
# ---------------------------------------------------------------------------
run_remote() {
  echo "== 🖥 真机段（Go 1.26 / 192.168.31.248）=="
  export PATH=/usr/local/go/bin:$PATH
  go version

  # 新库：G1 / 全量测试 / cgo 双构建
  GOWORK=off bash scripts/gate_g1.sh
  GOWORK=off go test ./... -count=1
  GOWORK=off CGO_ENABLED=0 go build ./...
  GOWORK=off CGO_ENABLED=1 go build ./...

  # 新库：CUDA / 昇腾双一等公民构建（🖥 GPU 轨道，待环境就绪）
  GOWORK=off ACCEL_BACKEND_LIB=cuda CGO_ENABLED=1 go build ./...
  GOWORK=off ACCEL_BACKEND_LIB=ascend CGO_ENABLED=1 go build ./...

  # 主仓：在 go.work workspace 内跑全量回归（勿加 GOWORK=off）
  (
    cd "$MAIN_REPO"
    unset GOWORK
    go build ./...
    go vet ./...
    go test ./... -count=1

    # 门控 1：prg_test.go T-5.3-8 intl/SMSW 逐字节等价 + 密钥长度 fail-closed
    go test ./cipher/mask/... -run 'T-5.3-8|TestHMACPRG' -count=1

    # 门控 2：TestFormAEquivalence（MaxAbsDiff ≤ 5e-3、top-1 一致）
    go test ./gateway/teecore/adapters/qwen/... -run 'TestFormAEquivalence' -count=1

    # 门控 3：TestRoute2StepRealQwenGolden（282 步 top-1=23811 / maxRelErr=0.0390）
    go test ./... -run 'TestRoute2StepRealQwenGolden' -count=1

    # 门控 4：主仓全量 build/vet/test + SBOM gate 不回归（已在上方执行），
    #         发布前另按 SBOM/README.md 重生成并复核。

    # 门控 5：G2 golden 与主仓生成脚本输出一致
    go run ../masked-infer/scripts/verify_golden_against_main.go \
      -golden ../masked-infer/masklite/testdata/stream.golden
  )
  echo "🖥 真机段完成：门控 1–5 已实际取证"
}

if [ "${1:-}" = "-remote" ]; then
  run_remote
  exit 0
fi

run_static
echo ""
echo "🖥 真机段未执行（SSH 192.168.31.248 不可用 / 本机 go1.20.3）："
echo "   空模块 go build、G1 真机判绿、go test ./...、cgo/!cgo 双构建、"
echo "   CUDA/昇腾双构建、门控 1–5 均标「🖥 待环境就绪（未取证）」。"
echo "   环境恢复后运行：bash scripts/verify_all.sh -remote"
