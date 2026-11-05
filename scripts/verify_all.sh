#!/usr/bin/env bash
# verify_all.sh —— §5 阶段 0 一键复验（本地静态段 + 🖥 真机段）。
#
# ⚠ 真机 192.168.31.248 SSH 当前不可用，真机段未取证；
#   **禁止把静态段 [STATIC-PASS] 冒充门控 1–5 PASS**。
#   本机仅 go1.20.3，无法编译 go 1.26.0 模块；编译/真机类验收一律标
#   「🖥 待环境就绪（未取证）」。
#   -remote 仅阶段 1+ 且 Go 1.26 真机 / go.work workspace 就绪后使用
#   （阶段 0 空模块无包可测，不满足该段前置条件）。
#
# 用法：
#   bash scripts/verify_all.sh             # 本地静态段（本机可执行，无需 Go 1.26；闭包默认弱校验）
#   bash scripts/verify_all.sh -baseline   # 静态段 + 闭包 4 项计数强比对（阶段 3/4 import 改写前复核）
#   bash scripts/verify_all.sh -remote     # 🖥 真机段（仅阶段 1+；本轮不执行）
#   亦可用环境变量 VERIFY_BASELINE=1 触发 -baseline 语义。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

MAIN_REPO="${MAIN_REPO:-$REPO_ROOT/../security-ai-gateway}"
# SUB_REPO 直接复用 REPO_ROOT：脚本位于 scripts/ 下，REPO_ROOT 即新库根 F:/方案/masked-infer。
# （$MAIN_REPO/../masked-infer 亦可绕回同一路径，但直接复用最不易错；不新增全局配置。）
SUB_REPO="${SUB_REPO:-$REPO_ROOT}"
GOFMT="${GOFMT:-gofmt}"
BASELINE_MODE=0
if [ "${1:-}" = "-baseline" ] || [ "${VERIFY_BASELINE:-0}" = "1" ]; then
  BASELINE_MODE=1
fi
TMP_DIR="$(mktemp -d)"
# Git Bash 的 mktemp 可能返回 C:\... 形式；转成 POSIX 路径才能作为 PATH 条目注入假 go。
if command -v cygpath >/dev/null 2>&1; then
  TMP_DIR="$(cygpath -u "$TMP_DIR")"
fi
trap 'rm -rf "$TMP_DIR"' EXIT

# 静态段统一加 [STATIC-PASS] 前缀，避免与真机门控判绿混淆（B4）。
pass() { printf '  [STATIC-PASS] %s\n' "$1"; }
skip() { printf '  [SKIP] %s\n' "$1"; }
info() { printf '  [INFO] %s\n' "$1"; }
warn() { printf '  [WARN] %s\n' "$1"; }
die() {
  printf '  [FAIL] %s\n' "$1" >&2
  exit 1
}

field() {
  grep -m1 "\"$1\"" "$2" 2>/dev/null | sed -E 's/[^0-9]*([0-9]+).*/\1/' || true
}

# assert_run <log> <label> [必须实跑的测试函数名...]
# 防 `go test -run` 无匹配却 exit 0 的恒假 PASS；「有 === RUN」才证明测试真跑过。
# 若输出含 --- SKIP，只告警不改判：SKIP 按 §5.1 仍属「未取证」，不得据此宣称 PASS。
assert_run() {
  local log="$1" label="$2"
  shift 2
  local expected="$#" run_count name
  grep -q '^=== RUN' "$log" \
    || die "${label} 无测试实跑（禁止假 PASS：检查 -run 是否匹配到真实测试名）"
  # 覆盖度：实跑条数不得少于 -run 目标数，再逐个名字断言，防「只跑了一个也算过」。
  run_count="$(grep -c '^=== RUN' "$log" || true)"
  [ "$run_count" -ge "$expected" ] \
    || die "${label} === RUN 实跑条数 ${run_count} < 目标数 ${expected}（禁止假 PASS）"
  for name in "$@"; do
    grep -qE "^=== RUN[[:space:]]+${name}$" "$log" \
      || die "${label} 缺少实跑测试 ${name}（禁止假 PASS）"
  done
  if grep -q '^--- SKIP' "$log"; then
    warn "${label} 存在 SKIP 用例：按 §5.1 判未取证，不得据此宣称 PASS"
  fi
}

# ---------------------------------------------------------------------------
# 本地静态段：不依赖 Go 1.26、不联网、不写被扫描仓库
# ---------------------------------------------------------------------------
run_static() {
  echo "== 本地静态段（[STATIC-PASS] 均为本地项，非真机门控结论） =="

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
  pass "G1 场景 A：含主仓裸名 → exit 1 + G1 FAIL"

  rc=0
  G1_FAKE_DEPS="$TMP_DIR/deps_pass.txt" G1_FAKE_EXIT=0 PATH="$fake_bin:$PATH" GOWORK=off \
    bash scripts/gate_g1.sh > "$TMP_DIR/g1_b.txt" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ] || ! grep -q 'G1 PASS' "$TMP_DIR/g1_b.txt"; then
    die "G1 场景 B（仅新库包）未判 PASS；rc=$rc out=$(cat "$TMP_DIR/g1_b.txt")"
  fi
  pass "G1 场景 B：仅新库包 → exit 0 + 门禁判绿字样（静态注入样本，非真机闭包判绿）"

  rc=0
  G1_FAKE_DEPS="$TMP_DIR/deps_empty.txt" G1_FAKE_EXIT=42 PATH="$fake_bin:$PATH" GOWORK=off \
    bash scripts/gate_g1.sh > "$TMP_DIR/g1_c.txt" 2>&1 || rc=$?
  if [ "$rc" -eq 0 ] || grep -q 'G1 PASS' "$TMP_DIR/g1_c.txt"; then
    die "G1 场景 C（go list 失败）被吞掉而静默判绿；rc=$rc out=$(cat "$TMP_DIR/g1_c.txt")"
  fi
  pass "G1 场景 C：假 go list 退出 42 → 门禁同码失败，set -e 未被吞掉（未输出判绿字样）"

  # 场景 D：0 deps 且 go list 成功 → 必须输出「空集判绿」文案，且仍以 G1 PASS 开头。
  rc=0
  G1_FAKE_DEPS="$TMP_DIR/deps_empty.txt" G1_FAKE_EXIT=0 PATH="$fake_bin:$PATH" GOWORK=off \
    bash scripts/gate_g1.sh > "$TMP_DIR/g1_d.txt" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ] || ! grep -q '^G1 PASS (empty module / 0 deps)' "$TMP_DIR/g1_d.txt"; then
    die "G1 场景 D（空模块）未输出空集判绿文案；rc=$rc out=$(cat "$TMP_DIR/g1_d.txt")"
  fi
  pass "G1 场景 D：0 deps → 空集判绿文案，实质闭包留待阶段 1 复验"

  # (e) check_import_closure.go 基线复核（纯标准库，go1.20 可跑）
  #   默认弱校验：只断言三项真门禁为空（parse_failures / forbidden_path_hits /
  #   new_repo_cross_hits）；4 项计数仅 INFO 打印、不判红。阶段 1+ 迁包、阶段 3/4
  #   删包改 import 后计数必然漂移，强比对会误报失败，违背「不破坏已有功能」。
  #   阶段 3/4 import 改写前须用 -baseline 复核；基线确认漂移时用工具显式重生成
  #   scripts/closure-baseline.json 并提交，两侧同批评审。
  if [ -d "$MAIN_REPO" ]; then
    # WARN-10：先 go build 到临时可执行文件再执行，去掉对 `go run` 临时目录执行权限的依赖。
    GO111MODULE=off go build -o "$TMP_DIR/cic" scripts/check_import_closure.go \
      || die "check_import_closure.go 构建失败"
    "$TMP_DIR/cic" \
      -root "$MAIN_REPO" -mode baseline -out "$TMP_DIR/closure-recheck.json" \
      > "$TMP_DIR/closure-recheck.log" 2>&1 || die "闭包扫描失败: $(cat "$TMP_DIR/closure-recheck.log")"
    for key in parse_failures forbidden_path_hits new_repo_cross_hits; do
      grep -q "\"${key}\": \[\]" "$TMP_DIR/closure-recheck.json" \
        || die "闭包真门禁 ${key} 非空（详见 $TMP_DIR/closure-recheck.json）"
    done
    info "闭包计数（仅 INFO，不判红）：go_files=$(field total_go_files "$TMP_DIR/closure-recheck.json") test_files=$(field total_test_go_files "$TMP_DIR/closure-recheck.json") import_lines=$(field total_import_lines "$TMP_DIR/closure-recheck.json") group_hits=$(field total_group_hits "$TMP_DIR/closure-recheck.json")"
    if [ "$BASELINE_MODE" -eq 1 ]; then
      [ -f scripts/closure-baseline.json ] || die "-baseline 模式缺少 scripts/closure-baseline.json"
      for key in total_go_files total_test_go_files total_import_lines total_group_hits; do
        a="$(field "$key" scripts/closure-baseline.json)"
        b="$(field "$key" "$TMP_DIR/closure-recheck.json")"
        [ -n "$a" ] && [ "$a" = "$b" ] || die "-baseline 强比对 $key 不一致: baseline=$a recheck=$b"
      done
      pass "闭包基线 4 项计数强比对通过（-baseline 模式）"
    else
      pass "import 闭包三项真门禁零命中（parse_failures / forbidden_path_hits / new_repo_cross_hits）"
    fi
  else
    skip "主仓目录不存在，跳过闭包复核（CI GOWORK=off 场景）"
  fi

  # (f) 国密红线：新库零 SM2/SM3/SM4 自实现
  if grep -rE --exclude-dir=.git 'func sm[234]' . > "$TMP_DIR/sm_hits.txt"; then
    die "国密红线命中: $(cat "$TMP_DIR/sm_hits.txt")"
  fi
  pass "国密红线 grep -rE 'func sm[234]' 零命中"

  # (f2) 许可文件自洽：LICENSE 无主仓附录 / 第三方清单悬空引用。
  # 关键字用字符串拼接构造，避免本校验脚本自身成为「全库 grep 零命中」的自命中源。
  p_sub="Sub""components"
  p_tpn="THIRD-PARTY-""NOTICES"
  p_gm="emmansun/""gmsm"
  p_main="security-ai-""gateway"
  p_appendix="许可证""附录"
  if grep -nE "${p_sub}|${p_tpn}|${p_gm}|${p_main}" LICENSE; then
    die "LICENSE 仍含主仓附录或第三方清单引用"
  fi
  grep -q 'limitations under the License.' LICENSE || die "LICENSE 缺 Apache-2.0 正文尾句"
  cross_notice="$(grep -rnE "${p_sub}|${p_tpn}|${p_appendix}" --exclude-dir=.git . || true)"
  [ -z "$cross_notice" ] || die "全库仍有附录悬空引用: $cross_notice"
  pass "LICENSE 为纯 Apache-2.0 全文，全库无 ${p_sub} / ${p_tpn} / ${p_appendix} 悬空引用"

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

  # (k) === RUN 守卫 fail-closed 自检：构造「-run 无匹配」样本
  printf '%s\n' 'go: warning: "./..." matched no packages' 'ok  (cached)' > "$TMP_DIR/no_run.log"
  rc=0
  ( assert_run "$TMP_DIR/no_run.log" "GUARD-SELFTEST" ) >/dev/null 2>&1 || rc=$?
  [ "$rc" -ne 0 ] || die "=== RUN 守卫在无 RUN 样本上未 fail-closed"
  printf '%s\n' '=== RUN   TestGolden' '--- PASS: TestGolden (0.00s)' 'PASS' > "$TMP_DIR/has_run.log"
  rc=0
  ( assert_run "$TMP_DIR/has_run.log" "GUARD-SELFTEST" TestGolden ) >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 0 ] || die "=== RUN 守卫在有 RUN 样本上误判"
  pass "=== RUN 守卫 fail-closed 自检（无 RUN 样本必失败 / 有 RUN 样本通过）"

  # (k2) 双向验证：用**真实 go test -v** 哑测试（仅存于临时目录，trap 清理、不进仓库）
  #   样本 A（-run 指向不存在的名字）→ 守卫必须判红，堵住假绿；
  #   样本 B（-run 指向真实存在的名字）→ 守卫不得误判红，且 -v 输出确实含 === RUN。
  #   形态固定为 `go test -v 2>&1 | tee <file>` 后**对文件 grep**：绝不把 grep -q 直接
  #   接在管道末端（命中即关读端 → 上游 SIGPIPE(141) → pipefail 下「有匹配反被判红」）。
  guard_pkg="$TMP_DIR/guard_pkg"
  mkdir -p "$guard_pkg"
  cat > "$guard_pkg/dummy_test.go" <<'DUMMYGO'
package dummy

import "testing"

func TestGuardReal(t *testing.T) {
	t.Log("guard positive sample")
}
DUMMYGO
  # tee 仍落盘，但把它的 stdout 收进 /dev/null，避免哑测试的裸 PASS 字样混入静态段输出。
  ( cd "$guard_pkg" && GO111MODULE=off go test -run '^TestGuardReal$' -count=1 -v 2>&1 \
      | tee "$TMP_DIR/guard_pos.log" ) >/dev/null \
    || die "正向哑测试 go test 执行失败: $(tail -n 3 "$TMP_DIR/guard_pos.log")"
  grep -qE '^=== RUN[[:space:]]+TestGuardReal$' "$TMP_DIR/guard_pos.log" \
    || die "-v 未产生 === RUN（守卫链漏 -v）"
  pos_run_count="$(grep -c '^=== RUN' "$TMP_DIR/guard_pos.log" || true)"
  rc=0
  ( assert_run "$TMP_DIR/guard_pos.log" "GUARD-POS" TestGuardReal ) >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 0 ] || die "有匹配样本被守卫误判红（疑似 grep -q 直连管道导致 SIGPIPE 假红）"
  ( cd "$guard_pkg" && GO111MODULE=off go test -run '^TestNoSuchName$' -count=1 -v 2>&1 \
      | tee "$TMP_DIR/guard_neg.log" ) >/dev/null \
    || die "无匹配哑测试 go test 执行失败: $(tail -n 3 "$TMP_DIR/guard_neg.log")"
  neg_run_count="$(grep -c '^=== RUN' "$TMP_DIR/guard_neg.log" || true)"
  rc=0
  ( assert_run "$TMP_DIR/guard_neg.log" "GUARD-NEG" TestNoSuchName ) >/dev/null 2>&1 || rc=$?
  [ "$rc" -ne 0 ] || die "-run 无匹配样本未被守卫判红（假绿通道未堵住）"
  pass "=== RUN 守卫双向验证（真实 go test -v：有匹配 ${pos_run_count} 条 RUN 不误判红 / 无匹配 ${neg_run_count} 条 RUN 必判红；tee 落文件后 grep，无 SIGPIPE 假红）"

  # (l) 仓库可 clone 留证（只读，临时目录，不污染仓库）
  if [ -d .git ]; then
    [ "$(git rev-parse --is-inside-work-tree)" = "true" ] || die "非 git 工作树"
    git fsck --no-progress --no-dangling > "$TMP_DIR/fsck.log" 2>&1 \
      || die "git fsck 失败: $(cat "$TMP_DIR/fsck.log")"
    git clone --no-hardlinks -q . "$TMP_DIR/clone-check" || die "git clone 留证失败"
    [ "$(git rev-parse HEAD)" = "$(git -C "$TMP_DIR/clone-check" rev-parse HEAD)" ] \
      || die "clone 后 HEAD 不一致"
    [ "$(git ls-files | wc -l)" -eq "$(git -C "$TMP_DIR/clone-check" ls-files | wc -l)" ] \
      || die "clone 后跟踪文件数不一致"
    pass "仓库可 clone 留证（fsck 通过；clone 后 HEAD=$(git rev-parse --short HEAD)、跟踪文件数一致）"
  else
    skip "新库尚未 git init，跳过 clone 留证"
  fi

  echo "[STATIC-PASS] 本地静态段完成（仅本地静态项，不含任何门控 1–5 结论）"
}

# ---------------------------------------------------------------------------
# 🖥 真机段：本轮不执行（192.168.31.248 SSH 不可用 / 本机 go1.20.3；仅阶段 1+）
#   - 新库侧全部 GOWORK=off；主仓侧必须在 go.work workspace 内，**勿加 GOWORK=off**
#   - 门控 1–5 只有在本段实际跑通后才可判 PASS；本段是阶段 1/3/4 共用的门控入口
#   - 所有 go test -run 必须「-v + 2>&1 | tee <file>」，再对**文件**做 === RUN 守卫：
#     * 漏 -v ⇒ 无 === RUN 输出 ⇒ 正常通过被误判红；
#     * grep -q 直连管道 ⇒ 命中即关读端 ⇒ SIGPIPE(141) + pipefail ⇒ 有匹配反被误判红；
#     * 两者都避开后，才能防「-run 无匹配却 exit 0」的恒假 PASS。
#   - assert_run 同时断言实跑条数 >= -run 目标数并逐名核对，防「只跑一个也算过」
# ---------------------------------------------------------------------------
run_remote() {
  echo "== 🖥 真机段（Go 1.26 / 192.168.31.248；仅阶段 1+）=="
  export PATH=/usr/local/go/bin:$PATH
  go version

  # 新库：G1 / cgo 双构建 / 全量测试
  # 阶段 0 空模块 `go test ./...` 会 no packages to test 退出 1，故先 build，
  # 再用 go list 判定是否有包；go list 自身失败必须 die，不能被守卫吞掉。
  GOWORK=off bash scripts/gate_g1.sh
  GOWORK=off CGO_ENABLED=0 go build ./...
  GOWORK=off CGO_ENABLED=1 go build ./...
  rc=0
  pkg_list="$(GOWORK=off go list ./... 2>"$TMP_DIR/golist.err")" || rc=$?
  [ "$rc" -eq 0 ] || die "新库 go list ./... 失败: $(cat "$TMP_DIR/golist.err")"
  if [ -n "$pkg_list" ]; then
    GOWORK=off go test ./... -count=1
  else
    echo "SKIP: 阶段 0 空模块无包可测；阶段 1+ 起执行 go test ./..."
  fi

  # 新库：CUDA / 昇腾双一等公民构建（🖥 GPU 轨道，环境恢复后显式启用并取证）
  GOWORK=off ACCEL_BACKEND_LIB=cuda CGO_ENABLED=1 go build ./...
  GOWORK=off ACCEL_BACKEND_LIB=ascend CGO_ENABLED=1 go build ./...

  # 门控 3（新库侧）：阶段 3 起 golden 测试随 step/ 迁入新库、CA-3 改造对象也在新库，
  # 必须验新库侧；用目录存在性守卫避免阶段 0/1/2 报错。
  if [ -d "$SUB_REPO/adapters/qwen" ]; then
    (
      cd "$SUB_REPO"
      GOWORK=off go test ./adapters/qwen/... -run TestRoute2StepRealQwenGolden \
        -count=1 -v 2>&1 | tee "$TMP_DIR/gate3_sub.log"
    )
    assert_run "$TMP_DIR/gate3_sub.log" "门控3(新库侧)" TestRoute2StepRealQwenGolden
  else
    echo "SKIP: 门控3 新库侧（adapters/qwen 尚未迁入，阶段 3 起生效）"
  fi

  # 主仓：在 go.work workspace 内跑全量回归（勿加 GOWORK=off）
  (
    cd "$MAIN_REPO"
    unset GOWORK
    go build ./...
    go vet ./...
    go test ./... -count=1

    # 门控 1：T-5.3-8 是注释编号、不是函数名。以下 6 个名字由
    #   grep -nE '^func Test' cipher/mask/prg_test.go 实测得到（:41/:58/:91/:111/:134/:159）；
    #   含 intl 逐字节等价两半、SM4 确定性/不可互操作、密钥长度 fail-closed。
    go test ./cipher/mask/... \
      -run 'TestHMACPRGMatchesLegacy|TestHMACPRGEqualsIntlProviderKeystream|TestIntlStreamWithProviderEqualsStreamDomain|TestSM4StreamDeterministic|TestSM4VsHMACNotInteroperable|TestNewStreamWithProviderKeySize' \
      -count=1 -v 2>&1 | tee "$TMP_DIR/gate1.log"
    assert_run "$TMP_DIR/gate1.log" "门控1" \
      TestHMACPRGMatchesLegacy TestHMACPRGEqualsIntlProviderKeystream \
      TestIntlStreamWithProviderEqualsStreamDomain TestSM4StreamDeterministic \
      TestSM4VsHMACNotInteroperable TestNewStreamWithProviderKeySize

    # 门控 2：TestFormAEquivalence / TestFormAKVConsistency 实测位于
    #   gateway/route2/orchestrator/form_a_test.go:25/:82（adapters/qwen 下无此测试）。
    #   MaxAbsDiff ≤ 5e-3、top-1 一致。
    go test ./gateway/route2/orchestrator/... \
      -run 'TestFormAEquivalence|TestFormAKVConsistency' -count=1 -v 2>&1 | tee "$TMP_DIR/gate2.log"
    assert_run "$TMP_DIR/gate2.log" "门控2" TestFormAEquivalence TestFormAKVConsistency

    # 门控 3（主仓侧）：基线形式；阶段 4 删主仓包后移除本行。
    #   282 步 top-1=23811 / maxRelErr=0.0390；新库侧命令见上方（阶段 3 起生效）。
    go test ./... -run 'TestRoute2StepRealQwenGolden' -count=1 -v 2>&1 | tee "$TMP_DIR/gate3_main.log"
    assert_run "$TMP_DIR/gate3_main.log" "门控3(主仓侧)" TestRoute2StepRealQwenGolden

    # 门控 4：主仓全量 build/vet/test + SBOM gate 不回归（已在上方执行），
    #         发布前另按 SBOM/README.md 重生成并复核。

    # 门控 5：G2 golden 与主仓 NewStreamDomain 逐字节一致（去硬编码，用 $SUB_REPO）
    go run "$SUB_REPO/scripts/verify_golden_against_main.go" \
      -golden "$SUB_REPO/masklite/testdata/stream.golden"
  )
  echo "[REMOTE-PASS] 真机段完成：门控 1–5 已实际取证"
}

case "${1:-}" in
  -remote)
    run_remote
    exit 0
    ;;
  -baseline|"")
    run_static
    ;;
  *)
    echo "用法: bash scripts/verify_all.sh [-baseline|-remote]" >&2
    exit 2
    ;;
esac

echo ""
echo "🖥 真机段未执行（SSH 192.168.31.248 不可用 / 本机 go1.20.3）："
echo "   空模块 go build、G1 真机判绿、go test ./...、cgo/!cgo 双构建、"
echo "   CUDA/昇腾双构建、门控 1–5 均标「🖥 待环境就绪（未取证）」。"
echo "   环境恢复后（仅阶段 1+）运行：bash scripts/verify_all.sh -remote"
