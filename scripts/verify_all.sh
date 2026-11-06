#!/usr/bin/env bash
# verify_all.sh —— 阶段 0 一键复验（本地静态段 + 🖥 真机段）。
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
# REMOTE_SKIPS：真机段门控累计的 SKIP 用例数（SKIP 按「未取证」，不得据此宣称 PASS）。
# 门控一律用 assert_run_strict（发现 SKIP 立即 die）；段末再独立复扫全部 gate*.log 兜底，
# 只要 >0 就禁止输出 [REMOTE-PASS]（防某个门控漏改 strict 仍在段末宣称全取证）。
REMOTE_SKIPS=0
TMP_DIR="$(mktemp -d)"
# Git Bash 的 mktemp 可能返回 C:\... 形式；转成 POSIX 路径才能作为 PATH 条目注入假 go。
if command -v cygpath >/dev/null 2>&1; then
  TMP_DIR="$(cygpath -u "$TMP_DIR")"
fi

# BUILD_DIR：Go **编译产物**（cic 可执行文件、go test 的临时测试二进制）的落地目录。
#
# 两条硬约束（都是本机实测撞出来的，不是预防性设计）：
#  1) 不能放系统 Temp：360 杀毒按启发式拦截 Temp 下新生成的 exe，报
#     Win64/Heur.Generic.H8oAN9EA，表现为执行时 `Permission denied`(rc=126) 或被删除
#     ⇒ 静态段非确定（同一份代码随机失败在 (e)/(e2)/(k2)/(k3)/(k4)）。
#  2) **不能放仓库内**：仓库级检查用 find 枚举 .go；GOTMPDIR 会让 Go 把自动生成的
#     `_testmain.go` 写进去，一次异常中断（进程组被 SIGKILL，trap 不保证执行）就残留，
#     下一次运行立刻红在 `gofmt -l: ./.verify-tmp/gotmp/.../_testmain.go` 上（实测）。
#     所以「trap 清理」不能作为唯一保证，必须从**位置**上隔离。
# 默认落在仓库的**同级目录**（与仓库同盘但不在工作树内），可用 MASKED_INFER_BUILD_DIR 覆写
# （CI / 只读挂载时改道）。日志（.log/.json）仍留在 TMP_DIR：纯文本不触发启发式。
BUILD_DIR="${MASKED_INFER_BUILD_DIR:-$(cd "$REPO_ROOT/.." && pwd)/.masked-infer-verify}"
# 相对路径先绝对化，否则下面的「是否落在仓库内」前缀守卫会漏判。
case "$BUILD_DIR" in
  /* | [A-Za-z]:[/\\]*) : ;;
  *) BUILD_DIR="$PWD/$BUILD_DIR" ;;
esac
# 守卫：真的落在仓库内就退回 TMP_DIR/build（宁可回到会被杀软拦的 Temp，也不能毒化仓库扫描）
case "$BUILD_DIR" in
  "$REPO_ROOT" | "$REPO_ROOT"/*) BUILD_DIR="$TMP_DIR/build" ;;
esac
mkdir -p "$BUILD_DIR"

_vcleanup() { rm -rf "$TMP_DIR" "$BUILD_DIR"; }
trap '_vcleanup' EXIT
# INT/TERM 必须显式 exit：trap 处理函数只删目录然后返回的话，脚本会继续往下执行。
trap '_vcleanup; exit 130' INT TERM

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
#
# 四条判据都只看**日志内容**，不看管道 rc —— 因为 `go test ... | tee` 的 rc 语义依赖
# pipefail：本脚本 `set -euo pipefail` 时 rc 能穿透（实测失败用例 rc=1），但只要有人
# 在某个子 shell 里 `set +o pipefail`、或把这段片段抄到别处，rc 就变成 tee 的 0（实测
# 同一失败用例 rc=0）。所以「有没有失败」必须自己从输出里读，不能指望 rc。
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
  # 硬判 --- FAIL（防御纵深）。缩进容忍是必须的：子测试失败输出为
  # `    --- FAIL: TestX/sub`（4 空格），只认行首会漏。
  # 一律 `grep -qE <pat> <file>` 直接读文件，绝不写成 `cmd | grep -q`
  # （命中即关读端 → 上游 SIGPIPE(141) → pipefail 下把正常通过误判红）。
  if grep -qE '^[[:space:]]*--- FAIL' "$log"; then
    die "${label} 输出含 --- FAIL（go test 失败但管道 rc 可能被 tee 吞成 0）：禁止判过"
  fi
  # R2-e：FAIL 汇总行判据。测试函数体内的 os.Exit(1) / log.Fatal / runtime.Goexit
  # 会直接终止**测试进程**，任何 --- FAIL 都来不及打印（实测：输出只剩
  # `=== RUN   TestE` + `FAIL <pkg> 0.6s` + 裸 `FAIL`，`--- FAIL` 命中 0 次），
  # 上面那条 --- FAIL 硬判与管道 rc 双双失效 → 必须再拦 FAIL 汇总行。
  # 锚定 `[[:space:]]|$`：裸 `FAIL` 行与 `FAIL <pkg> <dur>` 都命中；`--- FAIL`
  # （行首是 ---）不受影响；正常通过的输出（`ok <pkg>` / `PASS`）零命中，不误伤。
  if grep -qE '^FAIL([[:space:]]|$)' "$log"; then
    die "${label} 输出含 FAIL 汇总行（测试进程非正常退出，--- FAIL 不会打印）：禁止判过"
  fi
  # SKIP 只告警不改判（宽松版语义）；同样缩进容忍，子测试 Skip 输出为 `    --- SKIP: TestX/sub`。
  if grep -qE '^[[:space:]]*--- SKIP' "$log"; then
    warn "${label} 存在 SKIP 用例：按门控规范判未取证，不得据此宣称 PASS"
  fi
}

# assert_run_strict <log> <label> [必须实跑的测试函数名...]
# 门控专用断言：在 assert_run 的三重断言（有 RUN / 条数 >= 目标数 / 逐名命中）
# 之上，追加「输出不得含 --- SKIP」。
#
# 为什么必须单独有这一层：门控 3 的 TestRoute2StepRealQwenGolden 在模型权重不在本机时
# 主动 t.Skip（其头注写明「权重不在本机时 Skip，写明 D2 未执行，不伪造 PASS」）。
# 若只判「=== RUN 存在」，该用例会：=== RUN 有 → assert_run 判过 → 门控 3 判过 →
# 段末照打 [REMOTE-PASS]，直接把「SKIP = 未取证」洗成「门控已取证」，与门控规范直接冲突。
#
# 注意：静态段的自检（GUARD-SELFTEST / GUARD-POS / GUARD-NEG）继续用宽松的 assert_run，
# 那里是「断言函数本身的行为」而非门控取证，不能套 strict（否则会自证循环）。
assert_run_strict() {
  local log="$1" label="$2"
  assert_run "$@"
  # 缩进容忍：`go test -v` 对**子测试**输出 `    --- SKIP: TestX/sub`（4 空格）。
  # 只认行首 `^--- SKIP` 会放过「顶层 PASS、子测试 Skip」这种形态 —— 那是 SKIP 冒充
  # 取证的第二个入口（F-B 上一轮只堵了行首那个）。实测：真实子测试 Skip 样本里
  # `^--- SKIP` 命中 0 次、`^[[:space:]]*--- SKIP` 命中 1 次。
  if grep -qE '^[[:space:]]*--- SKIP' "$log"; then
    local skips
    skips="$(grep -cE '^[[:space:]]*--- SKIP' "$log" || true)"
    skips="${skips:-0}"
    REMOTE_SKIPS=$((REMOTE_SKIPS + skips))
    die "${label} 存在 ${skips} 条 --- SKIP 用例：按门控规范判未取证，不得宣称 PASS（段末判绿标记已被阻止）"
  fi
}

# ---------------------------------------------------------------------------
# 本地静态段：不依赖 Go 1.26、不联网、不写被扫描仓库
# ---------------------------------------------------------------------------
run_static() {
  echo "== 本地静态段（[STATIC-PASS] 均为本地项，非真机门控结论） =="

  # go test 会把临时测试二进制写进 GOTMPDIR（默认落在系统 Temp）；一并挪到 BUILD_DIR，
  # 避免同一处杀软启发式误伤。见文件头部 BUILD_DIR 的说明。
  export GOTMPDIR="$BUILD_DIR/gotmp"
  mkdir -p "$GOTMPDIR"

  # (a) gofmt -l 零输出
  # 枚举用 **git 跟踪清单**而不是 `find` 文件系统枚举：
  #   find 会把任何往仓库里落地的生成物（如 Go 自动生成的 _testmain.go）算进来，
  #   一次异常中断的残留就能让它红在一个与源码无关的路径上（实测过）。
  #   `git ls-files` 只认已跟踪文件，判据不会被工作树里的临时物污染。
  # 非 git 工作树（如 CI 里从 tarball 展开的副本）退回 find，并显式排除构建产物目录。
  if [ -d .git ]; then
    mapfile -t go_files < <(git ls-files '*.go' | sort)
  else
    mapfile -t go_files < <(find . -name '*.go' -not -path './.git/*' -type f \
      -not -path './.masked-infer-verify/*' | sort)
  fi
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
  pass "G1 场景 D：0 deps → 空集判绿文案（静态注入样本；实质闭包须真机 go list -test -deps 复验，🖥 未取证）"

  # (e) check_import_closure.go 基线复核（纯标准库，go1.20 可跑）
  #   默认弱校验：只断言三项真门禁为空（parse_failures / forbidden_path_hits /
  #   new_repo_cross_hits）；4 项计数仅 INFO 打印、不判红。阶段 1+ 迁包、阶段 3/4
  #   删包改 import 后计数必然漂移，强比对会误报失败，违背「不破坏已有功能」。
  #   阶段 3/4 import 改写前须用 -baseline 复核；基线确认漂移时用工具显式重生成
  #   scripts/closure-baseline.json 并提交，两侧同批评审。
  if [ -d "$MAIN_REPO" ]; then
    # WARN-10：先 go build 到临时可执行文件再执行，去掉对 `go run` 临时目录执行权限的依赖。
    GO111MODULE=off go build -o "$BUILD_DIR/cic" scripts/check_import_closure.go \
      || die "check_import_closure.go 构建失败"
    "$BUILD_DIR/cic" \
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

  # (e2) 新库零主仓依赖核验（verify 模式常驻门禁；go1.20 可跑）
  #   产品代码不得出现主仓/gmsm import 前缀；唯一白名单 scripts/verify_golden_against_main.go
  #   由工具在 verify 模式显式跳过（真机复核工具须 import 主仓 cipher/mask）。S2/S3 主仓语义 SKIP。
  GO111MODULE=off go build -o "$BUILD_DIR/cic" scripts/check_import_closure.go \
    || die "check_import_closure.go 构建失败"
  if "$BUILD_DIR/cic" -root "$REPO_ROOT" -mode verify \
      -forbid-prefix 'security-ai-gateway/' \
      -forbid-prefix 'github.com/FengYang/security-ai-gateway/' \
      -forbid-prefix 'github.com/emmansun/gmsm' \
      -out "$TMP_DIR/verify-self.json" > "$TMP_DIR/verify-self.log" 2>&1; then
    pass "新库零主仓依赖（verify 模式 S1/S4/S6 全 PASS、S2/S3 主仓语义 SKIP；白名单仅 verify_golden_against_main.go）"
    # 白名单可审计性：被跳过的文件数必须恒为 1（>1 说明白名单被人为扩大，须人工复核）。
    # 判据必须是**数值等于 1**，不能写成 `grep -E '^...=1'` 命中即过：
    # 那个正则没有尾锚，`=12`、`=19` 都以 `=1` 开头，白名单从 1 个扩到 12 个照样放行
    # （这正是「守卫自身有假绿」的形态）。取值后再比较，且取不到（空串）同样判红 ——
    # 否则工具一旦停止打印该行，守卫就静默失效。
    wl_n="$(sed -n 's/^VERIFY_WHITELIST_SKIPPED_FILES=\([0-9][0-9]*\).*/\1/p' "$TMP_DIR/verify-self.log" | head -n 1)"
    if [ "$wl_n" != "1" ]; then
      die "verify 白名单跳过数不为 1（实际 ${wl_n:-未取到}）：白名单可能被人为扩大、或工具未打印该行"
    fi
    # _test.go 覆盖性：G1 的关键风险是随迁测试把主仓路径带进闭包，故必须确认测试文件纳入扫描
    test_files_seen="$(sed -n 's/.*已覆盖 test_files=\([0-9][0-9]*\).*/\1/p' "$TMP_DIR/verify-self.log" | head -n 1)"
    if [ -z "$test_files_seen" ] || [ "$test_files_seen" -le 0 ]; then
      die "verify 模式未覆盖 _test.go（test_files=${test_files_seen:-未取到}），测试文件路径未被扫描"
    fi
    pass "verify 白名单跳过数=1 且 _test.go 已纳入扫描（test_files=$test_files_seen）"
  else
    die "新库存在主仓/gmsm import 前缀或 verify 自检失败：$(cat "$TMP_DIR/verify-self.log")"
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

  # (k3) 断言层双向自检（F-B 回归护栏，CI 可跑、不需要真机）
  #   为什么要有这条：(k)/(k2) 只证明「有没有实跑」，不证明「SKIP 会不会被洗成 PASS」。
  #   门控 3 的测试在权重缺失时主动 t.Skip，若只有宽松断言，=== RUN 存在就能一路判绿、
  #   段末照打判绿标记 —— 这正是 F-B 的假 PASS 通道。
  #   两个样本，均用**真实 go test -v** 产出（不用手写日志，避免样本与 Go 实际输出漂移）：
  #     样本 A（顶层 --- SKIP）：宽松 assert_run 必须判过（对照，证明差量来自 strict）、
  #                              assert_run_strict 必须判红；
  #     样本 B（纯 PASS）      ：assert_run_strict 必须不误判红。
  #   （缩进的子测试 SKIP 与 --- FAIL 两个样本见下方的 (k4)，独立成条以便审计。）
  cat > "$guard_pkg/dummy_skip_test.go" <<'DUMMYSKIPGO'
package dummy

import "testing"

// TestGuardSkip 模拟「模型权重不在本机时 Skip」的门控测试形态。
func TestGuardSkip(t *testing.T) {
	t.Skip("guard skip sample: 模拟权重缺失导致的 Skip")
}
DUMMYSKIPGO
  ( cd "$guard_pkg" && GO111MODULE=off go test -run '^TestGuardSkip$' -count=1 -v 2>&1 \
      | tee "$TMP_DIR/guard_skip.log" ) >/dev/null \
    || die "SKIP 哑测试 go test 执行失败: $(tail -n 3 "$TMP_DIR/guard_skip.log")"
  grep -q '^=== RUN[[:space:]]\+TestGuardSkip$' "$TMP_DIR/guard_skip.log" \
    || die "SKIP 哑测试未产出 === RUN（go test 很可能被杀软/权限拦在临时编译产物上，属环境问题，非判据失效；先查杀软白名单与 .verify-tmp 可执行权限）：$(tail -n 3 "$TMP_DIR/guard_skip.log")"
  grep -qE '^--- SKIP' "$TMP_DIR/guard_skip.log" \
    || die "SKIP 哑测试未产生 --- SKIP 行（样本无效，无法验证 strict）"
  rc=0
  ( assert_run "$TMP_DIR/guard_skip.log" "GUARD-SKIP-LOOSE" TestGuardSkip ) >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 0 ] \
    || die "对照失败：宽松 assert_run 在 SKIP 样本上不应判红，否则无法归因 strict 的差量"
  rc=0
  ( assert_run_strict "$TMP_DIR/guard_skip.log" "GUARD-SKIP-STRICT" TestGuardSkip ) >/dev/null 2>&1 || rc=$?
  [ "$rc" -ne 0 ] || die "assert_run_strict 在 --- SKIP 样本上未判红（SKIP 仍可冒充门控取证）"
  rc=0
  ( assert_run_strict "$TMP_DIR/guard_pos.log" "GUARD-PASS-STRICT" TestGuardReal ) >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 0 ] || die "assert_run_strict 在纯 PASS 样本上误判红"
  pass "assert_run_strict 双向验证（A 顶层 SKIP：宽松断言判过 / strict 判红 → 差量可归因；B 纯 PASS 样本 strict 不误判红）"

  # (k4) 缩进逃逸与 FAIL 硬判自检（D-1 回归护栏）
  #   与 (k3) 分开成独立断言，是为了让「这两条覆盖存在」在静态段输出里独占一行可审计，
  #   而不是被合并进 (k3) 的括号里（合并后条数不变，人就看不出来多了两项）。
  #   样本 C（子测试 Skip，缩进 `    --- SKIP: TestGuardSub/sub`）：
  #     旧正则 `^--- SKIP` 对它命中 0 次 ⇒ strict 会放行 ⇒ SKIP 冒充取证的第二入口。
  #   样本 D（--- FAIL）：assert_run 必须自己从输出判红，不依赖管道 rc
  #     （关掉 pipefail 时同一样本管道 rc=0，实测）。
  cat > "$guard_pkg/dummy_sub_test.go" <<'DUMMYSUBGO'
package dummy

import "testing"

// TestGuardSub 模拟「顶层 PASS、子测试 Skip」的形态（门控按其用例分组时会出现）。
func TestGuardSub(t *testing.T) {
	t.Run("sub", func(t *testing.T) {
		t.Skip("guard sub-skip sample: 模拟子测试因前置条件缺失而 Skip")
	})
}
DUMMYSUBGO
  ( cd "$guard_pkg" && GO111MODULE=off go test -run '^TestGuardSub$' -count=1 -v 2>&1 \
      | tee "$TMP_DIR/guard_sub.log" ) >/dev/null \
    || die "子测试 Skip 样本 go test 执行失败: $(tail -n 3 "$TMP_DIR/guard_sub.log")"
  # 前置断言（必须在判据断言之前）：区分「环境/工具链坏了」与「判据失效」。
  # 若 go test 因杀软拦截、权限拒绝、编译失败而根本没跑起来，日志里不会有任何 === RUN。
  # 这时若直接报「样本无效」，会把人引去改样本/改正则 —— 那正是「为了让门禁闭嘴而改
  # 期望值」的入口。所以先单独判「有没有实跑」，文案明确指向环境。
  sub_run_count="$(grep -c '^=== RUN' "$TMP_DIR/guard_sub.log" || true)"
  sub_run_count="${sub_run_count:-0}"
  [ "$sub_run_count" -ge 1 ] \
    || die "子测试 Skip 样本未产出任何 === RUN（go test 很可能被杀软拦截了临时编译产物，属环境问题，非判据失效）：$(tail -n 3 "$TMP_DIR/guard_sub.log")"
  # 样本有效性自证（这是本样本的全部价值）：行首正则命中 0、缩进正则命中 >=1，
  # 即「旧正则必然漏掉这个样本」这件事本身被机器证明了。
  sub_line_start_hits="$(grep -cE '^--- SKIP' "$TMP_DIR/guard_sub.log" || true)"
  sub_indented_hits="$(grep -cE '^[[:space:]]*--- SKIP' "$TMP_DIR/guard_sub.log" || true)"
  sub_line_start_hits="${sub_line_start_hits:-0}"
  sub_indented_hits="${sub_indented_hits:-0}"
  [ "$sub_line_start_hits" -eq 0 ] \
    || die "子测试 Skip 样本未体现缩进逃逸（行首命中 ${sub_line_start_hits} 次），样本无效"
  [ "$sub_indented_hits" -ge 1 ] \
    || die "子测试 Skip 样本有 === RUN 但无缩进 --- SKIP 行（缩进命中 ${sub_indented_hits} 次）：Go 的 -v 输出格式可能变了，须复核正则，非环境问题：$(tail -n 3 "$TMP_DIR/guard_sub.log")"
  rc=0
  ( assert_run_strict "$TMP_DIR/guard_sub.log" "GUARD-SUBSKIP-STRICT" TestGuardSub ) >/dev/null 2>&1 || rc=$?
  [ "$rc" -ne 0 ] || die "assert_run_strict 未拦住缩进的子测试 --- SKIP（D-1 缩进逃逸未修好）"

  cat > "$guard_pkg/dummy_fail_test.go" <<'DUMMYFAILGO'
package dummy

import "testing"

// TestGuardFail 模拟「测试真的失败」的形态。
func TestGuardFail(t *testing.T) {
	t.Fatal("guard fail sample: 模拟测试失败")
}
DUMMYFAILGO
  # 先证明「rc 不可依赖」这个前提成立：关掉 pipefail 后，同一条失败管道 rc=0（tee 的 rc）。
  fail_pipe_rc_nopipefail=0
  ( set +o pipefail
    cd "$guard_pkg" && GO111MODULE=off go test -run '^TestGuardFail$' -count=1 -v 2>&1 \
      | tee "$TMP_DIR/guard_fail.log" >/dev/null ) || fail_pipe_rc_nopipefail=$?
  # 前置断言：与样本 C 同理，先分「没跑起来（环境）」和「跑了但没有 FAIL 行（格式变了）」。
  fail_run_count="$(grep -c '^=== RUN' "$TMP_DIR/guard_fail.log" || true)"
  fail_run_count="${fail_run_count:-0}"
  [ "$fail_run_count" -ge 1 ] \
    || die "FAIL 样本未产出任何 === RUN（go test 很可能被杀软拦截了临时编译产物，属环境问题，非判据失效）：$(tail -n 3 "$TMP_DIR/guard_fail.log")"
  grep -qE '^[[:space:]]*--- FAIL' "$TMP_DIR/guard_fail.log" \
    || die "FAIL 样本有 === RUN 但无 --- FAIL 行：Go 的 -v 输出格式可能变了，须复核，非环境问题：$(tail -n 3 "$TMP_DIR/guard_fail.log")"
  rc=0
  ( assert_run "$TMP_DIR/guard_fail.log" "GUARD-FAIL" TestGuardFail ) >/dev/null 2>&1 || rc=$?
  [ "$rc" -ne 0 ] || die "assert_run 未拦住 --- FAIL（管道 rc 被吞时会假绿）"
  pass "缩进逃逸与 FAIL 硬判自检（C 子测试缩进 SKIP 已判红：行首命中 ${sub_line_start_hits} 次 / 缩进命中 ${sub_indented_hits} 次；D --- FAIL 已判红：关 pipefail 后管道 rc=${fail_pipe_rc_nopipefail} 已被吞仍判红；panic 不属此洞 —— panic 本身就会打行首 --- FAIL，已被上面 D 的判据覆盖）"

  #   样本 E（os.Exit，R2-e）：测试函数体内 os.Exit(1) 直接终止测试进程，
  #     `--- FAIL` 来不及打印（实测真实 go test：--- FAIL 命中 0 次、=== RUN 有、
  #     管道 rc=0），只剩 FAIL 汇总行可抓 → assert_run 必须靠
  #     `^FAIL([[:space:]]|$)` 判红。这是 D-1/W-2 同族的第三缺口（前两个已堵）。
  cat > "$guard_pkg/dummy_exit_test.go" <<'DUMMYEXITGO'
package dummy

import (
	"os"
	"testing"
)

// TestGuardExit 模拟「测试函数体内 os.Exit(1)」的形态：进程当场死掉，
// --- FAIL 不会打印，只剩 FAIL 汇总行。
func TestGuardExit(t *testing.T) {
	t.Log("guard os.Exit sample: 模拟测试函数体内 os.Exit(1)")
	os.Exit(1)
}
DUMMYEXITGO
  # tee 仍落盘、stdout 进 /dev/null（同样本 A–D 形态）；管道 rc 无论如何不参与判定。
  ( set +o pipefail
    cd "$guard_pkg" && GO111MODULE=off go test -run '^TestGuardExit$' -count=1 -v 2>&1 \
      | tee "$TMP_DIR/guard_exit.log" >/dev/null ) || true
  # 前置断言（与样本 C/D 同理）：先分「没跑起来（环境）」和「跑了但形态不对（格式变了）」。
  exit_run_count="$(grep -c '^=== RUN' "$TMP_DIR/guard_exit.log" || true)"
  exit_run_count="${exit_run_count:-0}"
  [ "$exit_run_count" -ge 1 ] \
    || die "os.Exit 样本未产出任何 === RUN（go test 很可能被杀软拦截了临时编译产物，属环境问题，非判据失效）：$(tail -n 3 "$TMP_DIR/guard_exit.log")"
  # 样本有效性自证：--- FAIL 必须命中 0 次（洞存在的前提）、FAIL 汇总行必须命中 >=1
  # （新判据的靶子确实在）。两件事都被机器证明，而不是口头断言。
  exit_indent_fail_hits="$(grep -cE '^[[:space:]]*--- FAIL' "$TMP_DIR/guard_exit.log" || true)"
  exit_summary_hits="$(grep -cE '^FAIL([[:space:]]|$)' "$TMP_DIR/guard_exit.log" || true)"
  exit_indent_fail_hits="${exit_indent_fail_hits:-0}"
  exit_summary_hits="${exit_summary_hits:-0}"
  [ "$exit_indent_fail_hits" -eq 0 ] \
    || die "os.Exit 样本意外出现 --- FAIL 行（命中 ${exit_indent_fail_hits} 次）：样本形态与本洞前提不符，须复核样本与 Go 输出格式"
  [ "$exit_summary_hits" -ge 1 ] \
    || die "os.Exit 样本有 === RUN 但无 FAIL 汇总行：Go 的 -v 输出格式可能变了，须复核正则，非环境问题：$(tail -n 3 "$TMP_DIR/guard_exit.log")"
  rc=0
  ( assert_run "$TMP_DIR/guard_exit.log" "GUARD-EXIT" TestGuardExit ) >/dev/null 2>&1 || rc=$?
  [ "$rc" -ne 0 ] \
    || die "assert_run 未拦住 os.Exit 样本（仅靠 --- FAIL 硬判时，测试进程非正常退出会双双假绿）"
  pass "os.Exit 逃逸自检（E os.Exit 样本已判红：--- FAIL 命中 ${exit_indent_fail_hits} 次 / FAIL 汇总行命中 ${exit_summary_hits} 次，管道 rc 被吞仍判红；log.Fatal 与 runtime.Goexit 同属本洞，判据一致覆盖）"

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
#   - 门控 1–5 一律用 assert_run_strict（额外禁止 --- SKIP），并在段末独立复扫
#     gate*.log 兜底：SKIP = 未取证，绝不允许洗完再打 [REMOTE-PASS]。
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
  # 必须验新库侧。
  # 守卫必须绑「该测试文件」而非「其父目录」：阶段 1 已迁入 adapters/qwen（目录存在），
  # 但 route2step_golden_test.go 阶段 3 才迁 ⇒ 用 -d 判目录会在阶段 1/2 误入本分支，
  # 导致 -run 无匹配（go test rc=0、无 === RUN）被 assert_run 判红，真机段恒失败。
  # 改为 -f 判文件：阶段 3 迁入该测试后自动生效。
  GATE3_SUB_RAN=0
  if [ -f "$SUB_REPO/adapters/qwen/route2step_golden_test.go" ]; then
    GATE3_SUB_RAN=1
    (
      cd "$SUB_REPO"
      GOWORK=off go test ./adapters/qwen/... -run TestRoute2StepRealQwenGolden \
        -count=1 -v 2>&1 | tee "$TMP_DIR/gate3_sub.log"
    )
    assert_run_strict "$TMP_DIR/gate3_sub.log" "门控3(新库侧)" TestRoute2StepRealQwenGolden
  else
    echo "SKIP: 门控3 新库侧（adapters/qwen/route2step_golden_test.go 尚未迁入，阶段 3 迁入后自动生效）"
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
    assert_run_strict "$TMP_DIR/gate1.log" "门控1" \
      TestHMACPRGMatchesLegacy TestHMACPRGEqualsIntlProviderKeystream \
      TestIntlStreamWithProviderEqualsStreamDomain TestSM4StreamDeterministic \
      TestSM4VsHMACNotInteroperable TestNewStreamWithProviderKeySize

    # 门控 2：TestFormAEquivalence / TestFormAKVConsistency 实测位于
    #   gateway/route2/orchestrator/form_a_test.go:25/:82（adapters/qwen 下无此测试）。
    #   MaxAbsDiff ≤ 5e-3、top-1 一致。
    go test ./gateway/route2/orchestrator/... \
      -run 'TestFormAEquivalence|TestFormAKVConsistency' -count=1 -v 2>&1 | tee "$TMP_DIR/gate2.log"
    assert_run_strict "$TMP_DIR/gate2.log" "门控2" TestFormAEquivalence TestFormAKVConsistency

    # 门控 3（主仓侧）：基线形式；阶段 4 删主仓包后移除本行。
    #   282 步 top-1=23811 / maxRelErr=0.0390；新库侧命令见上方（阶段 3 起生效）。
    go test ./... -run 'TestRoute2StepRealQwenGolden' -count=1 -v 2>&1 | tee "$TMP_DIR/gate3_main.log"
    assert_run_strict "$TMP_DIR/gate3_main.log" "门控3(主仓侧)" TestRoute2StepRealQwenGolden

    # 门控 4：主仓全量 build/vet/test + SBOM gate 不回归（已在上方执行），
    #         发布前另按 SBOM/README.md 重生成并复核。

    # 门控 5：G2 golden 与主仓 NewStreamDomain 逐字节一致（去硬编码，用 $SUB_REPO）
    go run "$SUB_REPO/scripts/verify_golden_against_main.go" \
      -golden "$SUB_REPO/masklite/testdata/stream.golden"
  )
  # 段末总闸（F-B 第二层，防「漏改 strict 仍在段末宣称全取证」）：
  #   **仅在 run_remote 上下文内使用（无条件要求 gate1/gate2/gate3_main 三份日志存在）**；
  #   静态段不得调用 —— 静态段没有真机门控日志，误用会把空集当全绿。
  #   独立复扫本次全部门控日志，任何 --- SKIP 都禁止输出 [REMOTE-PASS]。
  #   与 assert_run_strict 的即时 die 是**双保险**，不是重复：
  #   - 门控 1/2/3(主仓侧) 跑在 `( cd "$MAIN_REPO" ... )` 子 shell 里，子 shell 内的
  #     REMOTE_SKIPS 自增不会回传父 shell（这是 shell 语义，不是 bug），所以
  #     「日志复扫」才是这几段计数的**权威来源**；strict 负责当场判红、给出精确 label。
  #   - 本闸同时兜住「将来新增门控但忘了用 strict」这类回归。
  #
  # 门控日志存在性断言（必须在下面的通配循环**之前**）：
  #   循环写的是 `for x in "$TMP_DIR"/gate*.log`，无匹配时 bash 会把未展开的字面量
  #   `…/gate*.log` 当成一项传进来，再被 `[ -f ] || continue` 兜掉 —— 结果是
  #   「一份门控日志都没有」也被当成正常：某个门控没跑/中途退出 ⇒ total_skips=0 ⇒
  #   照打段末判绿标记。所以这里先按**具体文件名**逐个断言存在，缺一即 die。
  #   注意 gate3_sub.log 只在 gate3 新库侧真的跑过时才有（GATE3_SUB_RAN=1）。
  gate_must_logs="gate1.log gate2.log gate3_main.log"
  if [ "${GATE3_SUB_RAN:-0}" -eq 1 ]; then
    gate_must_logs="$gate_must_logs gate3_sub.log"
  fi
  for m in $gate_must_logs; do
    [ -f "$TMP_DIR/$m" ] \
      || die "真机段缺少门控日志 ${m}：该门控未执行或中途退出，禁止输出段末判绿标记"
  done

  local_gate_skips=0
  for gate_log in "$TMP_DIR"/gate*.log; do
    [ -f "$gate_log" ] || continue
    n="$(grep -cE '^[[:space:]]*--- SKIP' "$gate_log" || true)"
    n="${n:-0}"
    if [ "$n" -gt 0 ]; then
      echo "  [SKIP-DETECTED] $(basename "$gate_log")：${n} 条 --- SKIP" >&2
    fi
    local_gate_skips=$((local_gate_skips + n))
  done
  total_skips=$((REMOTE_SKIPS + local_gate_skips))
  if [ "$total_skips" -gt 0 ]; then
    die "真机段累计 ${total_skips} 条 --- SKIP 用例（strict 计数=${REMOTE_SKIPS}，日志复扫=${local_gate_skips}）：按门控规范判未取证，禁止输出段末判绿标记"
  fi
  # 文案不得超出实际取证范围：阶段 1/2 门控 3 新库侧按设计未启用（测试文件阶段 3 才迁入），
  # 此时不能笼统宣称「门控 1–5 已实际取证」，须显式标出哪一项未启用。
  if [ "$GATE3_SUB_RAN" -eq 1 ]; then
    echo "[REMOTE-PASS] 真机段完成：门控 1–5 已实际取证（0 条 SKIP；含门控 3 新库侧）"
  else
    echo "[REMOTE-PASS] 真机段完成：门控 1–4 / 5（主仓侧）已实际取证（0 条 SKIP）；门控 3 新库侧按设计未启用（阶段 3 迁入 route2step_golden_test.go 后自动生效）"
  fi
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
