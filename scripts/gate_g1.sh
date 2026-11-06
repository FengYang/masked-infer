#!/usr/bin/env bash
# G1 新库依赖门禁 —— 《路线2-独立代码库拆分方案》，自 阶段 0 起常驻。
#
# 判据：含测试的依赖闭包（go list -test -deps ./...）中，禁止出现
#   1) 主仓裸名前缀 "${MAIN_MOD}/"（当前为 security-ai-gateway/）；
#   2) 主仓改名（D4a）后的域名前缀 "github.com/${SUB_ORG}/security-ai-gateway/"；
#   3) 国密库 "github.com/emmansun/gmsm"。
# 双前缀 + MAIN_MOD 可注入，保证 D4a 改名后不漏报。
#
# 加固点（相对前稿 `... | grep ... && exit 1 || true`）：
#   - set -euo pipefail + 临时文件：go list 自身失败不会被 `|| true` 吞掉而静默判绿；
#   - 显式 GOWORK=off：CI 不依赖本地 go.work workspace，也不会把主仓带进闭包；
#   - 用 -test -deps：把 _test.go 的 import 计入，防 go mod tidy 把主仓路径写进 go.mod。
#
# 【为何主仓侧此时不加 "cipher/mask ↛ cryptop" deny 规则】
#   该依赖当前真实存在（route2step/step_exec.go 的生产代码直接 import cipher/mask，
#   且其 *mask.Stream 签名把主仓具体类型写进引擎侧 API）。提前加 deny 规则会让
#   现有代码判红，属误报。它登记为拆库验收判据：待 CA-3 把 NewStream 改为
#   新库 MaskStream 接口、宿主注入点适配完成后，再启用该规则并作为阶段 3 验收项。
#   本门禁只负责新库侧「防未来新增链」，不负责修当前主仓。
set -euo pipefail

MAIN_MOD=${MAIN_MOD:-security-ai-gateway}      # D4a 改名后由 CI 注入新 path
SUB_ORG=${SUB_ORG:-FengYang}                   # 覆写点：CI 变量 / 建仓组织配置
export GOWORK=off

DEPS_FILE="${TMPDIR:-/tmp}/g1_deps.txt"

# go list 失败时 set -e 立即终止；不使用管道 + || true，避免失败被吞掉。
go list -test -deps -f '{{.ImportPath}}' ./... > "${DEPS_FILE}"

if grep -nE "^(${MAIN_MOD}/|github\.com/${SUB_ORG}/security-ai-gateway/|github\.com/emmansun/gmsm)" "${DEPS_FILE}"; then
  echo "G1 FAIL: forbidden main-repo / gmsm dependency"
  exit 1
fi

# 只改输出文案，不改判定逻辑：空模块（0 deps）时明确标注「空集判绿」，
# 避免把无包可扫误读为实质闭包已验证；文案仍以 "G1 PASS" 开头，保证既有
# 断言（verify_all.sh 场景 A/B/C 与 QA 样本组）不受影响。
DEP_COUNT="$(wc -l < "${DEPS_FILE}" | tr -d '[:space:]')"
if [ "${DEP_COUNT}" -eq 0 ]; then
  echo "G1 PASS (empty module / 0 deps): 空集判绿，实质闭包判绿须待阶段 1 有包后复验"
else
  echo "G1 PASS: zero forbidden prefix in ${DEP_COUNT} deps"
fi
