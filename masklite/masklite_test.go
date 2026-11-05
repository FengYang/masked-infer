package masklite

// TestGolden 是 G2 金标向量回归（ci.yml 冻结文件 masklite/masklite_test.go 与函数名 TestGolden）。
//
// 只读 masklite/testdata/stream.golden，**不写 golden、严禁 t.Skip**：任何缺失/格式/解析失败
// 一律 t.Fatalf（fail-closed，防止「无断言却判绿」）。逐 uint64 精确比对，不做字符串比较。
import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// wantModulus 是 golden 的基准模 R = 2^64-1（route2MaskModulus，统计等价 2^64）。
const wantModulus uint64 = ^uint64(0)

// goldenCase 表示一个 `case=` 数据段。
type goldenCase struct {
	name   string
	seed   []byte
	r      uint64
	domain []byte
	n      int
	values []uint64
}

var (
	reMainCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)
	reDataLine   = regexp.MustCompile(`^([0-9]+) ([0-9a-f]{16})$`)
)

func mustHeader(t *testing.T, headers map[string]string, key string) string {
	t.Helper()
	v, ok := headers[key]
	if !ok {
		t.Fatalf("golden 头部缺少字段 %q", key)
	}
	return v
}

func parseCaseLine(line string) (*goldenCase, error) {
	c := &goldenCase{}
	for _, f := range strings.Fields(line) {
		switch {
		case strings.HasPrefix(f, "case="):
			c.name = strings.TrimPrefix(f, "case=")
		case strings.HasPrefix(f, "seed="):
			b, err := hex.DecodeString(strings.TrimPrefix(f, "seed="))
			if err != nil {
				return nil, fmt.Errorf("seed: %w", err)
			}
			c.seed = b
		case strings.HasPrefix(f, "r="):
			v, err := strconv.ParseUint(strings.TrimPrefix(f, "r="), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("r: %w", err)
			}
			c.r = v
		case strings.HasPrefix(f, "domain="):
			d := strings.TrimPrefix(f, "domain=")
			if d != "" {
				b, err := hex.DecodeString(d)
				if err != nil {
					return nil, fmt.Errorf("domain: %w", err)
				}
				c.domain = b
			}
		case strings.HasPrefix(f, "n="):
			n, err := strconv.Atoi(strings.TrimPrefix(f, "n="))
			if err != nil {
				return nil, fmt.Errorf("n: %w", err)
			}
			c.n = n
		default:
			return nil, fmt.Errorf("未知字段 %q", f)
		}
	}
	if c.name == "" {
		return nil, fmt.Errorf("缺少 case 名")
	}
	return c, nil
}

func parseParams(t *testing.T, s string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, f := range strings.Fields(s) {
		i := strings.Index(f, "=")
		if i < 0 {
			t.Fatalf("params 字段非法: %q", f)
		}
		out[f[:i]] = f[i+1:]
	}
	return out
}

func uint64SliceEqual(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestGolden(t *testing.T) {
	path := filepath.Join("testdata", "stream.golden")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 golden 失败 %s: %v", path, err)
	}

	headers := make(map[string]string)
	var cases []*goldenCase
	var cur *goldenCase

	finalize := func() {
		if cur == nil {
			return
		}
		if len(cur.values) != cur.n {
			t.Fatalf("case %s: 数据行数 %d != 头部 n=%d", cur.name, len(cur.values), cur.n)
		}
	}

	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "# "):
			body := strings.TrimPrefix(line, "# ")
			idx := strings.Index(body, ": ")
			if idx < 0 {
				t.Fatalf("第 %d 行 header 格式非法（缺 \": \"）: %q", lineNo, line)
			}
			headers[body[:idx]] = body[idx+2:]
		case strings.HasPrefix(line, "case="):
			finalize()
			c, perr := parseCaseLine(line)
			if perr != nil {
				t.Fatalf("第 %d 行 case 解析失败: %v", lineNo, perr)
			}
			cur = c
			cases = append(cases, c)
		default:
			m := reDataLine.FindStringSubmatch(line)
			if m == nil {
				t.Fatalf("第 %d 行无法识别（非 header / case / 数据）: %q", lineNo, line)
			}
			if cur == nil {
				t.Fatalf("第 %d 行数据出现在任何 case= 之前", lineNo)
			}
			idx, _ := strconv.Atoi(m[1])
			if idx != len(cur.values) {
				t.Fatalf("case %s: 第 %d 行 idx=%d 非连续（期望 %d，跳号/重号）", cur.name, lineNo, idx, len(cur.values))
			}
			v, perr := strconv.ParseUint(m[2], 16, 64)
			if perr != nil {
				t.Fatalf("case %s: 第 %d 行值 %q 非 uint64 hex: %v", cur.name, lineNo, m[2], perr)
			}
			cur.values = append(cur.values, v)
		}
	}
	finalize()
	if err := sc.Err(); err != nil {
		t.Fatalf("扫描 golden 出错: %v", err)
	}

	// (1) schema 精确匹配。
	if got := mustHeader(t, headers, "schema"); got != "masked-infer/g2-stream-golden/v1" {
		t.Fatalf("schema=%q != masked-infer/g2-stream-golden/v1", got)
	}
	// (2) 必需头部字段齐全（缺一即 fail）。
	for _, k := range []string{
		"params", "gen_cmd", "gen_impl", "main_commit", "main_anchor",
		"main_modulus_source", "verify_cmd", "change_ctl", "algorithm", "cases",
	} {
		mustHeader(t, headers, k)
	}
	// (3) main_commit 为 40 位小写 hex。
	if mc := headers["main_commit"]; !reMainCommit.MatchString(mc) {
		t.Fatalf("main_commit=%q 不匹配 ^[0-9a-f]{40}$", mc)
	}
	// (4) algorithm 行必须含正确阈值写法，防用已废弃公式生成。
	if !strings.Contains(headers["algorithm"], "^uint64(0)-(^uint64(0)%r)") {
		t.Fatalf("algorithm 行缺少 ^uint64(0)-(^uint64(0)%%r) 子串（疑似废弃公式 2^64-(2^64 mod r) 生成）: %q", headers["algorithm"])
	}
	// (5) cases 声明。
	if got := headers["cases"]; got != "base | domain_sep | large_modulus" {
		t.Fatalf("cases=%q != base | domain_sep | large_modulus", got)
	}
	// (6) 恰 3 段且名称/顺序一致。
	wantNames := []string{"base", "domain_sep", "large_modulus"}
	if len(cases) != len(wantNames) {
		t.Fatalf("case 段数 %d != %d", len(cases), len(wantNames))
	}
	for i, w := range wantNames {
		if cases[i].name != w {
			t.Fatalf("第 %d 段名称 %q != %q（顺序不符）", i, cases[i].name, w)
		}
	}
	byName := make(map[string]*goldenCase, len(cases))
	for _, c := range cases {
		byName[c.name] = c
	}
	base := byName["base"]
	domainSep := byName["domain_sep"]
	largeMod := byName["large_modulus"]

	// (8) header/常量一致性。
	if base.r != wantModulus {
		t.Fatalf("base.r=%d != wantModulus=%d", base.r, wantModulus)
	}
	params := parseParams(t, headers["params"])
	if params["modulus"] != strconv.FormatUint(wantModulus, 10) {
		t.Fatalf("params modulus=%q != %d", params["modulus"], wantModulus)
	}
	if params["seed"] != hex.EncodeToString(base.seed) {
		t.Fatalf("params seed=%q != base seed=%q", params["seed"], hex.EncodeToString(base.seed))
	}
	if params["count"] != strconv.Itoa(base.n) {
		t.Fatalf("params count=%q != base n=%d", params["count"], base.n)
	}

	// (6b) base 与 domain_sep：同 seed、同 r、不同 domain，且值不得完全相同（域分离生效）。
	if !bytes.Equal(base.seed, domainSep.seed) {
		t.Fatalf("base/domain_sep seed 不同")
	}
	if base.r != domainSep.r {
		t.Fatalf("base/domain_sep r 不同")
	}
	if bytes.Equal(base.domain, domainSep.domain) {
		t.Fatalf("base/domain_sep domain 相同（域分离失效）")
	}
	if uint64SliceEqual(base.values, domainSep.values) {
		t.Fatalf("base/domain_sep 值完全相同（域分离未生效）")
	}

	// (7) large_modulus 段 r > 2^63（主仓 mask.go:98 拒绝采样边界）。
	if largeMod.r <= uint64(1)<<63 {
		t.Fatalf("large_modulus.r=%d 不满足 > 2^63(%d)", largeMod.r, uint64(1)<<63)
	}

	// (9) 逐 uint64 精确比对（用本包 NewStreamDomain + Fill 重算）。
	for _, c := range cases {
		s, serr := NewStreamDomain(c.seed, c.r, c.domain)
		if serr != nil {
			t.Fatalf("case %s: NewStreamDomain: %v", c.name, serr)
		}
		got := make([]uint64, c.n)
		if ferr := s.Fill(got); ferr != nil {
			t.Fatalf("case %s: Fill: %v", c.name, ferr)
		}
		for i := range got {
			if got[i] != c.values[i] {
				t.Fatalf("case %s 第 %d 值不符: got=%016x want=%016x", c.name, i, got[i], c.values[i])
			}
		}
	}
	t.Logf("TestGolden PASS: base/domain_sep/large_modulus 各 %d 值逐 uint64 精确匹配", base.n)
}
