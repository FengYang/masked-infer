//go:build ignore

// verify_golden_against_main.go —— G2 真机侧复核工具（门控 5）。
//
// 【运行位置】主仓 security-ai-gateway 根目录（必须在该 module 内执行）。
// 【前置条件】真机 Go 1.26（192.168.31.248，/usr/local/go/bin）、主仓 module 可编译
//
//	（cryptop / cipher/mask 的依赖齐备），且新库侧 golden 与主仓 commit 对齐。
//
// 【命令】
//
//	cd F:/方案/security-ai-gateway && \
//	  go run ../masked-infer/scripts/verify_golden_against_main.go \
//	    -golden ../masked-infer/masklite/testdata/stream.golden
//
// 本文件引用主仓 `security-ai-gateway/cipher/mask` 的 NewStreamDomain，故：
//   - 带 //go:build ignore，不进入新库 go list -test -deps ./... 的 G1 闭包（否则 G1 立刻判红），
//     也避免与同目录其它 package main 的 func main() 冲突；
//   - 只在新库 CI 的 GOWORK=off 之外、由真机在主仓 module 内运行，本阶段（阶段 0）写好但不运行。
//
// 输出：G2_VERIFY_MAIN PASS（全部逐字节一致）或 G2_VERIFY_MAIN FAIL: <原因>（exit 1）。
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"security-ai-gateway/cipher/mask"
)

type goldenCase struct {
	name   string
	seed   []byte
	r      uint64
	domain []byte
	n      int
	values []uint64
}

func fail(format string, args ...interface{}) {
	fmt.Printf("G2_VERIFY_MAIN FAIL: "+format+"\n", args...)
	os.Exit(1)
}

func parseCaseParams(fields []string) (*goldenCase, error) {
	kv := make(map[string]string, len(fields))
	for _, f := range fields {
		parts := strings.SplitN(f, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("bad field %q", f)
		}
		kv[parts[0]] = parts[1]
	}
	name, ok := kv["case"]
	if !ok {
		return nil, fmt.Errorf("case line without case= field")
	}
	seed, err := hex.DecodeString(kv["seed"])
	if err != nil {
		return nil, fmt.Errorf("case %s: seed hex: %w", name, err)
	}
	domain, err := hex.DecodeString(kv["domain"])
	if err != nil {
		return nil, fmt.Errorf("case %s: domain hex: %w", name, err)
	}
	r, err := strconv.ParseUint(kv["r"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("case %s: r: %w", name, err)
	}
	n, err := strconv.Atoi(kv["n"])
	if err != nil {
		return nil, fmt.Errorf("case %s: n: %w", name, err)
	}
	if n < 1 {
		return nil, fmt.Errorf("case %s: n=%d < 1", name, n)
	}
	return &goldenCase{name: name, seed: seed, r: r, domain: domain, n: n, values: make([]uint64, 0, n)}, nil
}

func readGolden(path string) ([]*goldenCase, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()
	var cases []*goldenCase
	var current *goldenCase
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if strings.HasPrefix(fields[0], "case=") {
			c, err := parseCaseParams(fields)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
			cases = append(cases, c)
			current = c
			continue
		}
		if len(fields) != 2 {
			return nil, fmt.Errorf("line %d: expected '<index> <16hex>', got %q", lineNo, line)
		}
		if current == nil {
			return nil, fmt.Errorf("line %d: data before first case= line", lineNo)
		}
		idx, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil, fmt.Errorf("line %d: index: %w", lineNo, err)
		}
		v, err := strconv.ParseUint(fields[1], 16, 64)
		if err != nil {
			return nil, fmt.Errorf("line %d: value: %w", lineNo, err)
		}
		if idx != len(current.values) {
			return nil, fmt.Errorf("line %d: index %d != expected %d", lineNo, idx, len(current.values))
		}
		current.values = append(current.values, v)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cases, nil
}

func verifyCase(c *goldenCase) error {
	if len(c.values) != c.n {
		return fmt.Errorf("case %s: got %d values, header n=%d", c.name, len(c.values), c.n)
	}
	s, err := mask.NewStreamDomain(c.seed, c.r, c.domain)
	if err != nil {
		return fmt.Errorf("case %s: NewStreamDomain: %w", c.name, err)
	}
	buf := make([]uint64, len(c.values))
	if err := s.Fill(buf); err != nil {
		return fmt.Errorf("case %s: Fill: %w", c.name, err)
	}
	if s.Modulus() != c.r {
		return fmt.Errorf("case %s: Modulus()=%d want %d", c.name, s.Modulus(), c.r)
	}
	for i := range buf {
		if buf[i] != c.values[i] {
			return fmt.Errorf("case %s: value %d mismatch main=%016x golden=%016x", c.name, i, buf[i], c.values[i])
		}
	}
	s.Zeroize()
	fmt.Printf("  case %-14s n=%d r=%d domain=%s: %d values match\n",
		c.name, len(c.values), c.r, hex.EncodeToString(c.domain), len(c.values))
	return nil
}

func main() {
	goldenPath := flag.String("golden", "../masked-infer/masklite/testdata/stream.golden", "G2 golden 文件路径（相对主仓根目录）")
	flag.Parse()

	cases, err := readGolden(*goldenPath)
	if err != nil {
		fail("read golden %s: %v", *goldenPath, err)
	}
	if len(cases) != 3 {
		fail("expected 3 cases (base | domain_sep | large_modulus), got %d", len(cases))
	}
	wantNames := []string{"base", "domain_sep", "large_modulus"}
	for i, want := range wantNames {
		if cases[i].name != want {
			fail("case %d name=%s want %s", i, cases[i].name, want)
		}
	}
	if cases[0].r != cases[1].r || string(cases[0].seed) != string(cases[1].seed) {
		fail("domain_sep case must share seed and r with base")
	}
	if string(cases[0].domain) == string(cases[1].domain) {
		fail("domain_sep case must use a different domain")
	}
	if cases[2].r <= uint64(1)<<63 {
		fail("large_modulus r=%d must be > 2^63", cases[2].r)
	}

	for _, c := range cases {
		if err := verifyCase(c); err != nil {
			fail("%v", err)
		}
	}
	diff := 0
	for i := range cases[0].values {
		if cases[0].values[i] != cases[1].values[i] {
			diff++
		}
	}
	if diff == 0 {
		fail("domain separation: base and domain_sep golden sequences are identical")
	}
	fmt.Printf("  domain separation: %d/%d values differ\n", diff, len(cases[0].values))
	fmt.Println("G2_VERIFY_MAIN PASS")
}
