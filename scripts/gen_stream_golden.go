//go:build ignore

// gen_stream_golden.go —— G2 掩码流 golden 向量生成器（§5 阶段 0）。
//
// 纯标准库实现，逐字节复刻主仓 cipher/mask 的真实算法（mask.go L57–L184）：
//   - candidate_k = HMAC-SHA256(seed, BE64(k) || domain)[:8]
//   - hmacPRG.Keystream(n) = concat_{ctr=0,1,2,...} candidate_ctr，截断到 n 字节
//   - Stream.Next()：buf 不足 8 字节时追加 Keystream(64)；取 BE64(buf[:8]) 并消费；
//     拒绝采样阈值 threshold = ^uint64(0) - (^uint64(0) % r)；接受 v < threshold 时
//     返回 v % r，否则丢弃续取。
//
// ⚠ 阈值口径以主仓源码 mask.go:89 为准，不得写成 2^64 - (2^64 mod r)。
//
//	两者在 r | 2^64 时结果不同，会使 golden 整体错位；主仓 mask.go:98 亦明确警告
//	r > 2^63 时不能用 (2^64-1-r+1)/r*r 写法（该式为 0 导致无限循环）。
//
// 本文件带 //go:build ignore：不进入新库 go list -test -deps ./... 的 G1 闭包，
// 也不与同目录其它 package main 的 func main() 冲突。
//
// 运行（本机 go1.20.3 亦可：纯标准库 + ignore tag + GO111MODULE=off）：
//
//	GO111MODULE=off go run scripts/gen_stream_golden.go -selfcheck
//	GO111MODULE=off go run scripts/gen_stream_golden.go -golden \
//	    -main-commit <40hex> -verify-cmd '<真机命令>' -out masklite/testdata/stream.golden
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	minSeedLen = 32

	// route2MaskModulus 取自主仓 gateway/tee-infer-service/route2step/errors.go:24：
	// const Route2MaskModulus uint64 = ^uint64(0)；step_exec.go:70/90/337 使用该常量。
	route2MaskModulus = ^uint64(0) // 18446744073709551615

	// largeModulus 用于覆盖 r > 2^63 的拒绝采样边界（主仓 mask.go:98 注释的坑）。
	largeModulus = (uint64(1) << 63) + 1 // 9223372036854775809

	goldenCount = 64
)

// zeroBytes 就地清零敏感字节。
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// hmacPRG 是 profile 无关的 HMAC-SHA256 PRG，逐字节复刻主仓 cipher/mask.hmacPRG。
type hmacPRG struct {
	key    []byte
	domain []byte
	ctr    uint64
}

func newHMACPRG(key, domain []byte) (*hmacPRG, error) {
	if len(key) < minSeedLen {
		return nil, fmt.Errorf("mask: seed length %d below minimum %d", len(key), minSeedLen)
	}
	return &hmacPRG{
		key:    append([]byte(nil), key...),
		domain: append([]byte(nil), domain...),
		ctr:    0,
	}, nil
}

// Keystream 输出 concat_{ctr=0..} HMAC-SHA256(key, BE64(ctr)||domain)[:8]，截断到 n 字节。
func (g *hmacPRG) Keystream(n int) []byte {
	if n <= 0 {
		return nil
	}
	out := make([]byte, 0, n+8)
	var ctr [8]byte
	for len(out) < n {
		binary.BigEndian.PutUint64(ctr[:], g.ctr)
		mac := hmac.New(sha256.New, g.key)
		_, _ = mac.Write(ctr[:])
		if len(g.domain) > 0 {
			_, _ = mac.Write(g.domain)
		}
		sum := mac.Sum(nil)
		out = append(out, sum[:8]...)
		g.ctr++
	}
	return out[:n]
}

func (g *hmacPRG) zeroize() {
	zeroBytes(g.key)
	zeroBytes(g.domain)
	g.key = nil
	g.domain = nil
	g.ctr = 0
}

// Stream 是掩码流，逐字节复刻主仓 cipher/mask.Stream（去掉 mutex 与 Provider 路径）。
type Stream struct {
	prg *hmacPRG
	r   uint64
	buf []byte
}

// NewStreamDomain 以 seed / r / domain 构造掩码流，校验 r>=2 且 seed 长度 >= 32。
func NewStreamDomain(seed []byte, r uint64, domain []byte) (*Stream, error) {
	if r < 2 {
		return nil, fmt.Errorf("mask: modulus R must be >= 2")
	}
	g, err := newHMACPRG(seed, domain)
	if err != nil {
		return nil, err
	}
	return &Stream{prg: g, r: r}, nil
}

// Next 返回下一个 [0, r) 掩码元素，使用主仓 L89 的拒绝采样阈值。
func (s *Stream) Next() uint64 {
	threshold := ^uint64(0) - (^uint64(0) % s.r)
	for {
		for len(s.buf) < 8 {
			s.buf = append(s.buf, s.prg.Keystream(64)...)
		}
		v := binary.BigEndian.Uint64(s.buf[:8])
		s.buf = s.buf[8:]
		if v < threshold {
			return v % s.r
		}
	}
}

// Fill 逐元素调用 Next 填充 buf。
func (s *Stream) Fill(buf []uint64) error {
	if len(buf) == 0 {
		return nil
	}
	if s.prg == nil {
		return fmt.Errorf("mask: stream already zeroized")
	}
	for i := range buf {
		buf[i] = s.Next()
	}
	return nil
}

// Modulus 返回掩码模 R。
func (s *Stream) Modulus() uint64 { return s.r }

// Zeroize 清零 key / domain / buf，调用后不可再使用。
func (s *Stream) Zeroize() {
	if s.prg != nil {
		s.prg.zeroize()
	}
	s.prg = nil
	zeroBytes(s.buf)
	s.buf = nil
}

// referenceSequence 是独立的第二份实现：不经 Stream 缓冲与 hmacPRG.ctr，
// 直接从候选下标 k 重算 HMAC 并做同一拒绝采样，用于自检确定性与阈值口径。
func referenceSequence(seed []byte, r uint64, domain []byte, n int) ([]uint64, error) {
	if r < 2 {
		return nil, fmt.Errorf("reference: modulus R must be >= 2")
	}
	if len(seed) < minSeedLen {
		return nil, fmt.Errorf("reference: seed length %d below minimum %d", len(seed), minSeedLen)
	}
	if n < 0 {
		return nil, fmt.Errorf("reference: negative count %d", n)
	}
	threshold := ^uint64(0) - (^uint64(0) % r)
	out := make([]uint64, 0, n)
	var ctr [8]byte
	var k uint64
	for len(out) < n {
		binary.BigEndian.PutUint64(ctr[:], k)
		mac := hmac.New(sha256.New, seed)
		_, _ = mac.Write(ctr[:])
		if len(domain) > 0 {
			_, _ = mac.Write(domain)
		}
		sum := mac.Sum(nil)
		v := binary.BigEndian.Uint64(sum[:8])
		k++
		if v < threshold {
			out = append(out, v%r)
		}
	}
	return out, nil
}

type goldenCase struct {
	name   string
	seed   []byte
	r      uint64
	domain []byte
	n      int
}

// fixedSeed 返回 32 字节可复现常量 0x00,0x01,...,0x1f。
func fixedSeed() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// goldenCases 定义 3 类用例：基准序列 / 同 seed 不同 domain 域分离 / r>2^63 拒绝采样边界。
func goldenCases() []goldenCase {
	return []goldenCase{
		{name: "base", seed: fixedSeed(), r: route2MaskModulus, domain: []byte("base"), n: goldenCount},
		{name: "domain_sep", seed: fixedSeed(), r: route2MaskModulus, domain: []byte("domain-sep"), n: goldenCount},
		{name: "large_modulus", seed: fixedSeed(), r: largeModulus, domain: []byte("large"), n: goldenCount},
	}
}

func sequenceFor(c goldenCase) ([]uint64, error) {
	s, err := NewStreamDomain(c.seed, c.r, c.domain)
	if err != nil {
		return nil, err
	}
	out := make([]uint64, c.n)
	if err := s.Fill(out); err != nil {
		return nil, err
	}
	if s.Modulus() != c.r {
		return nil, fmt.Errorf("Modulus() = %d, want %d", s.Modulus(), c.r)
	}
	s.Zeroize()
	return out, nil
}

// runSelfCheck 用固定 seed/r/domain 生成 N 个值，与独立第二份实现逐字节比对，
// 并重复生成一次确认确定性；全部通过打印 GEN_SELFCHECK PASS。
func runSelfCheck() error {
	cases := goldenCases()
	for _, c := range cases {
		got, err := sequenceFor(c)
		if err != nil {
			return fmt.Errorf("case %s: stream: %w", c.name, err)
		}
		want, err := referenceSequence(c.seed, c.r, c.domain, c.n)
		if err != nil {
			return fmt.Errorf("case %s: reference: %w", c.name, err)
		}
		if len(got) != len(want) {
			return fmt.Errorf("case %s: length %d != %d", c.name, len(got), len(want))
		}
		for i := range got {
			if got[i] != want[i] {
				return fmt.Errorf("case %s: value %d mismatch got=%016x want=%016x", c.name, i, got[i], want[i])
			}
		}
		again, err := sequenceFor(c)
		if err != nil {
			return fmt.Errorf("case %s: second run: %w", c.name, err)
		}
		for i := range got {
			if got[i] != again[i] {
				return fmt.Errorf("case %s: non-deterministic at %d", c.name, i)
			}
		}
		fmt.Printf("  case %-14s n=%d r=%d domain=%s: %d values match independent reference\n",
			c.name, c.n, c.r, hex.EncodeToString(c.domain), len(got))
	}
	// 校验构造器的 fail-closed 行为（r<2 与短 seed）。
	if _, err := NewStreamDomain(fixedSeed(), 1, nil); err == nil {
		return fmt.Errorf("expected error for r<2")
	}
	if _, err := NewStreamDomain([]byte{0x01}, route2MaskModulus, nil); err == nil {
		return fmt.Errorf("expected error for short seed")
	}
	// 域分离：base 与 domain_sep 必须产生不同序列。
	base, err := sequenceFor(cases[0])
	if err != nil {
		return err
	}
	sep, err := sequenceFor(cases[1])
	if err != nil {
		return err
	}
	diff := 0
	for i := range base {
		if base[i] != sep[i] {
			diff++
		}
	}
	if diff == 0 {
		return fmt.Errorf("domain separation failed: identical sequences")
	}
	fmt.Printf("  domain separation: %d/%d values differ\n", diff, len(base))
	fmt.Println("GEN_SELFCHECK PASS")
	return nil
}

func parseHex(s, label string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid hex %q: %w", label, s, err)
	}
	return b, nil
}

func parseUint(s, label string) (uint64, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid uint64 %q: %w", label, s, err)
	}
	return v, nil
}

func defaultVerifyCmd() string {
	return "cd <MAIN_REPO> && go run ../masked-infer/scripts/verify_golden_against_main.go -golden ../masked-infer/masklite/testdata/stream.golden"
}

func writeHeader(w *bufio.Writer, genCmd, mainCommit, verifyCmd string, cases []goldenCase) error {
	base := cases[0]
	names := make([]string, 0, len(cases))
	for _, c := range cases {
		names = append(names, c.name)
	}
	lines := []string{
		"# schema: masked-infer/g2-stream-golden/v1",
		fmt.Sprintf("# params: seed=%s modulus=%d domain=%s count=%d",
			hex.EncodeToString(base.seed), base.r, hex.EncodeToString(base.domain), base.n),
		fmt.Sprintf("# gen_cmd: %s", genCmd),
		"# gen_impl: scripts/gen_stream_golden.go（纯标准库 HMAC-SHA256，逐字节复刻主仓 cipher/mask.hmacPRG + Stream.Next）",
		fmt.Sprintf("# main_commit: %s", mainCommit),
		"# main_anchor: cipher/mask/mask.go:57 NewStreamDomain / hmacPRG（T-5.3-8 / TestHMACPRGMatchesLegacy）",
		fmt.Sprintf("# main_modulus_source: gateway/tee-infer-service/route2step/errors.go:24 Route2MaskModulus=^uint64(0)=%d（step_exec.go:70/90/337 使用）", route2MaskModulus),
		fmt.Sprintf("# large_modulus: %d = (1<<63)+1 > 2^63（主仓 mask.go:98 拒绝采样边界注释）", largeModulus),
		fmt.Sprintf("# verify_cmd: %s", verifyCmd),
		"# change_ctl: 主仓 cipher/mask 的 Stream/hmacPRG/Next 变更 → 重跑 gen_cmd 并同步本文件，两侧同批评审",
		"# algorithm: candidate_k=HMAC-SHA256(seed, BE64(k)||domain)[:8] → BE64 → threshold=^uint64(0)-(^uint64(0)%r) 拒绝采样 → v%r",
		fmt.Sprintf("# cases: %s", strings.Join(names, " | ")),
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

func writeGolden(path, genCmd, mainCommit, verifyCmd string, cases []goldenCase) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()
	w := bufio.NewWriter(f)
	if err := writeHeader(w, genCmd, mainCommit, verifyCmd, cases); err != nil {
		return err
	}
	for _, c := range cases {
		values, err := sequenceFor(c)
		if err != nil {
			return fmt.Errorf("case %s: %w", c.name, err)
		}
		if _, err := fmt.Fprintf(w, "case=%s seed=%s r=%d domain=%s n=%d\n",
			c.name, hex.EncodeToString(c.seed), c.r, hex.EncodeToString(c.domain), c.n); err != nil {
			return err
		}
		for i, v := range values {
			if _, err := fmt.Fprintf(w, "%d %016x\n", i, v); err != nil {
				return err
			}
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	return f.Sync()
}

func main() {
	selfcheck := flag.Bool("selfcheck", false, "运行确定性自检并输出 GEN_SELFCHECK PASS")
	golden := flag.Bool("golden", false, "生成完整 3 类用例的 G2 golden 文件")
	seedHex := flag.String("seed", "", "单用例模式的 seed（hex）")
	rText := flag.String("r", strconv.FormatUint(route2MaskModulus, 10), "模 R（uint64 十进制）")
	domainHex := flag.String("domain", "", "域分离标签（hex，可为空）")
	n := flag.Int("n", goldenCount, "每用例输出元素个数")
	out := flag.String("out", "", "输出文件路径")
	mainCommit := flag.String("main-commit", "", "主仓 HEAD 的 40 位 hex（golden 模式必填）")
	verifyCmd := flag.String("verify-cmd", "", "真机复核命令（golden 模式写入头部）")
	flag.Parse()

	if *selfcheck {
		if err := runSelfCheck(); err != nil {
			fmt.Fprintf(os.Stderr, "GEN_SELFCHECK FAIL: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "gen_stream_golden: -out is required")
		os.Exit(2)
	}
	if *n < 1 {
		fmt.Fprintln(os.Stderr, "gen_stream_golden: -n must be >= 1")
		os.Exit(2)
	}
	r, err := parseUint(*rText, "-r")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *verifyCmd == "" {
		*verifyCmd = defaultVerifyCmd()
	}

	var cases []goldenCase
	var genCmd string
	if *golden {
		if len(*mainCommit) != 40 {
			fmt.Fprintf(os.Stderr, "gen_stream_golden: -main-commit must be 40 hex chars, got %d\n", len(*mainCommit))
			os.Exit(2)
		}
		if _, err := parseHex(*mainCommit, "-main-commit"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		cases = goldenCases()
		genCmd = fmt.Sprintf("GO111MODULE=off go run scripts/gen_stream_golden.go -golden -main-commit %s -verify-cmd '%s' -out %s",
			*mainCommit, *verifyCmd, *out)
	} else {
		if *seedHex == "" {
			fmt.Fprintln(os.Stderr, "gen_stream_golden: -seed is required in single-case mode (or use -golden)")
			os.Exit(2)
		}
		seed, err := parseHex(*seedHex, "-seed")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		domain, err := parseHex(*domainHex, "-domain")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		cases = []goldenCase{{name: "single", seed: seed, r: r, domain: domain, n: *n}}
		genCmd = fmt.Sprintf("GO111MODULE=off go run scripts/gen_stream_golden.go -seed %s -r %d -domain %s -n %d -out %s",
			*seedHex, r, *domainHex, *n, *out)
	}

	if err := writeGolden(*out, genCmd, *mainCommit, *verifyCmd, cases); err != nil {
		fmt.Fprintf(os.Stderr, "gen_stream_golden: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("GOLDEN WRITTEN: %s (%d cases x %d values)\n", *out, len(cases), cases[0].n)
}
