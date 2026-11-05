package masklite

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

// MinSeedLen 种子最小长度（字节）。
// 256 位种子与 HMAC-SHA256 输出强度对齐，满足现代密码学与量子安全余量要求。
const MinSeedLen = 32

// PRG 确定性伪随机流生成器（P0-4 §5.3.2）：生成 n 字节确定性流。
//
// 实现：本包只提供 hmacPRG（profile 无关的 HMAC-SHA256 PRG）。
// profile 绑定的实现（intl=HMAC-SHA256 / sm=SM4-CTR，经主仓密码 provider）
// 不在本包，留在主仓 `cipher/mask`；本包不依赖任何密钥/证明设施。
//
// 调用方按 §5.3.2「PRG 选择点表」选构造器。
type PRG interface {
	Keystream(n int) []byte
}

// Stream 基于 PRG 的确定性掩码流（P0-4 §5.3.2 字段重设计）。
//
// 每个元素 = 从 prg 取 8 字节 → 拒绝采样映射到 [0, r)，保证均匀性
// （对应论文 PRG(s_u,v) 掩码扩展）。拒绝采样逻辑与现役实现逐字节一致。
//
// 并发安全：内部互斥锁保护状态，可安全跨 goroutine 复用。
// 生命周期：单个 Stream 最多产生 2^64 个元素，超出后行为未定义。
type Stream struct {
	mu  sync.Mutex
	prg PRG    // v1.3 N2-P3-1：删既有 seed/ctr/domain/mac，改持有 prg
	r   uint64 // 掩码模 R
	buf []byte // 待消费的确定性流字节（不足 8 字节时向 prg 补充）
}

// NewStream 以 seed 构造 [0, r) 上的掩码流（无域分离，HMAC-SHA256 PRG）。
func NewStream(seed []byte, r uint64) (*Stream, error) {
	return NewStreamDomain(seed, r, nil)
}

// NewStreamDomain 以 seed 构造 [0, r) 上的掩码流，并绑定域分离标签（**HMAC-SHA256 构造器**）。
//
// 内部即 hmacPRG（profile 无关）——intl 默认与 sm 桥接（`mask_prg=bridge` 的 hmac 格）共用。
// **签名不变**（与既有参数序 `(seed, r, domain)` 一致，v1.3 订正 N2-P1-1）且**行为逐字节保持**
// （candidate_k = HMAC-SHA256(seed, BE64(k)‖domain) 前 8 字节），保 intl 灰度滚动升级兼容。
//
// domain 用于区分同一种子在不同用途下派生的掩码流（如自掩码 b_u 与成对掩码 seed_{v,u}
// 使用不同 domain），防止跨用途掩码流碰撞。不同用途必须传入不同的非空 domain。
func NewStreamDomain(seed []byte, r uint64, domain []byte) (*Stream, error) {
	if r < 2 {
		return nil, errors.New("mask: modulus R must be >= 2")
	}
	g, err := newHMACPRG(seed, domain)
	if err != nil {
		return nil, err
	}
	return &Stream{prg: g, r: r}, nil
}

// Next 返回下一个 [0, r) 掩码元素（拒绝采样保证均匀）。
func (s *Stream) Next() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	threshold := ^uint64(0) - (^uint64(0) % s.r)
	for {
		for len(s.buf) < 8 {
			s.buf = append(s.buf, s.prg.Keystream(64)...)
		}
		v := binary.BigEndian.Uint64(s.buf[:8])
		s.buf = s.buf[8:]
		// 拒绝采样：丢弃使分布偏移的最高区间。
		// 标准公式：threshold = 2^64 - (2^64 mod r)，接受 v < threshold。
		// 注意：不能用 (2^64-1-r+1)/r*r 的写法，r > 2^63 时该式为 0 导致无限循环。
		if v < threshold {
			return v % s.r
		}
		// v >= threshold：丢弃，续取下 8 字节重试
	}
}

// Fill 填充 buf 的前 n 个掩码元素。
func (s *Stream) Fill(buf []uint64) error {
	if len(buf) == 0 {
		return nil
	}
	for i := range buf {
		buf[i] = s.Next()
	}
	return nil
}

// Modulus 返回掩码模 R。
func (s *Stream) Modulus() uint64 { return s.r }

// Zeroize 清零敏感内存（种子/密钥与缓冲），释放锁后调用。
// 调用后 Stream 不可再使用。
func (s *Stream) Zeroize() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if z, ok := s.prg.(interface{ zeroize() }); ok {
		z.zeroize()
	}
	s.prg = nil
	memzeroBytes(s.buf)
	s.buf = nil
}

// MaskStream 是掩码流的最小契约：阶段 3 CA-3 用它替换主仓 route2step 里写死的 *mask.Stream。
//
// 方法集必须与 *Stream 逐方法对齐（Next/Fill/Modulus/Zeroize），不多不少。
type MaskStream interface {
	Next() uint64
	Fill(buf []uint64) error
	Modulus() uint64
	Zeroize()
}

// 编译期断言：*Stream 满足 MaskStream（CA-3 契约冻结物）。
var _ MaskStream = (*Stream)(nil)

// ---------- hmacPRG：profile 无关的 HMAC-SHA256 PRG ----------

// hmacPRG 直接绑 crypto/hmac+sha256，**复现 cipher/mask 现役算法**。
//
// **存在理由（N-P0-2）**：profile 绑定的 Keystream（sm 只产 SM4）由主仓密码 provider 承担；
// 而 `hmac-sha256` 路径（intl 默认 + sm 桥接）需产 HMAC-SHA256 流 ⇒ 本包只承载这条
// profile 无关路径。**这是 provider 之外的唯一例外**（§9.1 边界）：仅 Go 服务/sidecar 使用；
// wasm 插件禁止引用（仍经 `/v1/mask/stream`）。
type hmacPRG struct {
	key    []byte
	domain []byte
	ctr    uint64
}

func newHMACPRG(key, domain []byte) (*hmacPRG, error) {
	if len(key) < MinSeedLen {
		return nil, fmt.Errorf("mask: seed length %d below minimum %d", len(key), MinSeedLen)
	}
	return &hmacPRG{
		key:    append([]byte(nil), key...),
		domain: append([]byte(nil), domain...),
	}, nil
}

// Keystream 输出 = concat_{k=0..} HMAC-SHA256(key, BE64(ctr+k)‖domain)[:8]，截断到 n 字节。
// 与主仓 `cipher/mask` 的 hmacPRG 逐字节等价（T-5.3-8）；跨实现等价由 G2 golden
// 与主仓侧 `verify_golden_against_main.go` 双向校验。
func (g *hmacPRG) Keystream(n int) []byte {
	if n <= 0 {
		return nil
	}
	out := make([]byte, 0, n+8)
	var ctr [8]byte
	for len(out) < n {
		binary.BigEndian.PutUint64(ctr[:], g.ctr)
		mac := hmac.New(sha256.New, g.key)
		_, _ = mac.Write(ctr[:]) // hash.Hash.Write 按规范永不返回错误
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
	memzeroBytes(g.key)
	memzeroBytes(g.domain)
	g.key = nil
	g.domain = nil
}
