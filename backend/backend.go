// Package backend 定义并落地方案 §4.2 的「消费接口」MaskedInferenceBackend。
//
// 依赖方向（方案 §2）：网关（①）→ 路线2（本仓库）。接口定义在本仓库，由网关导入消费之；
// 不在网关侧定义（否则形成 路线2→网关 反向依赖，违反 INV-3 / G1）。
//
// 本包仅做「薄接入层」：生产路径直接复用 adapters/qwen 已数值锁定的真实权重前向
// （ForwardMaskedEmb，见 adapters/qwen/forward.go），不重新实现掩码像数学，避免分叉。
// 网关侧集成测试通过 NewBackendWithWeights 注入已加载权重即可端到端跑通（免真实模型）。
package backend

import (
	"context"

	"github.com/FengYang/masked-infer/adapters/qwen"
)

// MaskedVec 掩码态向量：落在 mod 2^64 整数环（uint64），非明文 float64。
//
// 网关用 Embedding(明文) → ToMaskDomain(×Scale) → OTP 加掩 r 后，以 MaskedVec 传入；
// 后端全程只见掩码整数，返回同环域的掩码末层隐状态（见方案 §4.2 缩放域契约）。
type MaskedVec []uint64

// ModelSpec 后端模型规格（方案 §4.2 草拟接口 ModelSpec 的落地版）。
// 字段取自 qwen.QwenConfig；网关据此做维度校验与 eager check。
type ModelSpec struct {
	Dim       int // hidden_size
	Vocab     int // vocab_size
	Layers    int // num_hidden_layers
	Heads     int // num_attention_heads
	KVHeads   int // num_key_value_heads（GQA）
	HeadDim   int // per-head 维
	FFN       int // intermediate_size（SwiGLU 中间宽）
	MaxTokens int // 单会话最大位置数
}

// MaskedInferenceBackend 网关（①）消费路线2 的唯一契约。
//
// 契约要点（方案 §4.2 / §7，防缩放域坑复发）：
//   - 缩放域一致：输入/输出均处于 ToMaskDomain 缩放后的整数环域；网关在 Unmask+Decode 后须 ÷Embed.Scale 还原，
//     否则 hidden 被放大致前向崩坏。
//   - OTP r 生命周期：r 由网关每序列生成、留存于可信域；prefill 与 decode 多步须复用同一 r
//     （掩码态 KV 在后端以该 r 加掩）；后端对 r 无状态——rGW 随每次 ForwardMasked 传入，不存储。
//   - 不携带 Tokenizer / Embedding / LMHead / argmax（INV-1）。
type MaskedInferenceBackend interface {
	// Config 返回后端模型规格。
	Config() ModelSpec
	// ForwardMasked 掩码域前向。maskedEmb 每行须为 ToMaskDomain 已缩放 + OTP 加掩的整数（长度=Dim）；
	// rGW 为本次序列的 OTP 掩码（长度=Dim），后端对其无状态。
	// 返回同缩放环域的掩码 hidden（长度=Dim 每行），网关须 Unmask→Decode→÷Embed.Scale 后才做 LMHead。
	ForwardMasked(ctx context.Context, maskedEmb []MaskedVec, rGW MaskedVec) ([]MaskedVec, error)
	// Close 释放后端持有的资源（权重/加速器句柄）；幂等。
	Close() error
}

// qwenBackend 形态A 实现：包裹 adapters/qwen 的真实权重前向（已数值锁定，见 golden）。
//
// 不持有 accelBackend 字段：加速后端（CUDA / 昇腾）选择属于**部署期**关切，
// 经环境变量 ACCEL_BACKEND_LIB（逗号分隔候选 .so 路径）在首次掩码线性调用时
// 惰性 dlopen（见 core/accel_dispatch.go），保持对硬件厂商中立（§4.1 全国产友好）。
// 构造器不传厂商参数，避免把"昇腾当事后补丁"或锁定单厂商。
type qwenBackend struct {
	w *qwen.Weights
}

func (b *qwenBackend) Config() ModelSpec {
	c := b.w.Cfg
	return ModelSpec{
		Dim:       c.Dim,
		Vocab:     c.Vocab,
		Layers:    c.Layers,
		Heads:     c.Heads,
		KVHeads:   c.KVHeads,
		HeadDim:   c.HeadDim,
		FFN:       c.FFN,
		MaxTokens: c.MaxTokens,
	}
}

func (b *qwenBackend) ForwardMasked(ctx context.Context, maskedEmb []MaskedVec, rGW MaskedVec) ([]MaskedVec, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	in := make([][]uint64, len(maskedEmb))
	for i := range maskedEmb {
		in[i] = maskedEmb[i]
	}
	out, err := qwen.ForwardMaskedEmb(b.w, in, rGW)
	if err != nil {
		return nil, err
	}
	res := make([]MaskedVec, len(out))
	for i := range out {
		res[i] = out[i]
	}
	return res, nil
}

// Close 释放后端持有的资源。当前 CPU 形态权重为纯 Go 内存（由 GC 回收），
// 无外部句柄须显式释放；待 CUDA/昇腾加速后端（core/accel_dispatch.go 的 .so 句柄）
// 落地时，此处须真正 Close 句柄并保证幂等。
func (b *qwenBackend) Close() error { return nil }

// NewBackend 由真实权重目录构造后端（形态A）。
//
// 加速后端（CUDA / 昇腾）选择属于**部署期**关切：经环境变量 ACCEL_BACKEND_LIB
// （逗号分隔候选 .so 路径）在首次掩码线性调用时惰性 dlopen（见 core/accel_dispatch.go），
// 不由本构造器传入——保持对硬件厂商中立（§4.1 全国产友好）。
func NewBackend(modelPath string) (MaskedInferenceBackend, error) {
	w, err := qwen.LoadWeights(modelPath, qwen.Qwen3_06B())
	if err != nil {
		return nil, err
	}
	return &qwenBackend{w: w}, nil
}

// NewBackendWithWeights 包裹已加载的 *qwen.Weights（供嵌入部署 / 单元测试 / 自包含场景使用）。
// 这是网关集成测试经 go.work 接回消费本接口的主入口（免下载真实模型）。
func NewBackendWithWeights(w *qwen.Weights) MaskedInferenceBackend {
	return &qwenBackend{w: w}
}

// 编译期接口断言：qwenBackend 满足 MaskedInferenceBackend。
var _ MaskedInferenceBackend = (*qwenBackend)(nil)
