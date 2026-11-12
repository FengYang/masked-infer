//go:build !cgo

// accel_dispatch_nocgo.go — 无 CGO 时的回退桩。
//
// 当构建环境禁用 CGO（CGO_ENABLED=0，或交叉编译无 C 工具链）时，无法用 dlopen 加载
// 加速后端 .so；此时 AccelLinearInt128 恒返回 ErrAccelUnavailable，调用方须回退到
// CPU 路径 CipherLinearInt128（int128_linear.go）。与 cgo 版本（accel_dispatch.go）
// 共享同一符号与语义，保证调用方代码无需感知构建差异。
//
// M5-1 池化版：AcquireAccelBackend / AccelLinearInt128Via 与 cgo 版同名导出（API 对齐），
// 无 CGO 时恒回退；池类型本身仅存在于 cgo 构建档。

package maskedinfer

import (
	"errors"
)

// ErrAccelUnavailable 与 cgo 版本一致：加速后端不可用，请回退 CPU 路径。
var ErrAccelUnavailable = errors.New("maskedinfer: 加速后端不可用（CGO 禁用），请回退 CPU 路径 CipherLinearInt128")

// AccelBackend 与 cgo 版同名导出；无 CGO 时无实际后端（恒回退），字段无意义。
type AccelBackend struct{}

// Key 返回空串（无 CGO 时无后端键）。
func (b *AccelBackend) Key() string { return "" }

// InitAccelBackend 在禁用 CGO 时为空操作，仅返回指示不可用的错误。
func InitAccelBackend(paths ...string) error {
	return ErrAccelUnavailable
}

// AcquireAccelBackend 与 cgo 版同名导出；无 CGO 时恒返回 ErrAccelUnavailable。
func AcquireAccelBackend(hint string) (*AccelBackend, error) {
	return nil, ErrAccelUnavailable
}

// AccelLinearInt128 在禁用 CGO 时恒返回 ErrAccelUnavailable。
func (m *QuantizedMatrix) AccelLinearInt128(V [][]uint64) ([][]uint64, error) {
	return nil, ErrAccelUnavailable
}

// AccelLinearInt128Via 与 cgo 版同名导出；无 CGO 时恒返回 ErrAccelUnavailable。
func (m *QuantizedMatrix) AccelLinearInt128Via(hint string, V [][]uint64) ([][]uint64, error) {
	return nil, ErrAccelUnavailable
}

// resetAccelStateForTest 无 CGO 时无一次性加载状态，空操作（与 cgo 版同签名，供测试共用）。
func resetAccelStateForTest() {}
