package masklite

import "runtime"

// memzeroBytes 覆盖清零字节切片。
//
// 语义与主仓 internal/memzero.Bytes 一致（逐字节置零 + KeepAlive 阻止编译器优化掉）。
// 架构师实测 cipher/mask/mask.go 只调用 memzero.Bytes，Uint64/String 从未被调用，
// 故此处仅实现 Bytes 一个同包内部函数（不导出），避免搬运无用代码。
func memzeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
