//go:build cgo

// accel_dispatch.go — 掩码线性加速后端（CUDA / 华为昇腾）运行时派发【M5-1 池化版】。
//
// 设计（路线2 步骤③ 多后端统一架构 + 网关侧缺口整改 M5-1）：
//   - 网关侧不感知硬件厂商；按部署环境（env ACCEL_BACKEND_LIB，逗号分隔受信绝对路径候选）
//     构建 AccelPool，per-key 惰性 dlopen 对应 .so（libaccel_cuda.so / libaccel_ascend.so），
//     并解析统一的 C ABI 符号 accel_cipher_linear_int128（见 accel_linear_int128.h）。
//   - 池化语义（技术实现方案 §4）：
//       · 多后端可同时加载（池内 N 个 .so），按 key（= 受信绝对路径）选择（Acquire(hint)）；
//       · 候选序（order）来自 ACCEL_BACKEND_LIB / InitAccelBackend，作为默认与回退序；
//       · 默认行为（hint=""）与旧版 sync.Once 一次性加载完全等价：按序首个可用者胜出，
//         全部失败缓存错误（不重试），AccelLinearInt128 返回 ErrAccelUnavailable 由调用方回退 CPU；
//       · per-key 单飞加载（loadMu 序列化 + 双重检查），并发安全（-race 全绿）；
//       · 不做 dlclose（函数指针与句柄进程生命周期内常驻，与旧版一致，避免符号卸载风险）。
//   - 安全约束不放松（Sec-C1）：池内每个成员仍须经 validateAccelLibPath（绝对路径/普通文件/
//     非符号链接/group·other 不可写），且 ABI 版本须与 accelLinearInt128ABIVersion 一致；
//     hint 仅接受候选列表内的 key（信任输入不变，禁止运行期注入任意路径）。
//   - 回滚开关（技术实现方案 §4.5）：env ACCEL_POOL=off → 禁用运行期多后端选择
//     （Acquire(hint≠"") 拒绝），默认候选序回退行为与旧实现一致；或直接回退 masked-infer
//     版本（两仓版本解耦，网关 go.mod pin）。
//   - 后端不可用（未配置 / 加载失败 / 调用失败）时，AccelLinearInt128 返回
//     ErrAccelUnavailable，调用方应回退到 CPU 路径 CipherLinearInt128（int128_linear.go）。
//   - 算法正确性已由 CipherLinearInt128 与 math/big 神谕逐位对拍锁定，各加速后端仅替换执行后端。
//
// 本文件仅在 CGO 可用时编译；无 CGO 时由 accel_dispatch_nocgo.go 提供恒回退桩。

package maskedinfer

/*
#include <stdint.h>
#include <dlfcn.h>
#include <stdlib.h>

typedef int (*accel_fn_t)(const int8_t* W, const int64_t* bias, const uint64_t* V, int rows, int cols, uint64_t* out, int batch);
typedef int (*abi_fn_t)(void);

// 从给定路径加载加速后端 .so，解析统一符号 accel_cipher_linear_int128，
// 并校验 ABI 版本（required_abi 为网关侧期望版本，须与后端 accel_cipher_linear_int128_abi_version 一致）。
// 成功时 *out_fn 置为主符号函数指针（句柄与符号进程内常驻，不做 dlclose）。
// 返回 0 成功；-1 dlopen 失败；-2 主符号缺失；-3 路径/出参为空；-4 ABI 版本符号缺失；-5 ABI 版本不匹配。
// 失败路径上的句柄立即 dlclose（不留悬挂句柄）。
static int maskedinfer_load_accel(const char* path, int required_abi, void** out_fn) {
    if (out_fn == NULL) return -3;
    if (path == NULL || *path == '\0') return -3;
    void* h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (h == NULL) return -1;
    void* sym = dlsym(h, "accel_cipher_linear_int128");
    if (sym == NULL) { dlclose(h); return -2; }
    abi_fn_t abi_fn = (abi_fn_t)dlsym(h, "accel_cipher_linear_int128_abi_version");
    if (abi_fn == NULL) { dlclose(h); return -4; }
    if (abi_fn() != required_abi) { dlclose(h); return -5; }
    *out_fn = sym;
    return 0;
}

// 经指定后端函数指针调用加速内核；fn 为空返回 -9。
static int maskedinfer_call_accel_fn(void* fn, const int8_t* W, const int64_t* bias, const uint64_t* V, int rows, int cols, uint64_t* out, int batch) {
    if (fn == NULL) return -9;
    return ((accel_fn_t)fn)(W, bias, V, rows, cols, out, batch);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"
)

// ErrAccelUnavailable 表示加速后端不可用（未配置 .so / 加载失败 / 调用失败 / 权重越界 / ABI 版本不匹配），
// 调用方应回退到 CPU 路径 CipherLinearInt128。
var ErrAccelUnavailable = errors.New("maskedinfer: 加速后端不可用，请回退 CPU 路径 CipherLinearInt128")

// accelLinearInt128ABIVersion 是网关侧要求的加速后端 ABI 版本，须与
// accel_linear_int128.h 中 ACCEL_LINEAR_INT128_ABI_VERSION 保持一致。
const accelLinearInt128ABIVersion = 1

// AccelBackend 池内单个加速后端：key = 受信绝对路径（去空白），fn = 已解析的
// accel_cipher_linear_int128 函数指针（C ABI；句柄进程生命周期内常驻，不 dlclose）。
type AccelBackend struct {
	key string
	fn  unsafe.Pointer
}

// Key 返回后端键（受信绝对路径）。
func (b *AccelBackend) Key() string { return b.key }

// AccelPool 加速后端池：per-key 惰性加载（单飞），多后端并存，按候选序回退。
//
// 并发模型：
//   - loadMu：序列化 per-key 加载（加载为一次性事件，锁竞争可忽略）＝单飞；
//   - mu（RWMutex）：保护 backends / loadErrs / defaultKey / defaultErr / resolved；
//   - 加载在 loadMu 内执行，先 RLock 双重检查再 dlopen，重复 dlopen 同一路径
//     （若发生）亦无害（dlopen 引用计数，同句柄）。
type AccelPool struct {
	loadMu sync.Mutex

	mu         sync.RWMutex
	backends   map[string]*AccelBackend // key → 已加载后端（每 key 最多加载一次）
	loadErrs   map[string]error         // key → 加载失败缓存（确定性：失败不重试）
	order      []string                 // 候选序（ACCEL_BACKEND_LIB / Init 顺序；默认与回退序）
	defaultKey string                   // Acquire("") 解析出的默认后端
	defaultErr error                    // 默认解析失败缓存（等价旧版 accelLoadErr 缓存语义）
	resolved   bool                     // 默认解析是否已尝试（含失败）
	poolOff    bool                     // ACCEL_POOL=off：禁用运行期多后端选择（hint 拒绝）
}

// newAccelPool 构建池：candidates 为显式候选路径（空则回退 env ACCEL_BACKEND_LIB，逗号分隔）。
// off=true 时仍保留完整候选序（默认解析行为与旧实现一致），仅禁用 hint 选择。
func newAccelPool(candidates []string, off bool) *AccelPool {
	if len(candidates) == 0 {
		if env := os.Getenv("ACCEL_BACKEND_LIB"); env != "" {
			candidates = strings.Split(env, ",")
		}
	}
	order := make([]string, 0, len(candidates))
	for _, p := range candidates {
		if p = strings.TrimSpace(p); p != "" {
			order = append(order, p)
		}
	}
	return &AccelPool{
		backends: map[string]*AccelBackend{},
		loadErrs: map[string]error{},
		order:    order,
		poolOff:  off,
	}
}

func poolOffFromEnv() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("ACCEL_POOL")), "off")
}

// 全局默认池（首次使用时按 env 构建；resetAccelStateForTest 可重建）。
var (
	globalPoolOnce sync.Once
	globalPool     *AccelPool
)

func defaultPool() *AccelPool {
	globalPoolOnce.Do(func() { globalPool = newAccelPool(nil, poolOffFromEnv()) })
	return globalPool
}

// resetAccelStateForTest 仅供测试：重建全局池，使「未配置后端 → 回退」等分支
// 在单进程内可重复验证（生产路径不调用）。
func resetAccelStateForTest() {
	globalPoolOnce = sync.Once{}
	globalPool = newAccelPool(nil, poolOffFromEnv())
	globalPoolOnce.Do(func() {}) // 标记已初始化，避免 defaultPool() 二次重建覆盖
}

// loadKeyLocked 加载单个 key（须持 loadMu；RLock 双重检查防重复加载）。
// 成功缓存进 backends；失败（含路径校验拒绝）缓存进 loadErrs，不重试。
func (p *AccelPool) loadKeyLocked(key string) (*AccelBackend, error) {
	p.mu.RLock()
	if b, ok := p.backends[key]; ok {
		p.mu.RUnlock()
		return b, nil
	}
	if cached, ok := p.loadErrs[key]; ok {
		p.mu.RUnlock()
		return nil, cached
	}
	p.mu.RUnlock()

	var b *AccelBackend
	var err error
	if verr := validateAccelLibPath(key); verr != nil {
		// 安全校验（Sec-C1）：拒绝任意注入路径，仅允许受信绝对路径，
		// 且必须是普通文件、非符号链接、不被 group/other 写入，以防 TEE 进程内代码注入。
		err = fmt.Errorf("后端路径 %q 校验失败: %w", key, verr)
	} else {
		var fnPtr unsafe.Pointer
		cp := C.CString(key)
		rc := C.maskedinfer_load_accel(cp, C.int(accelLinearInt128ABIVersion), &fnPtr)
		C.free(unsafe.Pointer(cp))
		if rc == 0 {
			b = &AccelBackend{key: key, fn: fnPtr}
		} else {
			err = fmt.Errorf("后端路径 %q 加载失败 rc=%d（-1 dlopen/-2 主符号缺失/-3 路径空/-4 ABI符号缺失/-5 版本不匹配）", key, int(rc))
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if b != nil {
		p.backends[key] = b
		return b, nil
	}
	p.loadErrs[key] = err
	log.Printf("[accel] 后端加载失败（已缓存，不再重试；%d/%d 候选可用）: %v", len(p.backends), len(p.order), err)
	return nil, err
}

// get 惰性获取单个 key 的后端（loadMu 单飞）。
func (p *AccelPool) get(key string) (*AccelBackend, error) {
	p.loadMu.Lock()
	defer p.loadMu.Unlock()
	return p.loadKeyLocked(key)
}

// Acquire 按 hint 选择后端：
//   - hint 空：按 order 首个可用者（默认解析，结果缓存——与旧版 sync.Once 语义等价）；
//     全部候选失败/无候选 → ErrAccelUnavailable（CPU 回退语义不变）；
//   - hint 非空：必须是候选列表内的 key（信任输入不变，禁止运行期注入任意路径）；
//     ACCEL_POOL=off 时拒绝 hint。
func (p *AccelPool) Acquire(hint string) (*AccelBackend, error) {
	if hint != "" {
		if p.poolOff {
			return nil, fmt.Errorf("%w: ACCEL_POOL=off 已禁用运行期后端选择", ErrAccelUnavailable)
		}
		key := strings.TrimSpace(hint)
		p.mu.RLock()
		inOrder := false
		for _, k := range p.order {
			if k == key {
				inOrder = true
				break
			}
		}
		p.mu.RUnlock()
		if !inOrder {
			return nil, fmt.Errorf("%w: hint %q 不在候选列表（候选 %d 个）", ErrAccelUnavailable, key, len(p.order))
		}
		return p.get(key)
	}

	// 默认解析（缓存）。
	p.mu.RLock()
	if p.resolved {
		key, derr := p.defaultKey, p.defaultErr
		p.mu.RUnlock()
		if derr != nil {
			return nil, derr
		}
		return p.backends[key], nil
	}
	p.mu.RUnlock()

	p.loadMu.Lock()
	defer p.loadMu.Unlock()
	// 双重检查（另一 goroutine 可能已完成解析）。
	p.mu.RLock()
	if p.resolved {
		key, derr := p.defaultKey, p.defaultErr
		p.mu.RUnlock()
		if derr != nil {
			return nil, derr
		}
		return p.backends[key], nil
	}
	p.mu.RUnlock()

	var lastErr error
	for _, key := range p.order {
		b, err := p.loadKeyLocked(key)
		if err == nil {
			p.mu.Lock()
			p.defaultKey = key
			p.resolved = true
			p.mu.Unlock()
			return b, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("未配置加速后端 .so（候选 0 个）")
	}
	p.mu.Lock()
	p.defaultErr = fmt.Errorf("%w: %v", ErrAccelUnavailable, lastErr)
	p.resolved = true
	p.mu.Unlock()
	return nil, p.defaultErr
}

// SwitchDefaultBackend 运行期切换默认加速后端（M5-2 调度 API 的执行点）：
//   - hint 必须是候选列表内 key（信任输入不变），否则拒绝；
//   - 目标后端经 per-key 惰性加载 + 路径/ABI 校验后，原子换入默认解析结果；
//   - 换入后 Acquire("")/AccelLinearInt128 立即走新后端；评估中请求仍用已取得的旧后端句柄；
//   - 失败保持原默认后端不变（fail-safe）。
func (p *AccelPool) SwitchDefaultBackend(hint string) error {
	if p.poolOff {
		return fmt.Errorf("%w: ACCEL_POOL=off 已禁用运行期后端选择", ErrAccelUnavailable)
	}
	key := strings.TrimSpace(hint)
	if key == "" {
		return fmt.Errorf("%w: 切换 key 不可为空", ErrAccelUnavailable)
	}
	p.mu.RLock()
	inOrder := false
	for _, k := range p.order {
		if k == key {
			inOrder = true
			break
		}
	}
	p.mu.RUnlock()
	if !inOrder {
		return fmt.Errorf("%w: 切换目标 %q 不在候选列表（拒绝运行期注入任意路径）", ErrAccelUnavailable, key)
	}
	b, err := p.get(key)
	if err != nil {
		return fmt.Errorf("%w: 切换目标加载失败（保持原默认）: %v", ErrAccelUnavailable, err)
	}
	p.mu.Lock()
	p.defaultKey, p.defaultErr, p.resolved = b.key, nil, true
	p.mu.Unlock()
	return nil
}

// CurrentDefault 返回当前默认后端 key（空串 = 尚未解析/无可用后端）。
func (p *AccelPool) CurrentDefault() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.defaultKey
}

// Candidates 返回候选列表快照（安装期受信输入，供管理 API 只读展示）。
func (p *AccelPool) Candidates() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]string(nil), p.order...)
}

// SwitchDefaultBackend 全局池入口（M5-2 管理 API 调用）。
func SwitchDefaultBackend(hint string) error { return defaultPool().SwitchDefaultBackend(hint) }

// CurrentDefaultBackend 全局池当前默认后端 key。
func CurrentDefaultBackend() string { return defaultPool().CurrentDefault() }

// AccelCandidates 全局池候选列表快照。
func AccelCandidates() []string { return defaultPool().Candidates() }

// AcquireAccelBackend 全局池入口：按 hint 选择加速后端（hint 空 = 默认候选序首个可用）。
// 网关侧 route2step/adapter 可按请求上下文透传 hint（M5-2 调度 API 的落点；一期可全默认）。
func AcquireAccelBackend(hint string) (*AccelBackend, error) {
	return defaultPool().Acquire(hint)
}

// InitAccelBackend 由网关在启动时显式调用：以指定候选路径（按序尝试）初始化全局池；
// 为空时回退到环境变量 ACCEL_BACKEND_LIB（逗号分隔）。
// 首次调用生效（设定候选序并同步解析默认后端）；后续调用仅返回默认解析结果。
// 默认解析失败不致命：返回错误供调用方记录，后续 AccelLinearInt128 会返回
// ErrAccelUnavailable 由调用方回退 CPU 路径。
func InitAccelBackend(paths ...string) error {
	pool := defaultPool()
	pool.mu.Lock()
	if !pool.resolved {
		pool.order = normalizeCandidates(paths)
	}
	pool.mu.Unlock()
	_, err := pool.Acquire("")
	return err
}

// normalizeCandidates 规整候选列表（去空白、去空项）；空输入回退 env ACCEL_BACKEND_LIB。
func normalizeCandidates(candidates []string) []string {
	if len(candidates) == 0 {
		if env := os.Getenv("ACCEL_BACKEND_LIB"); env != "" {
			candidates = strings.Split(env, ",")
		}
	}
	order := make([]string, 0, len(candidates))
	for _, p := range candidates {
		if p = strings.TrimSpace(p); p != "" {
			order = append(order, p)
		}
	}
	return order
}

// validateAccelLibPath 对受信后端 .so 路径做最小安全校验（防 TEE 进程内任意代码注入）：
//   - 必须是绝对路径；
//   - 不得是符号链接（防 TOCTOU / 重定向到攻击者可控文件）；
//   - 必须是普通文件；
//   - 不得被 group/other 写入（防被替换）。
func validateAccelLibPath(p string) error {
	if !filepath.IsAbs(p) {
		return fmt.Errorf("非绝对路径（拒绝：仅允许受信绝对路径）")
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("Lstat 失败: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("拒绝符号链接（防 TOCTOU/重定向）")
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("非普通文件")
	}
	if fi.Mode().Perm()&0o022 != 0 { // 0o022 = group-write | other-write
		return fmt.Errorf("权限过宽（group/other 可写，存在被替换风险）")
	}
	return nil
}

// AccelLinearInt128 经默认加速后端（CUDA / 昇腾 Ascend）计算掩码线性层。
// 后端不可用或调用失败时返回 ErrAccelUnavailable，调用方应回退 CipherLinearInt128。
//
// 算术语义与 CipherLinearInt128（int128_linear.go）逐位一致：
//
//	y[b][i] = ( Σ_j W[i*cols+j] · V[b*cols+j] + bias[i] ) mod 2^64
func (m *QuantizedMatrix) AccelLinearInt128(V [][]uint64) ([][]uint64, error) {
	return m.AccelLinearInt128Via("", V)
}

// AccelLinearInt128Via 经 hint 指定的加速后端计算掩码线性层（M5-1 按请求选择；
// hint 空 = 默认候选序首个可用）。后端不可用或调用失败时返回 ErrAccelUnavailable，
// 调用方应回退 CipherLinearInt128。算术语义同 AccelLinearInt128。
func (m *QuantizedMatrix) AccelLinearInt128Via(hint string, V [][]uint64) ([][]uint64, error) {
	backend, err := defaultPool().Acquire(hint)
	if err != nil {
		return nil, ErrAccelUnavailable
	}
	return m.accelLinearWith(backend, V)
}

// accelLinearWith 经已 Acquire 的后端执行线性内核（AccelLinearInt128Via 的执行段）。
func (m *QuantizedMatrix) accelLinearWith(backend *AccelBackend, V [][]uint64) ([][]uint64, error) {
	// 后端仅支持 int8 量化权重：超出 [-128,127] 时 int8 截断会失真，
	// 返回 ErrAccelUnavailable 由调用方回退到 CPU 路径（CipherLinearInt128 用全 int64）。
	for _, v := range m.Data {
		if v < -128 || v > 127 {
			return nil, ErrAccelUnavailable
		}
	}
	batch := len(V)
	if batch == 0 {
		return [][]uint64{}, nil
	}
	for b, vec := range V {
		if len(vec) != m.Cols {
			return nil, fmt.Errorf("maskedinfer: 向量[%d]长度 %d != 列数 %d", b, len(vec), m.Cols)
		}
	}
	// 权重 int32 → int8（量化位宽 8，值必落在 [-128,127]）
	w8 := make([]int8, len(m.Data))
	for i, v := range m.Data {
		w8[i] = int8(v)
	}
	// 偏置 int32 → int64
	bias64 := make([]int64, m.Rows)
	if m.Bias != nil {
		for i := range bias64 {
			bias64[i] = int64(m.Bias[i])
		}
	}
	// 展平 V 为 [batch*cols]，与内核布局 V[b*cols+j] 一致
	flatV := make([]uint64, batch*m.Cols)
	for b := 0; b < batch; b++ {
		copy(flatV[b*m.Cols:(b+1)*m.Cols], V[b])
	}
	flatOut := make([]uint64, batch*m.Rows)

	rc := C.maskedinfer_call_accel_fn(
		backend.fn,
		(*C.int8_t)(unsafe.Pointer(&w8[0])),
		(*C.int64_t)(unsafe.Pointer(&bias64[0])),
		(*C.uint64_t)(unsafe.Pointer(&flatV[0])),
		C.int(m.Rows), C.int(m.Cols),
		(*C.uint64_t)(unsafe.Pointer(&flatOut[0])),
		C.int(batch),
	)
	if rc != 0 {
		return nil, fmt.Errorf("maskedinfer: 加速后端 %s 调用失败 rc=%d: %w", backend.key, int(rc), ErrAccelUnavailable)
	}
	out := make([][]uint64, batch)
	for b := 0; b < batch; b++ {
		row := make([]uint64, m.Rows)
		for i := 0; i < m.Rows; i++ {
			v := flatOut[b*m.Rows+i]
			if m.ModBits == Mod32 {
				// 后端按 mod 2^64 写入；Mod32 矩阵再按 2^32 归约（2^32 | 2^64，低 32 位即精确）。
				row[i] = v & 0xFFFFFFFF
			} else {
				row[i] = v
			}
		}
		out[b] = row
	}
	return out, nil
}
