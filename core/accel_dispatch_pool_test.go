//go:build cgo

// accel_dispatch_pool_test.go — M5-1 ACCEL 后端池化单测（技术实现方案 §4 验收判据）：
//   1. 多后端可同时加载，按 key（受信绝对路径）选择；「双后端切换、按请求选择、失败回退 CPU」；
//   2. ABI 校验不变：abi_version != 1 拒绝加载（rc -5），池回退下一候选；
//   3. 路径安全约束不变：符号链接 / group·other 可写 / 非普通文件 / 非绝对路径逐成员拒绝；
//   4. 默认行为与旧版 sync.Once 等价（候选序首个可用者胜出、失败缓存不重试）；
//   5. ACCEL_POOL=off 回滚开关：hint 拒绝、默认行为保持；
//   6. 并发安全：多 goroutine 混合 Acquire/AccelLinearInt128Via 无竞态（-race）。
//
// 夹具：以 core/cipher_linear_int128_ascend.cpp 的可移植 CPU 参考实现语义现编 .so
//（需 g++；不可用时跳过，语义与 CI/真机一致）。夹具语义与 Go CPU 基准逐位对拍锁定。

package maskedinfer

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

// poolFixtureSo 以夹具 C 源现编一个实现统一 ABI 的 .so（abiVersion 可注入非 1 制造 ABI 不匹配负例）。
func poolFixtureSo(t *testing.T, dir, name string, abiVersion int) string {
	t.Helper()
	if _, err := exec.LookPath("g++"); err != nil {
		t.Skip("g++ 不可用，跳过池化夹具测试（CI/真机具备 g++ 时必跑）")
	}
	src := filepath.Join(dir, "fixture_"+name+".cpp")
	// 语义严格对齐 accel_linear_int128.h：y[b][i]=(Σ W(int8→int64)·V + bias) mod 2^64，
	// 128 位中间累加（真值 < 2^84，低 64 位精确）。
	code := fmt.Sprintf(`#include <stdint.h>
extern "C" int accel_cipher_linear_int128_abi_version(void) { return %d; }
extern "C" int accel_cipher_linear_int128(const int8_t* W, const int64_t* bias, const uint64_t* V, int rows, int cols, uint64_t* out, int batch) {
    if (rows <= 0 || cols <= 0 || batch <= 0) return -2;
    for (int b = 0; b < batch; ++b)
        for (int i = 0; i < rows; ++i) {
            unsigned __int128 acc = 0;
            for (int j = 0; j < cols; ++j)
                acc += (unsigned __int128)(unsigned long long)(long long)W[i*cols+j] * (unsigned __int128)V[b*cols+j];
            acc += (unsigned __int128)(unsigned long long)bias[i];
            out[b*rows+i] = (uint64_t)acc;
        }
    return 0;
}
`, abiVersion)
	if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
		t.Fatalf("写夹具源失败: %v", err)
	}
	out := filepath.Join(dir, name)
	cmd := exec.Command("g++", "-shared", "-fPIC", "-O0", src, "-o", out)
	if blob, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("编译夹具 .so 失败: %v\n%s", err, blob)
	}
	// validateAccelLibPath 要求 group/other 不可写：0644 = rw-r--r--。
	if err := os.Chmod(out, 0o644); err != nil {
		t.Fatalf("chmod 夹具失败: %v", err)
	}
	return out
}

// randMatrixWithBias 构造随机 int8 权重 + 偏置矩阵（与既有 TestAccelDispatch 同构）。
func randMatrixWithBias(t *testing.T, rng *rand.Rand, rows, cols int) *QuantizedMatrix {
	t.Helper()
	w := make([][]float64, rows)
	for i := range w {
		w[i] = make([]float64, cols)
		for j := range w[i] {
			w[i][j] = (float64(rng.Intn(255)-127) / 127.0) * (0.2 + rng.Float64())
		}
	}
	m, err := NewQuantizedMatrixMod(w, 8, Mod64)
	if err != nil {
		t.Fatalf("NewQuantizedMatrixMod: %v", err)
	}
	bias := make([]float64, rows)
	for i := range bias {
		bias[i] = float64(rng.Intn(4096) - 2048)
	}
	m.WithBias(bias)
	return m
}

// setGlobalPoolOrder 重置并设定全局池候选序（测试内直用内部构造器，不影响其它测试）。
func setGlobalPoolOrder(t *testing.T, candidates []string, off bool) *AccelPool {
	t.Helper()
	resetAccelStateForTest()
	p := newAccelPool(candidates, off)
	globalPool = p
	globalPoolOnce.Do(func() {}) // 标记已初始化，防止后续 defaultPool() 重建覆盖
	return p
}

// TestAccelPoolDefaultOrderFallback 判据 4：默认解析按候选序首个可用者胜出；
// 无效候选（不存在文件）被逐成员安全校验拒绝后回退下一候选；结果缓存不重试。
func TestAccelPoolDefaultOrderFallback(t *testing.T) {
	dir := t.TempDir()
	good := poolFixtureSo(t, dir, "libaccel_good.so", 1)
	missing := filepath.Join(dir, "libaccel_missing.so") // 不存在 → Lstat 拒绝

	p := setGlobalPoolOrder(t, []string{missing, good}, false)

	b, err := p.Acquire("")
	if err != nil {
		t.Fatalf("默认解析应回退到 good 候选: %v", err)
	}
	if b.key != good {
		t.Fatalf("默认后端 = %s，want %s", b.key, good)
	}
	// 失败候选已缓存（不重试）。
	if _, ok := p.loadErrs[missing]; !ok {
		t.Fatal("无效候选的加载失败应被缓存")
	}
	// 再次 Acquire 走缓存，仍是同一后端。
	b2, err := p.Acquire("")
	if err != nil || b2.key != good {
		t.Fatalf("二次 Acquire 应命中缓存: b=%v err=%v", b2, err)
	}
}

// TestAccelPoolPathSafetyRejections 判据 3：符号链接 / group 可写 / 权限过宽逐成员拒绝，
// 池回退到合法候选；hint 指向被拒 key 时报错。
func TestAccelPoolPathSafetyRejections(t *testing.T) {
	dir := t.TempDir()
	good := poolFixtureSo(t, dir, "libaccel_ok.so", 1)

	// 符号链接（指向合法 .so 也拒绝）。
	link := filepath.Join(dir, "libaccel_link.so")
	if err := os.Symlink(good, link); err != nil {
		t.Skipf("无法创建符号链接（环境限制）: %v", err)
	}
	// group 可写。
	wide := poolFixtureSo(t, dir, "libaccel_wide.so", 1)
	if err := os.Chmod(wide, 0o664); err != nil { // rw-rw-r-- → group-write
		t.Fatalf("chmod 失败: %v", err)
	}

	p := setGlobalPoolOrder(t, []string{link, wide, good}, false)

	b, err := p.Acquire("")
	if err != nil {
		t.Fatalf("应回退到合法候选: %v", err)
	}
	if b.key != good {
		t.Fatalf("默认后端 = %s，want %s", b.key, good)
	}
	for _, bad := range []string{link, wide} {
		if _, ok := p.loadErrs[bad]; !ok {
			t.Fatalf("被拒候选 %s 应留加载失败缓存", bad)
		}
		if _, err := p.Acquire(bad); err == nil {
			t.Fatalf("hint 指向被拒候选 %s 应报错", bad)
		}
	}
}

// TestAccelPoolABIMismatchRejected 判据 2：ABI 版本 != 1 拒绝加载（rc -5），
// 池回退下一候选；hint 指向 ABI 不匹配 key 时报错。
func TestAccelPoolABIMismatchRejected(t *testing.T) {
	dir := t.TempDir()
	badABI := poolFixtureSo(t, dir, "libaccel_abi2.so", 2)
	good := poolFixtureSo(t, dir, "libaccel_abi1.so", 1)

	p := setGlobalPoolOrder(t, []string{badABI, good}, false)

	b, err := p.Acquire("")
	if err != nil {
		t.Fatalf("应回退到 ABI 匹配候选: %v", err)
	}
	if b.key != good {
		t.Fatalf("默认后端 = %s，want %s", b.key, good)
	}
	if _, err := p.Acquire(badABI); err == nil {
		t.Fatal("hint 指向 ABI 不匹配候选应报错")
	}
}

// TestAccelPoolDualBackendSwitchByHint 判据 1：双后端同时加载、按请求选择；
// 两后端输出与 CPU 基准逐位一致（语义分层红线：后端仅替换执行路径）。
func TestAccelPoolDualBackendSwitchByHint(t *testing.T) {
	dir := t.TempDir()
	soA := poolFixtureSo(t, dir, "libaccel_backend_a.so", 1)
	soB := poolFixtureSo(t, dir, "libaccel_backend_b.so", 1)

	setGlobalPoolOrder(t, []string{soA, soB}, false)

	rng := rand.New(rand.NewSource(20261112))
	const trials = 20
	for trial := 0; trial < trials; trial++ {
		rows, cols := 1+rng.Intn(16), 1+rng.Intn(48)
		m := randMatrixWithBias(t, rng, rows, cols)
		batch := 1 + rng.Intn(4)
		V := make([][]uint64, batch)
		for b := range V {
			V[b] = make([]uint64, cols)
			for j := range V[b] {
				V[b][j] = rng.Uint64()
			}
		}
		cpuOut, err := m.CipherLinearInt128(V)
		if err != nil {
			t.Fatalf("trial %d CPU 基准: %v", trial, err)
		}
		for _, hint := range []string{soA, soB} {
			out, err := m.AccelLinearInt128Via(hint, V)
			if err != nil {
				t.Fatalf("trial %d hint=%s: %v", trial, hint, err)
			}
			for b := 0; b < batch; b++ {
				for i := 0; i < rows; i++ {
					if out[b][i] != cpuOut[b][i] {
						t.Fatalf("trial %d hint=%s b=%d i=%d: CPU=%d 后端=%d 不一致", trial, hint, b, i, cpuOut[b][i], out[b][i])
					}
				}
			}
		}
		// 默认 hint=""：首个可用候选（soA）。
		out, err := m.AccelLinearInt128(V)
		if err != nil {
			t.Fatalf("trial %d 默认: %v", trial, err)
		}
		if out[0][0] != cpuOut[0][0] {
			t.Fatalf("trial %d 默认后端输出与 CPU 不一致", trial)
		}
	}
}

// TestAccelPoolHintNotInOrderRejected hint 信任输入不变：不在候选列表的路径拒绝（防运行期注入）。
func TestAccelPoolHintNotInOrderRejected(t *testing.T) {
	dir := t.TempDir()
	good := poolFixtureSo(t, dir, "libaccel_in.so", 1)
	outside := poolFixtureSo(t, dir, "libaccel_outside.so", 1) // 合法 .so 但不在候选列表

	p := setGlobalPoolOrder(t, []string{good}, false)

	if _, err := p.Acquire(outside); err == nil {
		t.Fatal("hint 不在候选列表应拒绝（防运行期注入任意路径）")
	}
	if _, err := p.Acquire(good); err != nil {
		t.Fatalf("候选列表内 hint 应可用: %v", err)
	}
}

// TestAccelPoolOffSwitch 判据/回滚开关：ACCEL_POOL=off 禁用运行期后端选择，
// 默认候选序回退行为保持（等价旧实现）。
func TestAccelPoolOffSwitch(t *testing.T) {
	dir := t.TempDir()
	soA := poolFixtureSo(t, dir, "libaccel_off_a.so", 1)
	soB := poolFixtureSo(t, dir, "libaccel_off_b.so", 1)

	p := setGlobalPoolOrder(t, []string{soA, soB}, true)

	if _, err := p.Acquire(""); err != nil {
		t.Fatalf("off 模式默认解析应保持: %v", err)
	}
	if _, err := p.Acquire(soB); err == nil {
		t.Fatal("off 模式 hint 选择应被拒绝")
	}
}

// TestAccelPoolConcurrentAcquire 判据 5：多 goroutine 混合默认/hint 获取无竞态（-race）、
// 单飞加载下输出仍与 CPU 基准一致。
func TestAccelPoolConcurrentAcquire(t *testing.T) {
	dir := t.TempDir()
	soA := poolFixtureSo(t, dir, "libaccel_cc_a.so", 1)
	soB := poolFixtureSo(t, dir, "libaccel_cc_b.so", 1)

	setGlobalPoolOrder(t, []string{soA, soB}, false)

	rng := rand.New(rand.NewSource(42))
	m := randMatrixWithBias(t, rng, 8, 16)
	V := [][]uint64{{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}}
	cpuOut, err := m.CipherLinearInt128(V)
	if err != nil {
		t.Fatalf("CPU 基准: %v", err)
	}

	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var out [][]uint64
			var err error
			switch i % 3 {
			case 0:
				out, err = m.AccelLinearInt128(V) // 默认
			case 1:
				out, err = m.AccelLinearInt128Via(soA, V)
			default:
				out, err = m.AccelLinearInt128Via(soB, V)
			}
			if err != nil {
				errs[i] = err
				return
			}
			if out[0][0] != cpuOut[0][0] {
				errs[i] = fmt.Errorf("goroutine %d 输出与 CPU 基准不一致", i)
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
}

// TestAccelPoolFallbackNoBackend 未配置候选时优雅回退（全局池；判据 4 的空候选分支）。
func TestAccelPoolFallbackNoBackend(t *testing.T) {
	t.Setenv("ACCEL_BACKEND_LIB", "")
	setGlobalPoolOrder(t, nil, false)

	m := randMatrixWithBias(t, rand.New(rand.NewSource(7)), 4, 4)
	if _, err := m.AccelLinearInt128([][]uint64{{1, 2, 3, 4}}); err == nil {
		t.Fatal("无候选时 AccelLinearInt128 应返回 ErrAccelUnavailable")
	}
	if _, err := AcquireAccelBackend(""); err == nil {
		t.Fatal("无候选时 AcquireAccelBackend 应返回错误")
	}
}

// TestAccelPoolSwitchDefaultBackend M5-2：运行期切换默认后端（同进程管理 API 执行点）。
func TestAccelPoolSwitchDefaultBackend(t *testing.T) {
	dir := t.TempDir()
	soA := poolFixtureSo(t, dir, "libaccel_sw_a.so", 1)
	soB := poolFixtureSo(t, dir, "libaccel_sw_b.so", 1)

	p := setGlobalPoolOrder(t, []string{soA, soB}, false)
	if _, err := p.Acquire(""); err != nil {
		t.Fatalf("首载失败: %v", err)
	}
	if got := p.CurrentDefault(); got != soA {
		t.Fatalf("初始默认应为 soA，got %q", got)
	}
	if err := p.SwitchDefaultBackend(soB); err != nil {
		t.Fatalf("切换失败: %v", err)
	}
	if got := p.CurrentDefault(); got != soB {
		t.Fatalf("切换后默认应为 soB，got %q", got)
	}
	b, err := p.Acquire("")
	if err != nil || b.key != soB {
		t.Fatalf("切换后 Acquire(\"\") 应走 soB: b=%v err=%v", b, err)
	}
	// 非法 key（不在候选列表）拒绝且保持原默认。
	outside := poolFixtureSo(t, dir, "libaccel_sw_outside.so", 1)
	if err := p.SwitchDefaultBackend(outside); err == nil {
		t.Fatal("不在候选列表的切换应拒绝")
	}
	if got := p.CurrentDefault(); got != soB {
		t.Fatalf("失败切换不应改变默认，got %q", got)
	}
	if c := p.Candidates(); len(c) != 2 || c[0] != soA || c[1] != soB {
		t.Fatalf("候选列表快照异常: %v", c)
	}
}

// TestAccelPoolSwitchDefaultBackendOff ACCEL_POOL=off 拒绝运行期切换（回滚开关语义）。
func TestAccelPoolSwitchDefaultBackendOff(t *testing.T) {
	dir := t.TempDir()
	soA := poolFixtureSo(t, dir, "libaccel_offsw_a.so", 1)
	soB := poolFixtureSo(t, dir, "libaccel_offsw_b.so", 1)
	p := setGlobalPoolOrder(t, []string{soA, soB}, true)
	if err := p.SwitchDefaultBackend(soB); err == nil {
		t.Fatal("off 模式应拒绝运行期切换")
	}
}

// TestAccelDispatchRejectsLiteralBackendAndFallsBackCPU M-5/G-3 负向用例：
// ACCEL_BACKEND_LIB 的运行期契约是「逗号分隔的受信绝对路径候选」；
// 把构建期轨道字面量（cuda/ascend/both）或相对路径注入时，必须被路径校验拒绝，
// 且 AccelLinearInt128 返回 ErrAccelUnavailable 由调用方回退 CPU 路径（不得静默放行）。
func TestAccelDispatchRejectsLiteralBackendAndFallsBackCPU(t *testing.T) {
	rng := rand.New(rand.NewSource(20261113))
	m := randMatrixWithBias(t, rng, 4, 8)
	V := [][]uint64{{1, 2, 3, 4, 5, 6, 7, 8}}

	for _, literal := range []string{"cuda", "ascend", "both", "./libaccel.so", "libaccel.so"} {
		t.Run(literal, func(t *testing.T) {
			t.Setenv("ACCEL_BACKEND_LIB", literal)
			t.Setenv("ACCEL_POOL", "")
			resetAccelStateForTest()
			defer func() {
				os.Unsetenv("ACCEL_BACKEND_LIB")
				resetAccelStateForTest()
			}()
			if err := InitAccelBackend(); err == nil {
				t.Fatalf("字面量/相对路径 %q 应被拒绝（IsAbs 契约）", literal)
			}
			if _, err := m.AccelLinearInt128(V); err == nil {
				t.Fatalf("%q: 应返回 ErrAccelUnavailable 交由调用方回退 CPU", literal)
			}
			cpu, err := m.CipherLinearInt128(V)
			if err != nil || len(cpu) != 1 || len(cpu[0]) != 4 {
				t.Fatalf("%q: CPU 回退路径不可用: err=%v out=%v", literal, err, cpu)
			}
			// 校验和/句柄：确认池未把非法 key 记成已加载后端。
			p := defaultPool()
			p.mu.RLock()
			n := len(p.backends)
			p.mu.RUnlock()
			if n != 0 {
				t.Fatalf("%q: 非法候选不应进入已加载后端池（n=%d）", literal, n)
			}
		})
	}
}
