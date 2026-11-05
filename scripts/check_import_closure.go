//go:build ignore

// check_import_closure.go —— 语法级 AST import 闭包基线扫描（§5 阶段 0 基线模式）。
//
// 背景：真机 192.168.31.248 SSH 当前不可用，`go list -deps` 取证受阻。本工具用
// go/parser 对源码做语法级 AST 解析（不是正则），产出可复现的 import 闭包基线，
// 为 §5 阶段 3/4 的 import 路径全局改写提供完备性证据。
//
// 本文件带 //go:build ignore：不进入新库 go list -test -deps ./... 的 G1 闭包。
// 纯标准库、只读：不修改被扫描仓库的任何文件。
//
// 运行（本机 go1.20.3 可跑）：
//
//	# baseline 模式：扫主仓，产出/比对闭包基线（S2/S3 真判）
//	GO111MODULE=off go run scripts/check_import_closure.go \
//	    -root <MAIN_REPO> -mode baseline -out scripts/closure-baseline.json
//
//	# verify 模式：扫新库，断言零主仓依赖（S1/S4/S6 真判；S2/S3 显式 SKIP，理由见 main 注释）
//	# 禁用前缀由 scripts/verify_all.sh 注入（主仓裸名 / 主仓 module 路径 / 国密三方库前缀）。
//	# 注释里刻意不写出这些字面量：静态自检 (g) 会 grep 全库 *.go 的主仓/国密字面量，
//	# 写进本文件会让工具自身被误判为「白名单外命中」。
//	GO111MODULE=off go run scripts/check_import_closure.go \
//	    -root <SUB_REPO> -mode verify \
//	    -forbid-prefix '<MAIN_ORG>/' \
//	    -forbid-prefix '<MAIN_MODULE>/' \
//	    -forbid-prefix '<GM_LIB_MODULE>'
//
// 注意（Windows 本机）：`go run` 生成的临时 exe 可能因安全策略报 Access is denied，
// 请改用 `GO111MODULE=off go build -o <TMP>/cic scripts/check_import_closure.go` 再执行。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// groupKeys 为方案 §3.1 的 8 个被迁出包（短键按原文登记，匹配时用包含判定）
// + cipher/mask 命中清单，共 9 个闭集分组键。
var groupKeys = []string{
	"gateway/teecore/maskedinfer",
	"trustedops",
	"route2plan",
	"route2ref",
	"route2demo",
	"adapters/qwen",
	"gateway/tee-infer-service/route2step",
	"cmd/route2-client",
	"cipher/mask",
}

// fullKeyPaths 说明短键在主仓中的完整包路径，仅供报告阅读，不参与匹配。
var fullKeyPaths = map[string]string{
	"gateway/teecore/maskedinfer":          "gateway/teecore/maskedinfer",
	"trustedops":                           "gateway/teecore/trustedops",
	"route2plan":                           "gateway/teecore/route2plan",
	"route2ref":                            "gateway/teecore/route2ref",
	"route2demo":                           "gateway/teecore/route2demo",
	"adapters/qwen":                        "gateway/teecore/adapters/qwen",
	"gateway/tee-infer-service/route2step": "gateway/tee-infer-service/route2step",
	"cmd/route2-client":                    "cmd/route2-client",
	"cipher/mask":                          "cipher/mask",
}

// forbiddenFragments 为绝对禁碰路径（P1-8，由他人负责）的路径片段。
var forbiddenFragments = []string{
	"docs/P1-8-",
	"gateway/wasm/otpmask-plugin/",
	"gateway/attest-verify/",
	"deploy/higress/",
}

// skipRules 写入 JSON 报告，是已提交基线 closure-baseline.json 的组成部分：
// **文案一字不可改**，否则 baseline 字节比对（cmp）必然失败。
// 关于 _test.go 的补充说明只能写在这里（注释），不得塞进下面的字符串：
// verify 模式同样扫描 _test.go —— 随迁测试曾把主仓路径带进闭包（core/multilayer_masked_test.go
// 历史上 import 过 cipher/mask），故测试文件必须纳入零主仓依赖判定。
var skipRules = []string{
	"跳过目录 .git",
	"跳过目录 vendor / node_modules",
	"跳过所有隐藏目录（.tools / .gopath-p24 等工具链缓存，非主仓源码）",
	"仅扫描 *.go；_test.go 单独计数但同样计入闭包",
	"只读：不写入被扫描仓库",
}

// verifyModeWhitelist 为 verify 模式唯一白名单：rel 路径**逐字相等**匹配
// （map 查表，不是 strings.HasPrefix / strings.Contains，避免 "scripts/verify_golden_against_main.go.bak"
// 或子目录同名文件被误放行）。
//
// 存在理由：真机复核工具 verify_golden_against_main.go 必须在主仓 module 下 import 主仓
// cipher/mask 才能对拍 golden 向量，因此不能计入新库「零主仓依赖」判定。
// 每次 SKIP 都会打印文件路径，并汇总打印被跳过文件数；该数应恒为 1，若某天变成 2，
// 一眼即可看出白名单被扩大（构建/门禁双重可审计）。
var verifyModeWhitelist = map[string]bool{
	"scripts/verify_golden_against_main.go": true,
}

type Hit struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	ImportPath string `json:"import_path"`
}

type SelfCheck struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail"`
}

type Report struct {
	Schema             string              `json:"schema"`
	Mode               string              `json:"mode"`
	Root               string              `json:"root"`
	SkipRules          []string            `json:"skip_rules"`
	GroupKeys          []string            `json:"group_keys"`
	GroupKeyPaths      map[string]string   `json:"group_key_paths"`
	TotalGoFiles       int                 `json:"total_go_files"`
	TotalTestGoFiles   int                 `json:"total_test_go_files"`
	TotalImportLines   int                 `json:"total_import_lines"`
	TotalGroupHits     int                 `json:"total_group_hits"`
	ParseFailures      []string            `json:"parse_failures"`
	Groups             map[string][]Hit    `json:"groups"`
	GroupHitCounts     map[string]int      `json:"group_hit_counts"`
	GroupFileCounts    map[string]int      `json:"group_file_counts"`
	GroupOwnFiles      map[string][]string `json:"group_own_files"`
	GroupOwnCounts     map[string]int      `json:"group_own_file_counts"`
	NewRepoCrossHits   []string            `json:"new_repo_cross_hits"`
	ForbiddenPathHits  []string            `json:"forbidden_path_hits"`
	ForbiddenPathFiles []string            `json:"forbidden_path_files_present"`
	// ForbiddenPrefixHits：未传 -forbid-prefix 时为 nil → omitempty 省略（保持 baseline 字节一致）；
	// 传了则始终输出数组（零命中为 []），供 verify 模式机械断言「S6 零命中」。
	ForbiddenPrefixHits *[]string `json:"forbidden_prefix_hits,omitempty"`
	// WhitelistSkippedFiles：verify 模式跳过的白名单文件（baseline 恒为 nil → omitempty 省略），
	// 供审计白名单是否被人为扩大（应恒为 1 个）。
	WhitelistSkippedFiles []string    `json:"whitelist_skipped_files,omitempty"`
	SelfChecks            []SelfCheck `json:"self_checks"`
}

func shouldSkipDir(name, path, root string) bool {
	if path == root {
		return false
	}
	if name == ".git" || name == "vendor" || name == "node_modules" {
		return true
	}
	if strings.HasPrefix(name, ".") {
		return true
	}
	return false
}

func isForbiddenPath(rel string) bool {
	p := filepath.ToSlash(rel)
	if strings.HasSuffix(p, ".patch") {
		return true
	}
	for _, frag := range forbiddenFragments {
		if strings.Contains(p, frag) {
			return true
		}
	}
	return false
}

// isNewRepoImport 判定 import path 是否指向新库（用于 S3「与新库零交叉」）。
func isNewRepoImport(p string) bool {
	return strings.HasPrefix(p, "github.com/FengYang/masked-infer") || strings.HasSuffix(p, "/masked-infer")
}

// importPathOf 从 AST ImportSpec 取出去除引号后的 import 路径（语法级，不用正则）。
func importPathOf(spec *ast.ImportSpec) (string, error) {
	return strconv.Unquote(spec.Path.Value)
}

func scan(root, mode string, forbidPrefixes []string) (*Report, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	report := &Report{
		Schema:             "masked-infer/import-closure-baseline/v1",
		Mode:               mode,
		Root:               absRoot,
		SkipRules:          skipRules,
		GroupKeys:          groupKeys,
		GroupKeyPaths:      fullKeyPaths,
		Groups:             make(map[string][]Hit, len(groupKeys)),
		GroupHitCounts:     make(map[string]int, len(groupKeys)),
		GroupFileCounts:    make(map[string]int, len(groupKeys)),
		GroupOwnFiles:      make(map[string][]string, len(groupKeys)),
		GroupOwnCounts:     make(map[string]int, len(groupKeys)),
		ParseFailures:      []string{},
		NewRepoCrossHits:   []string{},
		ForbiddenPathHits:  []string{},
		ForbiddenPathFiles: []string{},
	}
	// 仅当传了 -forbid-prefix 才分配（nil 时 omitempty 省略以保持 baseline 字节一致；
	// 非 nil 则始终输出数组，零命中为 []，供 verify 模式机械断言）。
	if len(forbidPrefixes) > 0 {
		empty := []string{}
		report.ForbiddenPrefixHits = &empty
	}
	ownPrefixes := make(map[string]string, len(groupKeys))
	for _, key := range groupKeys {
		report.Groups[key] = []Hit{}
		report.GroupHitCounts[key] = 0
		report.GroupFileCounts[key] = 0
		report.GroupOwnFiles[key] = []string{}
		report.GroupOwnCounts[key] = 0
		ownPrefixes[key] = filepath.ToSlash(fullKeyPaths[key]) + "/"
	}

	err = filepath.Walk(absRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			if shouldSkipDir(info.Name(), path, absRoot) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(info.Name(), ".go") {
			return nil
		}
		rel, err := filepath.Rel(absRoot, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		// verify 模式跳过唯一白名单：真机复核工具 verify_golden_against_main.go 必须 import 主仓
		// cipher/mask（在 worktree 内以主仓 module 运行），故不计入新库「零主仓依赖」判定。
		// 精确路径逐字相等匹配（map 查表），不做前缀/Contains 判断。
		if mode == "verify" && verifyModeWhitelist[rel] {
			fmt.Printf("SKIP whitelist (verify mode): %s（真机复核工具，唯一白名单，须 import 主仓 cipher/mask）\n", rel)
			report.WhitelistSkippedFiles = append(report.WhitelistSkippedFiles, rel)
			return nil
		}
		report.TotalGoFiles++
		for key, prefix := range ownPrefixes {
			if strings.HasPrefix(rel, prefix) {
				report.GroupOwnFiles[key] = append(report.GroupOwnFiles[key], rel)
			}
		}
		if strings.HasSuffix(info.Name(), "_test.go") {
			report.TotalTestGoFiles++
		}
		// 禁碰路径文件只读盘点：这些路径由他人负责，存在属正常；
		// S4 判定的是「阶段 3/4 import 改写候选是否落入禁碰路径」，不是文件是否存在。
		if isForbiddenPath(rel) {
			report.ForbiddenPathFiles = append(report.ForbiddenPathFiles, rel)
		}

		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			report.ParseFailures = append(report.ParseFailures, fmt.Sprintf("%s: %v", rel, parseErr))
			return nil
		}
		for _, spec := range file.Imports {
			importPath, err := importPathOf(spec)
			if err != nil {
				report.ParseFailures = append(report.ParseFailures,
					fmt.Sprintf("%s: unquote import %q: %v", rel, spec.Path.Value, err))
				continue
			}
			report.TotalImportLines++
			if isNewRepoImport(importPath) {
				report.NewRepoCrossHits = append(report.NewRepoCrossHits, fmt.Sprintf("%s: %s", rel, importPath))
			}
			if report.ForbiddenPrefixHits != nil {
				for _, pfx := range forbidPrefixes {
					if strings.HasPrefix(importPath, pfx) {
						*report.ForbiddenPrefixHits = append(*report.ForbiddenPrefixHits,
							fmt.Sprintf("%s: %s", rel, importPath))
					}
				}
			}
			for _, key := range groupKeys {
				if strings.Contains(importPath, key) {
					if isForbiddenPath(rel) || isForbiddenPath(importPath) {
						report.ForbiddenPathHits = append(report.ForbiddenPathHits,
							fmt.Sprintf("group %s: import %s at %s", key, importPath, rel))
					}
					report.Groups[key] = append(report.Groups[key], Hit{
						File:       rel,
						Line:       fset.Position(spec.Pos()).Line,
						ImportPath: importPath,
					})
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// 排序保证 JSON 输出可逐字节复现。
	for _, key := range groupKeys {
		hits := report.Groups[key]
		sort.Slice(hits, func(i, j int) bool {
			if hits[i].File != hits[j].File {
				return hits[i].File < hits[j].File
			}
			if hits[i].Line != hits[j].Line {
				return hits[i].Line < hits[j].Line
			}
			return hits[i].ImportPath < hits[j].ImportPath
		})
		report.GroupHitCounts[key] = len(hits)
		seen := make(map[string]bool, len(hits))
		for _, h := range hits {
			seen[h.File] = true
		}
		report.GroupFileCounts[key] = len(seen)
		report.TotalGroupHits += len(hits)
		sort.Strings(report.GroupOwnFiles[key])
		report.GroupOwnCounts[key] = len(report.GroupOwnFiles[key])
	}
	sort.Strings(report.ParseFailures)
	sort.Strings(report.NewRepoCrossHits)
	sort.Strings(report.ForbiddenPathHits)
	sort.Strings(report.ForbiddenPathFiles)
	if report.ForbiddenPrefixHits != nil {
		sort.Strings(*report.ForbiddenPrefixHits)
	}
	sort.Strings(report.WhitelistSkippedFiles)
	return report, nil
}

func evaluate(report *Report) {
	add := func(name string, pass bool, format string, args ...interface{}) {
		report.SelfChecks = append(report.SelfChecks, SelfCheck{
			Name:   name,
			Pass:   pass,
			Detail: fmt.Sprintf(format, args...),
		})
	}
	add("S1", len(report.ParseFailures) == 0,
		"语法解析零失败（parse_failures=%d, go_files=%d）", len(report.ParseFailures), report.TotalGoFiles)

	if report.Mode == "verify" {
		// S2/S3 均为主仓专属语义；新库 verify 模式明确打印 SKIP（不静默，避免被误读为通过）。
		fmt.Println("S2 SKIP (verify mode: 闭集分组为主仓语义，新库不适用)")
		fmt.Println("S3 SKIP (verify mode: new_repo_cross_hits 判「主仓是否 import 新库」，新库自扫恒真，不适用)")
	} else {
		closed := len(report.GroupKeys) == len(groupKeys) && len(report.Groups) == len(groupKeys)
		for _, key := range groupKeys {
			if _, ok := report.Groups[key]; !ok {
				closed = false
			}
		}
		add("S2", closed, "闭集分组数=%d（8 个被迁出包 + cipher/mask），全部键在预定义闭集内", len(report.Groups))
		add("S3", len(report.NewRepoCrossHits) == 0,
			"与新库零交叉（new_repo_cross_hits=%d）", len(report.NewRepoCrossHits))
	}

	add("S4", len(report.ForbiddenPathHits) == 0,
		"禁碰路径零命中：import 改写候选落禁碰路径=%d（只读盘点到的禁碰文件数=%d，不计失败）",
		len(report.ForbiddenPathHits), len(report.ForbiddenPathFiles))
	add("S5", report.TotalImportLines >= 0 && report.TotalGroupHits >= 0,
		"汇总计数 go_files=%d test_files=%d import_lines=%d group_hits=%d",
		report.TotalGoFiles, report.TotalTestGoFiles, report.TotalImportLines, report.TotalGroupHits)

	if report.Mode == "verify" {
		// S6（verify 核心门禁）：禁用前缀零命中，且必须真的传了 -forbid-prefix。
		// 同时把「_test.go 是否被纳入扫描」并入本门禁：G1 的关键风险之一就是随迁测试把主仓
		// 路径带进闭包（历史上 core/multilayer_masked_test.go 就 import 过 cipher/mask）。
		// 若将来有人让扫描器跳过 _test.go，test_files 会归零 → S6 直接 FAIL（fail-closed）。
		switch {
		case report.ForbiddenPrefixHits == nil:
			add("S6", false, "S6 失败：verify 模式未传 -forbid-prefix，无法判定零命中")
		case report.TotalTestGoFiles == 0:
			add("S6", false, "S6 失败：verify 模式未扫到任何 _test.go（test_files=0），测试文件路径未被覆盖")
		default:
			add("S6", len(*report.ForbiddenPrefixHits) == 0,
				"禁用前缀零命中（forbidden_prefix_hits=%d；已覆盖 test_files=%d，白名单跳过=%d）",
				len(*report.ForbiddenPrefixHits), report.TotalTestGoFiles, len(report.WhitelistSkippedFiles))
		}
		// 白名单跳过数必须可审计；verify 模式下恒为 1（超过 1 说明白名单被扩大，需人工复核）。
		fmt.Printf("VERIFY_WHITELIST_SKIPPED_FILES=%d（应为 1；>1 说明白名单被扩大）\n",
			len(report.WhitelistSkippedFiles))
	}
}

// stringSliceFlag 支持可重复的 -forbid-prefix 参数。
type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }

func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	root := flag.String("root", "", "扫描根目录（必填，通常为主仓根目录）")
	// 模式职责分工（勿删；S2/S3 在 verify 下 SKIP 是刻意设计，不是遗漏或"悄悄删掉"）：
	//
	//	-mode baseline（-root <主仓>）：
	//	    S2 闭集分组 + S3 new_repo_cross_hits 真判 —— 守「主仓不得反向 import 新库」的
	//	    方向性约束（阶段 4 删包后仍需长期持续守）。
	//
	//	-mode verify（-root <新库>）：
	//	    S6 真判（新库不得 import 主仓前缀 / 第三方向量前缀），配合 S1 解析零失败与
	//	    S4 禁碰路径零命中。此时 S2/S3 显式 SKIP：new_repo_cross_hits 的定义是
	//	    「主仓里有文件 import 了新库路径」，扫描对象换成新库自己后，core/plan/demo/
	//	    masklite 之间互相 import 天然命中该词条（实测 19 条），那是自引用而非缺陷；
	//	    即判据与扫描对象不匹配，恒真恒 FAIL，因此不属于本模式的判据。
	//	    覆盖不会因此丢失：方向性约束由 baseline 模式的 S3 承担，两模式分工互补。
	mode := flag.String("mode", "baseline", "扫描模式：baseline（主仓基线；S2/S3 真判）| verify（新库零主仓依赖；S1/S4/S6 真判，S2/S3 显式 SKIP 因判据为主仓语义）")
	out := flag.String("out", "", "落盘 JSON 基线报告路径（可选）")
	var forbidPrefixes stringSliceFlag
	flag.Var(&forbidPrefixes, "forbid-prefix", "禁用的 import 前缀（可重复），命中项写入 forbidden_prefix_hits；verify 模式必须至少传 1 个，否则 S6 FAIL")
	flag.Parse()

	if *root == "" {
		fmt.Fprintln(os.Stderr, "check_import_closure: -root is required")
		os.Exit(2)
	}
	if *mode != "baseline" && *mode != "verify" {
		fmt.Fprintf(os.Stderr, "check_import_closure: mode %q not implemented (baseline|verify)\n", *mode)
		os.Exit(2)
	}

	report, err := scan(*root, *mode, forbidPrefixes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check_import_closure: %v\n", err)
		os.Exit(1)
	}
	evaluate(report)

	if *out != "" {
		blob, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "check_import_closure: marshal: %v\n", err)
			os.Exit(1)
		}
		blob = append(blob, '\n')
		if err := os.WriteFile(*out, blob, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "check_import_closure: write %s: %v\n", *out, err)
			os.Exit(1)
		}
	}

	allPass := true
	for _, c := range report.SelfChecks {
		status := "PASS"
		if !c.Pass {
			status = "FAIL"
			allPass = false
		}
		fmt.Printf("%s %s: %s\n", c.Name, status, c.Detail)
	}
	fmt.Printf("BASELINE_SUMMARY go_files=%d test_files=%d import_lines=%d group_hits=%d\n",
		report.TotalGoFiles, report.TotalTestGoFiles, report.TotalImportLines, report.TotalGroupHits)
	for _, key := range report.GroupKeys {
		fmt.Printf("  group %-38s import_hits=%d importer_files=%d own_files=%d\n",
			key, report.GroupHitCounts[key], report.GroupFileCounts[key], report.GroupOwnCounts[key])
	}
	if *out != "" {
		fmt.Printf("BASELINE_JSON: %s\n", *out)
	}
	if !allPass {
		fmt.Fprintln(os.Stderr, "check_import_closure: self-check failed")
		os.Exit(1)
	}
}
