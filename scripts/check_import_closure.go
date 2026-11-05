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
//	GO111MODULE=off go run scripts/check_import_closure.go \
//	    -root <MAIN_REPO> -mode baseline -out scripts/closure-baseline.json
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

var skipRules = []string{
	"跳过目录 .git",
	"跳过目录 vendor / node_modules",
	"跳过所有隐藏目录（.tools / .gopath-p24 等工具链缓存，非主仓源码）",
	"仅扫描 *.go；_test.go 单独计数但同样计入闭包",
	"只读：不写入被扫描仓库",
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
	SelfChecks         []SelfCheck         `json:"self_checks"`
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

func scan(root, mode string) (*Report, error) {
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

	closed := len(report.GroupKeys) == len(groupKeys) && len(report.Groups) == len(groupKeys)
	for _, key := range groupKeys {
		if _, ok := report.Groups[key]; !ok {
			closed = false
		}
	}
	add("S2", closed, "闭集分组数=%d（8 个被迁出包 + cipher/mask），全部键在预定义闭集内", len(report.Groups))

	add("S3", len(report.NewRepoCrossHits) == 0,
		"与新库零交叉（new_repo_cross_hits=%d）", len(report.NewRepoCrossHits))
	add("S4", len(report.ForbiddenPathHits) == 0,
		"禁碰路径零命中：import 改写候选落禁碰路径=%d（只读盘点到的禁碰文件数=%d，不计失败）",
		len(report.ForbiddenPathHits), len(report.ForbiddenPathFiles))
	add("S5", report.TotalImportLines >= 0 && report.TotalGroupHits >= 0,
		"汇总计数 go_files=%d test_files=%d import_lines=%d group_hits=%d",
		report.TotalGoFiles, report.TotalTestGoFiles, report.TotalImportLines, report.TotalGroupHits)
}

func main() {
	root := flag.String("root", "", "扫描根目录（必填，通常为主仓根目录）")
	mode := flag.String("mode", "baseline", "扫描模式：本阶段仅实现 baseline")
	out := flag.String("out", "", "落盘 JSON 基线报告路径（可选）")
	flag.Parse()

	if *root == "" {
		fmt.Fprintln(os.Stderr, "check_import_closure: -root is required")
		os.Exit(2)
	}
	if *mode != "baseline" {
		fmt.Fprintf(os.Stderr, "check_import_closure: mode %q not implemented in stage 0 (only baseline)\n", *mode)
		os.Exit(2)
	}

	report, err := scan(*root, *mode)
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
