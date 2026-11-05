# SBOM（§5 阶段 0 最小基线）

## 本阶段产物

`cdx.json` 是一份最小 CycloneDX 1.5 JSON 基线：

- `metadata.component` = `masked-infer`（Apache-2.0）；
- `components` = `[]`，与 `go.mod` 零 `require`、NOTICE「无第三方依赖」一致；
- 手写维护，不含时间戳/序列号等非确定性字段，便于逐字节比对。

## 生成方式

阶段 5 发布门禁须用 Syft / CycloneDX 工具重新生成，例如：

```
syft packages dir:. -o cyclonedx-json@1.5 > SBOM/cdx.json
```

本阶段**不安装、不 vendor、不在 `go.mod` 声明** Syft 或任何 CycloneDX 工具；上面的命令
仅是发布期操作说明，不构成运行时依赖或构建依赖。生成后须复核 components 与实际
`go.mod require` 一致。

## 阶段 5 发布门禁复核项

1. 许可：Apache-2.0（LICENSE / NOTICE）；
2. NOTICE 第三方依赖枚举与 SBOM components 一致；
3. 国密外发红线：全仓 `grep -rE 'func sm[234]'` 零命中；
4. G1 门禁（`scripts/gate_g1.sh`）零命中；
5. 本文件为阶段 0 基线快照；阶段 1–4 引入任何第三方依赖时必须同步更新 NOTICE/SBOM，
   并在发布前由工具重生成，禁止沿用本基线冒充发布产物。

> 阶段 1 补充：迁入的 5 个包与 `masklite` 全部只用 Go 标准库，`go.mod` 仍零 `require`，
> 故 `cdx.json` 的 `components` 保持 `[]`，本阶段**未改动** `cdx.json`。
