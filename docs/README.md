# TRACE Documentation

## For Operators (deploy & run)

| Document | Description |
|----------|-------------|
| [setup.md](setup.md) | Environment setup, GCP deployment, Cloud Run Job |

## For Developers (contribute code)

| Document | Description |
|----------|-------------|
| [structure.md](structure.md) | Project directory layout |
| [data-model.md](data-model.md) | Validation schemas, STIX bundle format |
| [crawl_design.md](crawl_design.md) | Crawler architecture, L2-L4 pipeline |
| [dependencies.md](dependencies.md) | Third-party dependency rationale |
| [beacon_handoff.md](beacon_handoff.md) | BEACON → TRACE data handoff specification |

## For Architects (design decisions)

| Document | Description |
|----------|-------------|
| [api-stability.md](api-stability.md) | API stability policy and BC guarantees |
| [high-level-design.md](high-level-design.md) | System design (local-only, gitignored) |

## Cross-project (shared via symlink)

| Document | Canonical repo | Description |
|----------|---------------|-------------|
| [pipeline-guide.md](pipeline-guide.md) | BEACON | End-to-end CTI pipeline operations |
| [citations.md](citations.md) | BEACON | External citations and license inventory |

> IR feedback flow の計算式は [SAGE docs/ir-feedback-flow.md](../../sage/docs/ir-feedback-flow.md) を参照。

日本語版は各ファイルの `.ja.md` サフィックスで同ディレクトリに配置。
