# TRACE ドキュメント

## オペレーター向け（デプロイ・運用）

| ドキュメント | 説明 |
|-------------|------|
| [setup.md](setup.md) | 環境セットアップ、GCP デプロイ、Cloud Run Job |

## 開発者向け（コード貢献）

| ドキュメント | 説明 |
|-------------|------|
| [structure.md](structure.md) | プロジェクトのディレクトリ構成 |
| [data-model.md](data-model.md) | バリデーションスキーマ、STIX バンドル形式 |
| [crawl_design.md](crawl_design.md) | クローラーアーキテクチャ、L2-L4 パイプライン |
| [dependencies.md](dependencies.md) | サードパーティ依存関係の採用理由 |
| [beacon_handoff.md](beacon_handoff.md) | BEACON → TRACE データハンドオフ仕様 |

## アーキテクト向け（設計上の判断）

| ドキュメント | 説明 |
|-------------|------|
| [api-stability.md](api-stability.md) | API 安定性ポリシーおよび後方互換性の保証 |
| [high-level-design.md](high-level-design.md) | システム設計（ローカルのみ、gitignored） |

## クロスプロジェクト（シンボリックリンク経由で共有）

| ドキュメント | 正規リポジトリ | 説明 |
|-------------|--------------|------|
| [pipeline-guide.md](pipeline-guide.md) | BEACON | エンドツーエンド CTI パイプライン操作 |
| [citations.md](citations.md) | BEACON | 外部引用とライセンス一覧 |

> IR フィードバックフローの計算式は [SAGE docs/ir-feedback-flow.md](../../sage/docs/ir-feedback-flow.md) を参照。

日本語版は各ファイルの `.ja.md` サフィックスで同ディレクトリに配置。
