# MITRE ATT&CK Detection Mapper

MITRE ATT&CK の STIX バンドルから Data Component（Detection）と Technique の対応関係を抽出し、Excel でそのまま扱える CSV を生成する CLI です。検知マトリクスのマスタデータとして活用できます。

## クイックスタート

```bash
# 事前準備（uv 利用）
uv sync

# 単一ドメイン（enterprise）の生成例
uv run python -m attack_detect_mapper \
  --source local \
  --input data/input/enterprise-attack.json \
  --domain enterprise-attack \
  --out data/output/enterprise.csv \
  --include-subtechniques

# ドメインごとに JSON が存在する場合の一括生成
uv run python -m attack_detect_mapper \
  --source local \
  --input-dir data/input \
  --domain all \
  --out-dir data/output
```

## CLI オプション

| フラグ | 説明 |
| --- | --- |
| `--source` | データの取得元。`local`（実装済み）、`taxii`、`github` |
| `--domain` | `enterprise-attack` / `mobile-attack` / `ics-attack` / `all` |
| `--input` | 単一バンドル JSON のパス（local ソース用） |
| `--input-dir` | `<domain>.json` を配置したディレクトリ（local ソース用） |
| `--out` | 単一ドメイン実行時の出力 CSV |
| `--out-dir` | `--domain all` 時の出力ディレクトリ |
| `--include-deprecated` | deprecated オブジェクトを除外せずに含める |
| `--include-revoked` | revoked オブジェクトを含める |
| `--include-subtechniques` | サブテクニックを含めて出力 |
| `--log-level` | ログレベル (`DEBUG`/`INFO`/`WARNING`/`ERROR`) |
