# instruction.md

ATT&CK Detection（Data Component）→ Technique マッピング CSV 生成ツール
設計書

------------------------------------------------------------------------

## 1. 目的 / ゴール

本ツールは、MITRE ATT&CK の STIX データ（enterprise-attack /
mobile-attack / ics-attack）から、 **Detection（= Data Component）→
Technique** の公式対応関係を抽出し、Excel で直接利用可能な CSV
として出力することを目的とする。

本 CSV は以下の最終ゴールのための **機械生成マスタ** と位置付ける。

-   縦軸：Detection（Data Component）
-   横軸：セキュリティツール（EDR / SIEM / NDR / CASB 等）
-   セル：当該ツールで検知可能か（◯ / △ / ×）
-   上記を基に、
    -   検知できている MITRE Technique
    -   検知できていない MITRE Technique を Excel 上で自動判定する

------------------------------------------------------------------------

## 2. 用語整理（ATT&CK データモデル）

  -----------------------------------------------------------------------------------
  概念                    STIX type                  説明
  ----------------------- -------------------------- --------------------------------
  Data Source             `x-mitre-data-source`      ログや観測元の大分類

  Data Component          `x-mitre-data-component`   実際の検知単位（Detection）

  Technique               `attack-pattern`           ATT&CK Technique

  Sub-technique           `attack-pattern`           `x_mitre_is_subtechnique=true`

  Detection関係           `relationship`             `relationship_type="detects"`
  -----------------------------------------------------------------------------------

本ツールでは **Data Component → detects → Technique** の relationship
のみを抽出対象とする。

------------------------------------------------------------------------

## 3. 出力CSV仕様

### 3.1 基本出力（MVP）

ファイル名例： - `attack_detection_to_technique_enterprise.csv`

  列名                       内容
  -------------------------- ------------------------------------------------
  domain                     enterprise-attack / mobile-attack / ics-attack
  data_component_id          Data Component の STIX ID
  data_component             Data Component 名
  data_source                Data Source 名（取得できる場合のみ）
  technique_stix_id          Technique の STIX ID
  technique_id               ATT&CK ID（Txxxx / Txxxx.yyy）
  technique_name             Technique 名
  is_subtechnique            true / false
  relationship_id            detects relationship の STIX ID
  relationship_description   relationship.description（存在する場合）

### 3.2 拡張列（任意）

  列名                         内容
  ---------------------------- -------------------------------
  technique_tactics            tactic shortname（`;`区切り）
  technique_platforms          platform（`;`区切り）
  data_component_description   Data Component の説明
  technique_deprecated         true / false
  technique_revoked            true / false

※ 通常運用では deprecated / revoked は除外するため false 固定想定。

------------------------------------------------------------------------

## 4. 実行環境 / 依存関係

### 4.1 Python

-   Python 3.11 以上（3.10 でも可）
-   venv 利用推奨

### 4.2 依存ライブラリ

-   stix2
-   requests（GitHub raw 利用時）
-   taxii2-client（TAXII 利用時）
-   pandas（CSV出力を簡潔にしたい場合。必須ではない）

※ TAXII 利用時は TAXII 2.0 対応のため v20 import を使用する。

------------------------------------------------------------------------

## 5. ディレクトリ構造（推奨）

attack-detect-mapper/ instruction.md README.md pyproject.toml .gitignore
src/ attack_detect_mapper/ **init**.py cli.py config.py datasource.py
stix_filters.py extract.py enrich.py export.py types.py utils.py data/
input/ output/ tests/ test_extract.py test_filters.py

------------------------------------------------------------------------

## 6. CLI 設計

### 6.1 実行例

ローカル bundle から enterprise-attack を生成：

python -m attack_detect_mapper --source local --input
./data/input/enterprise-attack.json --domain enterprise-attack --out
./data/output/enterprise.csv

全ドメイン一括生成：

python -m attack_detect_mapper --source local --input-dir ./data/input
--domain all --out-dir ./data/output

### 6.2 CLI 引数一覧

  引数                      内容
  ------------------------- ------------------------------------------------------
  --source                  local / taxii / github
  --domain                  enterprise-attack / mobile-attack / ics-attack / all
  --input                   ローカル bundle パス
  --input-dir               複数 bundle 配置ディレクトリ
  --out                     出力 CSV
  --out-dir                 出力ディレクトリ
  --include-deprecated      deprecated を含める
  --include-revoked         revoked を含める
  --include-subtechniques   サブテクニック含有
  --log-level               INFO / DEBUG

------------------------------------------------------------------------

## 7. モジュール別 設計

### 7.1 datasource.py

責務：STIX DataStore を取得する

-   load_local_bundle(path) -\> MemoryStore
-   load_from_taxii(domain) -\> TAXIICollectionSource
-   get_datastore(source, domain, input_path, ...) -\> DataStore

------------------------------------------------------------------------

### 7.2 stix_filters.py

-   remove_revoked_deprecated(objects, include_deprecated,
    include_revoked)
-   is_attack_technique(obj)
-   is_subtechnique(obj)

------------------------------------------------------------------------

### 7.3 extract.py（中核）

処理フロー：

1.  Data Component 全件取得
2.  Technique 全件取得
3.  detects relationship 抽出
4.  source_ref / target_ref 解決
5.  deprecated / revoked 除外
6.  CSV row 生成

主要関数：

-   extract_detects_relationships(src)
-   build_detection_to_technique_rows(src, domain, options)

------------------------------------------------------------------------

### 7.4 enrich.py（任意）

-   get_attack_external_id()
-   get_tactics()
-   get_platforms()
-   get_data_source_name()

------------------------------------------------------------------------

### 7.5 export.py

-   write_csv(rows, out_path)
-   write_csv_per_domain(rows_by_domain, out_dir)

------------------------------------------------------------------------

### 7.6 cli.py

-   parse_args()
-   main()

------------------------------------------------------------------------

## 8. テスト方針

-   deprecated / revoked 除外確認
-   detects relationship 抽出確認
-   ATT&CK ID 抽出確認

------------------------------------------------------------------------

## 9. 実装ステップ

1.  ローカル bundle 対応 MVP
2.  deprecated / revoked 除外
3.  enrichment 追加
4.  複数ドメイン対応
5.  TAXII 対応（必要に応じて）

------------------------------------------------------------------------

## 10. Excel 連携前提の設計思想

-   CSV は機械生成マスタ
-   Tool × Detection マトリクスは人が管理
-   STIX ID をキーとして JOIN 可能にする

------------------------------------------------------------------------
