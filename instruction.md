# instruction.md

ATT&CK Detection（Data Component）→ Technique マッピング CSV 生成ツール
設計書

------------------------------------------------------------------------

## 1. 目的 / ゴール

MITRE ATT&CK の STIX データ（enterprise / mobile /
ics）から、以下を満たす **Detection（= Data Component）→ Technique**
の対応表を生成し、CSVとして出力する。

-   出力CSVは Excel でそのまま利用可能（UTF-8 / ヘッダ付き）
-   deprecated / revoked
    オブジェクトを除外（オプションで含めることも可能）
-   ATT&CK ドメイン（enterprise / mobile / ics）を選択可能
-   データ取得元を切り替え可能
    -   ローカル STIX JSON（bundle）\
    -   （将来）TAXII サーバ
-   最終的に Excel 上で\
    **Detection × セキュリティツール → Technique 検知可否判定**\
    に利用することを前提とする

------------------------------------------------------------------------

## 2. 用語整理（ATT&CK データモデル）

  -------------------------------------------------------------------------------
  概念                    STIX type                説明
  ----------------------- ------------------------ ------------------------------
  Data Source             x-mitre-data-source      ログや観測元の大分類

  Data Component          x-mitre-data-component   実際の検知単位（Detection）

  Technique               attack-pattern           ATT&CK Technique

  Sub-technique           attack-pattern           x_mitre_is_subtechnique=true

  Detection関係           relationship             relationship_type="detects"
  -------------------------------------------------------------------------------

------------------------------------------------------------------------

（以下、設計書全文は前メッセージと同一内容）
