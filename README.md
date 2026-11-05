# IPアドレスリスク診断スクリプト (ip-assess.sh)
## 概要
本スクリプトは、アクセス元IPアドレスを調査し、その属性（一般回線、データセンター、匿名プロキシ、企業向け SASE 等）と脅威の評判を分析する、**インシデント調査の初動向け**の診断ツールです。  
判定結果は「安全／危険」の結論ではなく、**どの IP から優先的に調査すべきか（調査優先度）** と、その根拠として出力します。最終的な判断は、アプリケーションログや認証ログの振る舞いとあわせて行ってください。

## Usage
```
./ip-assess.sh [オプション] <IPv4アドレス>
```

| オプション | 内容 |
| :--- | :--- |
| `--json` | テキストレポートの代わりに JSON（機械可読形式）のみを標準出力へ出力 |
| `--plain` | 絵文字の代わりに ASCII の記号（`[!]` `[o]` `[i]` `[ ]` `[?]`）で表示 |
| `--verbose` | 各評価項目の判定根拠（Evidence / Reason）もあわせて表示 |
| `-v`, `--version` | バージョンを表示 |
| `-h`, `--help` | ヘルプを表示 |

```
# テキストレポート
./ip-assess.sh 203.0.113.10

# 判定根拠も表示し、ASCII の記号で出力（ログ保存や grep 向け）
./ip-assess.sh --plain --verbose 203.0.113.10

# JSON を証跡として保存
./ip-assess.sh --json 203.0.113.10 > ip-assess_203.0.113.10.json
```

> 対象は **IPv4 のみ** です。IPv4 として正しくない文字列を指定した場合はエラーで終了します。

## 動作要件
| コマンド | 用途 | 備考 |
| :--- | :--- | :--- |
| `bash` / `curl` / `awk` / `sed` / `grep` | 本体処理、RDAP・Tor 出口ノード一覧の取得、RDAP（JSON）の解析 | 必須。`awk` は mawk / gawk / busybox awk で動作確認済み。**`jq` は不要**です |
| `dig` または `host` | 逆引き・FCrDNS、DNSBL、ASN の問い合わせ | いずれか必須（`dig` 推奨）。どちらもない場合、該当チェックは判定不能になります |
| `ping` | レイテンシ測定（仮想ロケーション判定） | 任意 |
| GNU `date` | 登録日・更新日の経過日数の表示 | 任意。macOS 等では日付のみ表示 |
| `fold` / `tput` | テキストレポートの折り返し、端末の幅の取得 | `fold` は必須（coreutils / busybox に含まれる）。`tput` は任意 |

> **Spamhaus の問い合わせについて**  
> Spamhaus は Google Public DNS（8.8.8.8）や Cloudflare（1.1.1.1）などの公開リゾルバ経由の問い合わせを拒否します。実行環境のリゾルバがこれらの場合、DNSBL は毎回「Unknown」となります。ISP のリゾルバ、またはローカルのフルリゾルバ（unbound 等）を利用してください。

## 判定ロジック
本スクリプトは、性質の異なる 2 つの軸で IP を評価し、その組み合わせから調査優先度を決定します。

| 軸 | 内容 | 評価方法 |
| :--- | :--- | :--- |
| **回線種別（インフラ属性）** | どのような回線・設備からのアクセスか | **「日本国内の正規アクセス」** を基準にした加点・減点方式（インフラスコア） |
| **脅威の評判** | 既知の攻撃元・匿名化通信・なりすましに該当するか | 検出の有無（点数なし） |

2 つの軸を分けているのは、**脅威の評判を回線種別の減点で打ち消さないため** です。たとえば、マルウェアに感染した家庭の PC は「国内一般回線」かつ「ブラックリスト登録」となります。両者を 1 つの点数に合算すると低リスクに見えてしまいますが、本スクリプトでは脅威シグナルを検出した時点で調査優先度を HIGH とします。

### 回線種別（インフラ属性）の配点

| 区分 | 評価項目 | 配点 | セキュリティ上の判断根拠 |
| :---: | :--- | :---: | :--- |
| **安全** | **Domestic Consumer ISP / Mobile** | **-5** | NTT（OCN）、KDDI、ソフトバンク、楽天、ドコモ、CATV、電力系光等の国内キャリア。一般利用者が直接接続する正規アクセス回線であるため。※判定方法は下記「国内一般回線の判定方法」を参照 |
| **安全** | **Enterprise SASE / Zero Trust Gateway** | **-5** | Cato Networks、Zscaler、Netskope、Prisma Access 等。企業の業務用端末が社内セキュリティポリシーに基づき中継する正規トラフィックであるため。※PTR による判定は FCrDNS 検証済みの場合のみ採用 |
| **安全** | **Verified Search Engine Crawler** | **-5** | FCrDNS 検証済みの PTR が Google / Bing / Apple / Yandex / Baidu の公式クローラードメインに一致。遮断すると検索インデックス（SEO）に影響するため。 |
| **警戒** | **Datacenter / Hosting / Cloud** | **+3** | AWS、Azure、さくら、ConoHa、海外ホスティング（Zare/Hydra等）。既知のホスティング事業者 ASN、または登録情報・PTR のキーワードで判定。一般端末ではなくサーバー設備帯域であり、ボットや中継プロキシの温床となるため。 |
| **警戒** | **IP Sub-leasing / Domain Discrepancy** | **+3** | レジストリ契約組織（LIR）と運用担当組織のドメインが不一致。海外プロキシ業者への又貸し・再販が行われており、真の発信元追跡を困難にするため。 |
| **警戒** | **Virtual Office / PO Box Address** | **+2** | 組織・グループ等の登録住所に私書箱（Suite, Ste, PO Box, P.O. Box 等）表記。実体オフィスを持たないペーパーカンパニーや不審事業者が身元隠蔽に多用するため。※個人（`individual`）の連絡先住所のみが該当した場合は、配点なしの情報（`[i] Info`）として表示 |
| **警戒** | **Suspected Virtual Location** | **+2** | RDAP の登録国、または Geofeed の申告所在地が JP であるにもかかわらず Ping 応答が 90ms 以上。光速度の物理限界から、実機が欧米等の海外に存在し日本拠点を偽装しているため。※日本国内から実行する前提 |
| **警戒** | **Provider Aggregatable (PA) Block** | **+1** | エンドユーザーへ小分けして再販・貸出を行うための IP アドレス枠であるため。 |
| **警戒** | **Missing Consumer Reverse DNS (PTR)** | **+1** | 逆引き（PTR）が登録されていない、または相手側の逆引きが正常に応答しない（SERVFAIL）。国内大手 ISP は逆引きを必ず運用しており、使える逆引きがないことはサーバー・データセンター用 IP の特徴であるため。※他の警戒項目で加点済みの場合のみ |

### 国内一般回線の判定方法
「Domestic Consumer ISP / Mobile」（-5 点）は、以下のいずれかを根拠として、上から順に判定します。

| 順位 | 根拠 | 例 |
| :---: | :--- | :--- |
| 1 | FCrDNS 検証済みの逆引き（PTR）が国内 ISP のドメイン | `xxx.tokyo.ocn.ne.jp` |
| 2 | 経路を広告している ASN が、国内の一般向け ISP・モバイルキャリアのもの | AS4713（OCN）、AS2516（KDDI）、AS17676（ソフトバンク）、AS9605（ドコモ）等 |
| 3 | ASN を取得できなかった場合に限り、ネットワーク名・登録組織名 | 「NTT Communications Corporation」 |

- **備考欄（remarks）は判定に使いません。** 登録者が自由に記載できるため、転貸先のホスティング事業者が上位回線の事業者名を記載している場合などに誤判定するためです。
- NTT の国際基幹網（AS2914）や、法人・データセンター事業を同じ ASN で行う事業者（IIJ の AS2497 等）は、一般向けとみなしません。
- 登録情報に国内 ISP の名称があるにもかかわらず、ASN が一般向けでない場合は、配点なしの情報（`[i] Info`）として表示します。転送網・法人向け回線・転貸されたホスティング帯域の典型です。

### 登録住所の扱い
RDAP の各エンティティ（登録組織、Abuse 窓口、管理・技術担当者等）が持つ vCard の住所（`adr`）を、エンティティごとに取得して一覧表示します。

- 各住所には、vCard の種別（`individual`: 個人、`org`: 組織、`group`: 窓口・役割等）、名前、役割（`roles`）、ハンドルを併記します。種別が登録されていない場合は `unknown` と表示します。
- 書式付きの住所（`label`）を優先し、ない場合は構造化された要素（番地・市区町村・州・郵便番号・国）から組み立てます。国が含まれる場合は国も表示します。
- 代表の住所（`Holder Address`）は、登録組織（`org` かつ `registrant`）→ 組織 → 登録者 → 最初の住所、の順で選びます。
- 住所は登録者の申告であり、**検証された情報ではありません。**

> **個人情報について**  
> 担当者個人の住所も、RDAP で公開されている情報としてそのまま出力します。出力を報告書等に転記する際は、調査に不要な個人情報を含めないよう注意してください。

### 回線種別の分類
合致した評価項目から、回線種別を以下の優先順で 1 つに分類します。

| 分類 | 条件 |
| :--- | :--- |
| Anonymization Network (Tor) | Tor 出口ノードに合致 |
| Search Engine Crawler (verified) | 検証済みの検索エンジンクローラー |
| Enterprise SASE / Zero Trust Gateway | SASE 事業者に合致 |
| Mixed (domestic ISP and hosting traits) | 国内 ISP とデータセンターの両方の特徴に合致 |
| Domestic Consumer ISP / Mobile | 国内 ISP・モバイルに合致 |
| Datacenter / Hosting / Cloud | データセンター・ホスティング・クラウドに合致 |
| Unclassified | 上記のいずれにも該当しない |

### 脅威の評判
以下のいずれかに該当した場合、脅威シグナルとして検出します。点数は付けず、回線種別の減点でも打ち消されません。

| 評価項目 | 判断根拠 |
| :--- | :--- |
| **Confirmed Tor Exit Node** | Tor Project 公式のアクティブ出口ノード一覧に合致。オニオンルーティングによる匿名化通信であり、真の発信元を追跡できないため。 |
| **Public Threat Blacklist (DNSBL)** | Spamhaus ZEN の SBL / CSS / XBL / DROP に登録済み。既知のスパム送信元、マルウェア感染端末（ボットネット）、不正プロキシ、犯罪者管理下のネットワーク等であるため。※PBL のみの登録は一般回線の動的 IP を示すため、情報表示のみで脅威とはみなさない |
| **Spoofed Search Engine Crawler PTR** | PTR が検索エンジンのクローラードメインを名乗っているが、正引きで元の IP に戻らない。正規クローラーへのなりすましであり、ボット対策の回避を狙ったスクレイパーの典型であるため。 |

判定結果は次の 3 種類です。

| 結果 | 意味 |
| :--- | :--- |
| `DETECTED` | 脅威シグナルを 1 つ以上検出 |
| `NONE FOUND` | 確認したデータソースの範囲では検出なし（安全の証明ではない） |
| `UNKNOWN` | Tor または DNSBL のチェックを完了できなかった |

### 調査優先度

| 調査優先度 | 条件 | 想定される状況 |
| :---: | :--- | :--- |
| **HIGH** | 脅威シグナルを検出、またはインフラスコアが 4 点以上 | 既知の攻撃元・匿名化通信・なりすまし、またはデータセンター回線・IP 転貸・私書箱住所などが重複して検出された回線。優先的に調査する |
| **MEDIUM** | インフラスコアが 1〜3 点 | 一般回線とは異なる属性（クラウド帯域、PA 小分け割り当て等）が一部確認された状態。個人 VPN、スクレイピングツール、連携サービス等の可能性 |
| **LOW** | 上記以外 | 回線属性に異常なし。ただし **安全という意味ではない**（後述） |

調査優先度が LOW の場合、レポート先頭のサマリーに次の注意書き（`Note`）を表示します。

| 状況 | 注意書きの内容 |
| :--- | :--- |
| 通常の LOW | LOW は安全という意味ではない。マルウェアに感染した端末や住宅用プロキシ（一般家庭の回線を中継に使うサービス）も同じように見える |
| 検証済みクローラー | 遮断すると検索インデックスに影響する |

### 所在地の整合性チェック
IP の所在地について、性質の異なる 3 つの情報を突き合わせ、`Location Check` として表示します（表示のみで、配点は仮想ロケーション判定を除き行いません）。

| 情報 | 取得元 | 性質 |
| :--- | :--- | :--- |
| 登録国 | RDAP の `country` | レジストリへの登録情報。本社所在国が登録されている場合がある |
| 申告所在地（Geofeed） | RDAP が示す Geofeed（RFC 8805 / RFC 9632）の CSV | IP の運営者が自己申告する利用地。**検証された情報ではない** |
| 遅延 | `ping` の応答時間 | 物理的な距離の目安。ICMP を遮断している IP では取得できない |

Geofeed の URL は、RDAP の `links`（`rel: geofeed`）、または備考欄の `Geofeed https://...` 形式から取得します。CSV のうち、対象 IP を含む最も細かいプレフィックスの行を採用します。

| 結果 | 条件 |
| :--- | :--- |
| `DECLARATIONS DIFFER` | 登録国と申告所在地の国が異なる |
| `MISMATCH` | JP と登録・申告されているのに、遅延が 90ms 以上 |
| `CONSISTENT` | JP と登録・申告されており、遅延が 90ms 未満 |
| `NOT VERIFIED` | Ping の応答がなく、遅延で確認できない |
| `NOT EVALUATED` | JP 以外の登録・申告（遅延の閾値は JP 用のみ） |

> Geofeed の URL は IP の登録者が自由に記載できる値のため、`https://` の URL のみを受け付け、取得サイズ（50MB）と時間（20 秒）に上限を設けています。取得した CSV は照合後に削除します。

### 判定不能の扱い
外部サービスの障害、DNS 問い合わせの失敗、必要なコマンドの不在などでチェックを完了できなかった場合、該当項目は「Clean」や「No」ではなく **「Unknown」** と表示し、加点しません。  
このときレポート先頭のサマリーの `Confidence` 行が `PARTIAL` となり、完了できなかったチェックが列挙されます。Tor または DNSBL を確認できなかった場合、脅威の評判は `UNKNOWN` となります。**表示された調査優先度より実際の優先度が高い可能性がある** ことに注意してください。

対象となるチェック: Tor 出口ノード、DNSBL（Spamhaus ZEN）、ASN（Team Cymru）、逆引き（PTR）、FCrDNS、Geofeed（URL が公開されているが取得できなかった場合）

#### 逆引きの SERVFAIL について
逆引き・正引きの問い合わせで SERVFAIL が返った場合は、実行環境側の問題か、相手側の問題かを切り分けます。SERVFAIL を受け取ると、ルートサーバー（`a.root-servers.net`）の正引きでリゾルバの健全性を 1 回だけ確認します。

| 状況 | 扱い |
| :--- | :--- |
| リゾルバは正常（相手側の逆引きが壊れている） | 判定不能にはせず、「使える逆引きなし」という確定した結果として扱う。ホスティング帯域でよく見られる状態 |
| リゾルバも異常 | 実行環境側の問題として「Unknown」（判定不能） |
| タイムアウト・コマンドの不在 | 実行環境側の問題として「Unknown」（判定不能） |

FCrDNS の正引きが相手側で SERVFAIL となった場合は、「Not verified」（正引きが一致しない）として扱います。検索エンジンのクローラーを名乗る逆引きでこの状態になった場合は、偽装クローラーとして検出されます。

## 出力
### 出力内容
テキストレポートは、結論（サマリー）を先頭に表示し、続いて詳細を用途別に表示します。

| セクション | 内容 |
| :--- | :--- |
| サマリー | 対象IP、実行日時、ツールバージョン、調査優先度、回線種別の分類とインフラスコア、脅威の評判、判定の信頼度（Confidence）、注意書き（該当時のみ） |
| NETWORK | ネットワーク名・ハンドル、割当範囲・CIDR、割当種別、登録日・最終更新日（経過日数）、管轄RIR、備考、ASN / AS 名 / BGP プレフィックス / ASN 登録国 / プレフィックス割当日、逆引き（PTR）、FCrDNS 検証結果 |
| LOCATION | 登録国、Geofeed の申告所在地、代表の住所（Holder Address）とその国、Ping レイテンシ、所在地の整合性チェック |
| CONTACTS | エンティティごとの登録住所（種別・名前・役割・ハンドル付き）、Abuse 連絡先、エンティティ名、関与メールアドレスとドメイン |
| INFRASTRUCTURE ATTRIBUTES | 回線種別の全評価項目と、その配点・根拠。**該当しなかった項目や判定不能の項目も含めて** 一覧表示 |
| THREAT REPUTATION | 脅威の評判の全評価項目（Spamhaus ZEN、Tor 出口ノード、偽装クローラー）と、その結果 |
| DETAILS | 各評価項目の判定根拠（Evidence / Reason）。`--verbose` 指定時のみ |
| DATA SOURCES | 各チェックの取得元（RDAP の取得元URL、Geofeed の URL を含む）、DNS リゾルバ、RDAP 生データの保存先 |

### 記号

| 意味 | 標準（絵文字） | `--plain` |
| :--- | :---: | :---: |
| 警戒・脅威に該当、調査優先度 HIGH | 🔴 | `[!]` |
| 調査優先度 MEDIUM、信頼度 PARTIAL、申告の不一致 | 🟡 | `[~]` |
| 安全側に該当、調査優先度 LOW、信頼度 FULL、所在地の整合 | 🟢 | `[o]` |
| 配点なしの情報 | 🔵 | `[i]` |
| 該当なし | ⚪ | `[ ]` |
| 判定不能 | ❔ | `[?]` |

> 絵文字は端末やフォントによって表示幅が異なり、列がずれたり表示できなかったりする場合があります。その場合や、出力をログとして保存・検索する場合は `--plain` を使用してください。JSON 出力には絵文字を含みません。

### 表示の折り返し
住所などの値は省略せず、端末の幅を超える場合は字下げして折り返して表示します。端末の幅は、環境変数 `COLUMNS`、端末から取得した幅、100 桁の順で決定します（最小 60 桁）。

### エラー時の出力
RDAP の取得に失敗した場合は、エラーメッセージを標準エラー出力に表示し、終了コード 1 で終了します。`--json` 指定時は、あわせて `error` キーを含む JSON を標準出力に出力します。

### JSON 出力（`--json`）
主なキーは以下のとおりです。

| キー | 内容 |
| :--- | :--- |
| `tool` / `executed_at` / `target_ip` | ツール名・バージョン、実行日時、対象IP |
| `network` | ネットワーク名・ハンドル・国・割当種別・範囲・CIDR・登録日・更新日・RIR・代表の住所（`address`）・その国（`holder_country`）・備考、エンティティごとの住所（`addresses`: `kind`、`name`、`roles`、`handle`、`address`、`country` の配列） |
| `asn` | ASN、AS 名、BGP プレフィックス、ASN 登録国、プレフィックス割当日 |
| `dns` | PTR、`ptr_status`（`found`: 取得成功 / `none`: 登録なし / `broken`: 相手側で SERVFAIL / `failed`: 実行環境側の失敗）、FCrDNS の結果（`fcrdns_verified` は真偽値） |
| `ping_ms` / `tor_exit_node` / `dnsbl` | レイテンシ（取得できない場合は `null`）、Tor 判定、DNSBL 判定 |
| `location` | `registered_country`（RDAP の登録国）、`geofeed`（`status`、`prefix`、`country`、`region`、`city`）、`check`（所在地の整合性チェックの結果） |
| `abuse_contacts` / `entities` / `emails` | Abuse 連絡先、関与組織名、関与メールアドレス |
| `indicators` | 合致した評価項目の配列（`type`: `risk` / `safe` / `threat` / `info`、`points`、`name`、`details`）。`threat` の `points` は常に 0 |
| `summary` | `priority`（`HIGH` / `MEDIUM` / `LOW`）、`result`、`infrastructure`（`class`、`score`）、`threat`（`level`: `DETECTED` / `NONE_FOUND` / `UNKNOWN`、`signals`）、`note`（該当しない場合は `null`）、`confidence`（`FULL` / `PARTIAL`）、`unavailable_checks` |
| `sources` | RDAP 取得元URL、各データソース、Geofeed の URL、DNS リゾルバ、RDAP 生データの保存先 |

RDAP の取得に失敗した場合は、`error` キーを含む JSON を出力して終了コード 1 で終了します。

```json
{
  "target_ip": "203.0.113.10",
  "summary": {
    "priority": "HIGH",
    "result": "PRIORITY HIGH / Domestic Consumer ISP / Mobile",
    "infrastructure": { "class": "Domestic Consumer ISP / Mobile", "score": -5 },
    "threat": { "level": "DETECTED", "signals": ["Spamhaus XBL"] },
    "note": null,
    "confidence": "FULL",
    "unavailable_checks": []
  },
  "indicators": [
    { "type": "safe", "points": -5, "name": "Domestic Consumer ISP / Mobile Carrier detected", "details": ["..."] },
    { "type": "threat", "points": 0, "name": "Public Threat Blacklist (Spamhaus XBL)", "details": ["..."] }
  ]
}
```

> バージョン 1.2.0 で `summary` の構造を変更しました（`score` → `infrastructure.score`、`priority` / `threat` / `note` を追加）。

### 証跡
スクリプト実行時、APNIC / RIPE 等から返却された生のRDAPレスポンスが以下のパスに保存されます。  
保存先パス: `/tmp/rdap_<IPアドレス>.json`

診断結果を証跡として残す場合は、`--json` の出力をファイルに保存してください。実行日時・ツールバージョン・各データの取得元・判定根拠がすべて含まれます。  
※ `/tmp` 配下の RDAP 生データは OS により自動削除される場合があるため、必要に応じて JSON とあわせて別の場所へ保管してください。

## 免責事項 / Disclaimer

### 日本語
1. **診断結果の性質と限界**  
   本スクリプトが出力する調査優先度、回線種別の分類、インフラスコアおよび脅威の評判は、公的レジストリ（APNIC / JPNIC / RIPE / ARIN 等）が公開するネットワーク登録情報、DNS 逆引きおよび正引き、ICMP 応答、外部データソース（Tor Project 出口ノード一覧、Spamhaus ZEN、Team Cymru IP to ASN Mapping、IP 運営者が自己申告する Geofeed）に基づく**「インフラ属性上の推定情報」**です。対象IPによる通信内容そのものの無害性、正規性、または安全性を100%保証するものではありません。
2. **アカウント侵害・マルウェア感染のリスク**  
   調査優先度が「LOW」、または脅威の評判が「NONE FOUND」と判定された場合であっても、正規エンドユーザーの端末がマルウェア（ボットネット等）に感染している可能性や、盗まれた正規アカウントによる不正アクセスの可能性を排除するものではありません。最終的な脅威判断は、必ずアプリケーションログや認証ログの振る舞い（ステータスコード、リクエストパラメータ等）と併せて実施してください。
3. **運用・遮断判断に伴う責任**  
   本スクリプトの診断結果に基づいて実施されたアクセス遮断（WAF やファイアウォールへの拒否登録）、通信制限、サービス停止等に起因する直接的・間接的な損害（業務停止、逸失利益、正規ユーザーからのクレーム等）について、本スクリプトの作成者および提供者は一切の責任を負いません。通信の遮断にあたっては、システム管理者の責任において十分なログ精査および影響範囲の確認を行ってください。
4. **外部サービスの仕様変更および制限**  
   RDAP / Whois、Tor Project、Spamhaus、Team Cymru 等の提供元の仕様変更、一時的な障害、問い合わせ過多によるレートリミット（アクセス制限）、またはお客様環境のファイアウォール設定（ICMP / HTTP 制限）等により、正確な情報が取得できない場合があります。

---

### English
1. **Nature and Limitations of Assessment**  
   The investigation priority, infrastructure classification, infrastructure score, and threat reputation provided by this script are heuristic evaluations based on publicly available registry data (APNIC, JPNIC, RIPE, ARIN, etc.), reverse and forward DNS (PTR / FCrDNS), ICMP latency, and external data sources (Tor Project exit list, Spamhaus ZEN, Team Cymru IP to ASN Mapping, and operator-declared geofeeds). This tool does not guarantee the safety, legitimacy, or harmlessness of any underlying HTTP request or communication payload.
2. **Risk of Endpoint Compromise**  
   A "LOW" priority or a "NONE FOUND" threat reputation indicates only that no infrastructure-level anomalies or listings were found in the checked sources; it does not preclude scenarios involving malware-infected legitimate hosts (e.g., botnets), credential stuffing, or authorized account takeovers. Operational decisions must cross-reference application-layer behavior and authentication logs.
3. **Limitation of Liability**  
   The authors and distributors of this script accept no liability for any direct, indirect, incidental, or consequential damages (including, but not limited to, business interruption, loss of profits, or service disruptions) resulting from operational actions, firewall rules, or IP-blocking measures implemented based on this tool's output. Administrators are solely responsible for verifying logs prior to enforcing containment actions.
4. **External Service Availability & Rate Limits**  
   Lookup accuracy depends on the availability of external services (RIRs, Tor Project, Spamhaus, Team Cymru) and local network permissions. Spamhaus refuses queries via public DNS resolvers. Query limitations, rate limits, or outbound network filtering may impact the completeness of the retrieved intelligence.