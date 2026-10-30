# IPアドレスリスク診断スクリプト (ip-assess.sh)
## 概要
本スクリプトは、アクセス元IPアドレスを調査し、その属性（一般回線、データセンター、匿名プロキシ、企業向け SASE 等）を分析してリスクを判定する診断ツールです。  

## Usage
```
./ip-assess.sh [オプション] <IPv4アドレス>
```

| オプション | 内容 |
| :--- | :--- |
| `--json` | テキストレポートの代わりに JSON（機械可読形式）のみを標準出力へ出力 |
| `-v`, `--version` | バージョンを表示 |
| `-h`, `--help` | ヘルプを表示 |

```
# テキストレポート
./ip-assess.sh 203.0.113.10

# JSON を証跡として保存
./ip-assess.sh --json 203.0.113.10 > ip-assess_203.0.113.10.json
```

> 対象は **IPv4 のみ** です。IPv4 として正しくない文字列を指定した場合はエラーで終了します。

## 動作要件
| コマンド | 用途 | 備考 |
| :--- | :--- | :--- |
| `bash` / `curl` / `awk` / `sed` / `grep` | 本体処理、RDAP・Tor 出口ノード一覧の取得、RDAP（JSON）の解析 | 必須 |
| `dig` または `host` | 逆引き・FCrDNS、DNSBL、ASN の問い合わせ | いずれか必須（`dig` 推奨）。どちらもない場合、該当チェックは判定不能になります |
| `ping` | レイテンシ測定（仮想ロケーション判定） | 任意 |
| GNU `date` | 登録日・更新日の経過日数の表示 | 任意 |

> **Spamhaus の問い合わせについて**  
> Spamhaus は Google Public DNS（8.8.8.8）や Cloudflare（1.1.1.1）などの公開リゾルバ経由の問い合わせを拒否します。実行環境のリゾルバがこれらの場合、DNSBL は毎回「Unknown」となります。ISP のリゾルバ、またはローカルのフルリゾルバ（unbound 等）を利用してください。

## リスク判定基準と配点ロジック
本スクリプトは **「日本国内の正規アクセス」** を基準にしてインフラ属性を加点・減点方式でスコアリングし、累積スコアによって 3 段階でリスクを分類します。

### 配点マトリクス

| 区分 | 評価項目 | 配点 | セキュリティ上の判断根拠 |
| :---: | :--- | :---: | :--- |
| **安全** | **Domestic Consumer ISP / Mobile** | **-5** | NTT（OCN）、KDDI、ソフトバンク、楽天、ドコモ、CATV、電力系光等の国内キャリア。一般利用者が直接接続する正規アクセス回線であるため。※PTR による判定は FCrDNS 検証済みの場合のみ採用 |
| **安全** | **Enterprise SASE / Zero Trust Gateway** | **-5** | Cato Networks、Zscaler、Netskope、Prisma Access 等。企業の業務用端末が社内セキュリティポリシーに基づき中継する正規トラフィックであるため。※PTR による判定は FCrDNS 検証済みの場合のみ採用 |
| **安全** | **Verified Search Engine Crawler** | **-5** | FCrDNS 検証済みの PTR が Google / Bing / Apple / Yandex / Baidu の公式クローラードメインに一致。遮断すると検索インデックス（SEO）に影響するため。 |
| **警戒** | **Confirmed Tor Exit Node** | **+5** | Tor Project 公式のアクティブ出口ノード一覧に合致。オニオンルーティングによる完全匿名化通信であり、正規業務では通常利用されないため。 |
| **警戒** | **Public Threat Blacklist (DNSBL)** | **+4** | Spamhaus ZEN の SBL / CSS / XBL / DROP に登録済み。既知のスパム送信元、マルウェア感染端末、不正プロキシ、犯罪者管理下のネットワーク等であるため。※PBL のみの登録は一般回線の動的 IP を示すため加点しない |
| **警戒** | **Datacenter / Hosting / Cloud** | **+3** | AWS、Azure、さくら、ConoHa、海外ホスティング（Zare/Hydra等）。既知のホスティング事業者 ASN、または登録情報・PTR のキーワードで判定。一般端末ではなくサーバー設備帯域であり、ボットや中継プロキシの温床となるため。 |
| **警戒** | **Spoofed Search Engine Crawler PTR** | **+3** | PTR が検索エンジンのクローラードメインを名乗っているが、正引きで元の IP に戻らない。正規クローラーへのなりすましであり、ボット対策の回避を狙ったスクレイパーの典型であるため。 |
| **警戒** | **IP Sub-leasing / Domain Discrepancy** | **+3** | レジストリ契約組織（LIR）と運用担当組織のドメインが不一致。海外プロキシ業者への又貸し・再販が行われており、真の発信元追跡を困難にするため。 |
| **警戒** | **Virtual Office / PO Box Address** | **+2** | 管理者住所に私書箱（Suite, PO Box）表記。実体オフィスを持たないペーパーカンパニーや不審事業者が身元隠蔽に多用するため。 |
| **警戒** | **Suspected Virtual Location** | **+2** | 登録国が JP であるにもかかわらず Ping 応答が 90ms 以上。光速度の物理限界から、実機が欧米等の海外に存在し日本拠点を偽装しているため。 |
| **警戒** | **Provider Aggregatable (PA) Block** | **+1** | エンドユーザーへ小分けして再販・貸出を行うための IP アドレス枠であるため。 |
| **警戒** | **Missing Consumer Reverse DNS (PTR)** | **+1** | 国内大手 ISP 特有のホスト名が付与されておらず、サーバー・データセンター用静的 IP の特徴を持つため。※他の警戒項目で加点済みの場合のみ |

### 判定不能の扱い
外部サービスの障害、DNS 問い合わせの失敗、必要なコマンドの不在などでチェックを完了できなかった場合、該当項目は「Clean」や「No」ではなく **「Unknown」** と表示し、加点しません。  
このとき Report Summary の `Confidence` 行が `PARTIAL` となり、完了できなかったチェックが列挙されます。**実際のリスクは表示スコアより高い可能性がある** ことに注意してください。

対象となるチェック: Tor 出口ノード、DNSBL（Spamhaus ZEN）、ASN（Team Cymru）、逆引き（PTR）、FCrDNS

## 出力
### 出力内容
| 項目 | 出力内容 |
| :--- | :--- |
| [1] IP information | 対象IP、実行日時、ツールバージョン、使用DNSリゾルバ、RDAP取得ステータスと取得元URL（リダイレクト後に実際に回答したRIR） |
| [2] Network Information  | ネットワーク名・ハンドル、国、割当種別、割当範囲・CIDR、登録日・最終更新日（経過日数）、管轄RIR、管理者住所、備考、逆引き（PTR）と FCrDNS 検証結果、Ping レイテンシ、Tor 出口ノード判定、DNSBL 判定（リスト種別）、ASN / AS 名 / BGP プレフィックス / ASN 登録国 / プレフィックス割当日、Abuse 連絡先、関与組織・担当者ドメイン一覧 |
| [3] Risk Analysis & Scoring  | 各評価項目の合致状況と配点根拠 |
| [4] Report Summary | 総合スコア、判定の信頼度（Confidence）、判定結果 |
| [5] Data Sources | 各チェックの取得元、RDAP 生データの保存先 |

### JSON 出力（`--json`）
主なキーは以下のとおりです。

| キー | 内容 |
| :--- | :--- |
| `tool` / `executed_at` / `target_ip` | ツール名・バージョン、実行日時、対象IP |
| `network` | ネットワーク名・ハンドル・国・割当種別・範囲・CIDR・登録日・更新日・RIR・住所・備考 |
| `asn` | ASN、AS 名、BGP プレフィックス、ASN 登録国、プレフィックス割当日 |
| `dns` | PTR、FCrDNS の結果（`fcrdns_verified` は真偽値） |
| `ping_ms` / `tor_exit_node` / `dnsbl` | レイテンシ（取得できない場合は `null`）、Tor 判定、DNSBL 判定 |
| `abuse_contacts` / `entities` / `emails` | Abuse 連絡先、関与組織名、関与メールアドレス |
| `indicators` | 合致した評価項目の配列（`type`: `risk` / `safe` / `info`、`points`、`name`、`details`） |
| `summary` | `score`、`result`、`confidence`（`FULL` / `PARTIAL`）、`unavailable_checks` |
| `sources` | RDAP 取得元URL、各データソース、DNS リゾルバ、RDAP 生データの保存先 |

RDAP の取得に失敗した場合は、`error` キーを含む JSON を出力して終了コード 1 で終了します。

```json
{
  "target_ip": "203.0.113.10",
  "summary": { "score": 3, "result": "MEDIUM RISK / ...", "confidence": "FULL", "unavailable_checks": [] },
  "indicators": [
    { "type": "risk", "points": 3, "name": "Datacenter / Hosting / Cloud infrastructure detected",
      "details": ["Evidence: Known hosting ASN matched AS16509 (AMAZON-02, US)", "Reason: ..."] }
  ]
}
```

### スコア
| スコア | リスク | 評価 | 注意点 |
| :--- | :--- | :--- | :--- |
| 0点以下 | 低 | 国内通信キャリアの一般回線、正規のエンタープライズSASE、または検証済みの検索エンジンクローラー。 |インフラ自体の匿名化はないが、マルウェア感染端末によるボット化や、認証情報窃取による不正アクセスの可能性はあり。 |
| 1〜3点  | 中 | 一般回線とは異なる属性（クラウド帯域、PA 小分け割り当て等）が一部確認された状態。| 個人 VPN、スクレイピングツール、未承認クラウドからのアクセスの可能性があり |
| 4点以上  | 高 | データセンター回線、IP 転貸（ドメイン不一致）、私書箱住所などが重複して検出された高リスク回線。| 一般ユーザーが直接アクセスしてくる回線ではなく、海外攻撃者の身元偽装やボット中継拠点である可能性が極めて高い。 |


### 証跡
スクリプト実行時、APNIC / RIPE 等から返却された生のRDAPレスポンスが以下のパスに保存されます。  
保存先パス: `/tmp/rdap_<IPアドレス>.json`

診断結果を証跡として残す場合は、`--json` の出力をファイルに保存してください。実行日時・ツールバージョン・各データの取得元・判定根拠がすべて含まれます。  
※ `/tmp` 配下の RDAP 生データは OS により自動削除される場合があるため、必要に応じて JSON とあわせて別の場所へ保管してください。

## 免責事項 / Disclaimer

### 日本語
1. **診断結果の性質と限界**  
   本スクリプトが出力する判定結果およびリスクスコアは、公的レジストリ（APNIC / JPNIC / RIPE / ARIN 等）が公開するネットワーク登録情報、DNS 逆引きおよび正引き、ICMP 応答、外部データソース（Tor Project 出口ノード一覧、Spamhaus ZEN、Team Cymru IP to ASN Mapping）に基づく**「インフラ属性上の推定情報」**です。対象IPによる通信内容そのものの無害性、正規性、または安全性を100%保証するものではありません。
2. **アカウント侵害・マルウェア感染のリスク**  
   「低リスク / 安全（LOW RISK）」と判定された場合であっても、正規エンドユーザーの端末がマルウェア（ボットネット等）に感染している可能性や、盗まれた正規アカウントによる不正アクセスの可能性を排除するものではありません。最終的な脅威判断は、必ずアプリケーションログや認証ログの振る舞い（ステータスコード、リクエストパラメータ等）と併せて実施してください。
3. **運用・遮断判断に伴う責任**  
   本スクリプトの診断結果に基づいて実施されたアクセス遮断（WAF やファイアウォールへの拒否登録）、通信制限、サービス停止等に起因する直接的・間接的な損害（業務停止、逸失利益、正規ユーザーからのクレーム等）について、本スクリプトの作成者および提供者は一切の責任を負いません。通信の遮断にあたっては、システム管理者の責任において十分なログ精査および影響範囲の確認を行ってください。
4. **外部サービスの仕様変更および制限**  
   RDAP / Whois、Tor Project、Spamhaus、Team Cymru 等の提供元の仕様変更、一時的な障害、問い合わせ過多によるレートリミット（アクセス制限）、またはお客様環境のファイアウォール設定（ICMP / HTTP 制限）等により、正確な情報が取得できない場合があります。

---

### English
1. **Nature and Limitations of Assessment**  
   The assessment results and risk scores provided by this script are heuristic evaluations based on publicly available registry data (APNIC, JPNIC, RIPE, ARIN, etc.), reverse and forward DNS (PTR / FCrDNS), ICMP latency, and external data sources (Tor Project exit list, Spamhaus ZEN, Team Cymru IP to ASN Mapping). This tool does not guarantee the safety, legitimacy, or harmlessness of any underlying HTTP request or communication payload.
2. **Risk of Endpoint Compromise**  
   A "LOW RISK" verdict indicates the absence of infrastructure-level anonymization/proxying; it does not preclude scenarios involving malware-infected legitimate hosts (e.g., botnets), credential stuffing, or authorized account takeovers. Operational decisions must cross-reference application-layer behavior and authentication logs.
3. **Limitation of Liability**  
   The authors and distributors of this script accept no liability for any direct, indirect, incidental, or consequential damages (including, but not limited to, business interruption, loss of profits, or service disruptions) resulting from operational actions, firewall rules, or IP-blocking measures implemented based on this tool's output. Administrators are solely responsible for verifying logs prior to enforcing containment actions.
4. **External Service Availability & Rate Limits**  
   Lookup accuracy depends on the availability of external services (RIRs, Tor Project, Spamhaus, Team Cymru) and local network permissions. Spamhaus refuses queries via public DNS resolvers. Query limitations, rate limits, or outbound network filtering may impact the completeness of the retrieved intelligence.