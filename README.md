# IPアドレスリスク診断スクリプト (ip-assess.sh)
## 概要
本スクリプトは、アクセス元IPアドレスを調査し、その属性（一般回線、データセンター、匿名プロキシ、企業向け SASE 等）を分析してリスクを判定する診断ツールです。  

## Usage
```
./ip-assess.sh <IPアドレス>
```

## リスク判定基準と配点ロジック
本スクリプトは **「日本国内の正規アクセス」** を基準にしてインフラ属性を加点・減点方式でスコアリングし、累積スコアによって 3 段階でリスクを分類します。

### 配点マトリクス

| 区分 | 評価項目 | 配点 | セキュリティ上の判断根拠 |
| :---: | :--- | :---: | :--- |
| **安全** | **Domestic Consumer ISP / Mobile** | **-5** | NTT（OCN）、KDDI、ソフトバンク、楽天、ドコモ、CATV、電力系光等の国内キャリア。一般利用者が直接接続する正規アクセス回線であるため。 |
| **安全** | **Enterprise SASE / Zero Trust Gateway** | **-5** | Cato Networks、Zscaler、Netskope、Prisma Access 等。企業の業務用端末が社内セキュリティポリシーに基づき中継する正規トラフィックであるため。 |
| **警戒** | **Confirmed Tor Exit Node** | **+5** | Tor Project 公式のアクティブ出口ノード一覧に合致。オニオンルーティングによる完全匿名化通信であり、正規業務では通常利用されないため。 |
| **警戒** | **Public Threat Blacklist (DNSBL)** | **+4** | Spamhaus ZEN 等のグローバル脅威ブラックリストに登録済み。既知の攻撃ボット、マルウェア感染端末、オープンプロキシ等であるため。 |
| **警戒** | **Datacenter / Hosting / Cloud** | **+3** | AWS、Azure、さくら、ConoHa、海外ホスティング（Zare/Hydra等）。一般端末ではなくサーバー設備帯域であり、ボットや中継プロキシの温床となるため。 |
| **警戒** | **IP Sub-leasing / Domain Discrepancy** | **+3** | レジストリ契約組織（LIR）と運用担当組織のドメインが不一致。海外プロキシ業者への又貸し・再販が行われており、真の発信元追跡を困難にするため。 |
| **警戒** | **Virtual Office / PO Box Address** | **+2** | 管理者住所に私書箱（Suite, PO Box）表記。実体オフィスを持たないペーパーカンパニーや不審事業者が身元隠蔽に多用するため。 |
| **警戒** | **Suspected Virtual Location** | **+2** | 登録国が JP であるにもかかわらず Ping 応答が 90ms 以上。光速度の物理限界から、実機が欧米等の海外に存在し日本拠点を偽装しているため。 |
| **警戒** | **Provider Aggregatable (PA) Block** | **+1** | エンドユーザーへ小分けして再販・貸出を行うための IP アドレス枠であるため。 |
| **警戒** | **Missing Consumer Reverse DNS (PTR)** | **+1** | 国内大手 ISP 特有のホスト名が付与されておらず、サーバー・データセンター用静的 IP の特徴を持つため |

## 出力
### 出力内容
| 項目 | 出力内容 |
| :--- | :--- |
| IP information | 対象IPとRDAP取得ステータス |
| Network Information  | ネットワーク名、国、管轄RIR、関与組織・担当者ドメイン一覧 |
| Risk Analysis & Scoring  | 各評価項目の合致状況と配点根拠 |
| Report Summary | 総合スコア、判定結果 |

### スコア
| スコア | リスク | 評価 | 注意点 |
| :--- | :--- | :--- | :--- |
| 0点以下 | 低 | 国内通信キャリアの一般回線、または正規のエンタープライズSASE。 |インフラ自体の匿名化はないが、マルウェア感染端末によるボット化や、認証情報窃取による不正アクセスの可能性はあり。 |
| 1〜3点  | 中 | 一般回線とは異なる属性（クラウド帯域、PA 小分け割り当て等）が一部確認された状態。| 個人 VPN、スクレイピングツール、未承認クラウドからのアクセスの可能性があり |
| 4点以上  | 高 | データセンター回線、IP 転貸（ドメイン不一致）、私書箱住所などが重複して検出された高リスク回線。| 一般ユーザーが直接アクセスしてくる回線ではなく、海外攻撃者の身元偽装やボット中継拠点である可能性が極めて高い。 |


### 証跡
スクリプト実行時、APNIC / RIPE 等から返却された生のRDAPレスポンスが以下のパスに保存されます。  
保存先パス: `/tmp/rdap_<IPアドレス>.json`

## 免責事項 / Disclaimer

### 日本語
1. **診断結果の性質と限界**  
   本スクリプトが出力する判定結果およびリスクスコアは、公的レジストリ（APNIC / JPNIC / RIPE / ARIN 等）が公開するネットワーク登録情報、DNS 逆引き、ICMP 応答に基づく**「インフラ属性上の推定情報」**です。対象IPによる通信内容そのものの無害性、正規性、または安全性を100%保証するものではありません。
2. **アカウント侵害・マルウェア感染のリスク**  
   「低リスク / 安全（LOW RISK）」と判定された場合であっても、正規エンドユーザーの端末がマルウェア（ボットネット等）に感染している可能性や、盗まれた正規アカウントによる不正アクセスの可能性を排除するものではありません。最終的な脅威判断は、必ずアプリケーションログや認証ログの振る舞い（ステータスコード、リクエストパラメータ等）と併せて実施してください。
3. **運用・遮断判断に伴う責任**  
   本スクリプトの診断結果に基づいて実施されたアクセス遮断（WAF やファイアウォールへの拒否登録）、通信制限、サービス停止等に起因する直接的・間接的な損害（業務停止、逸失利益、正規ユーザーからのクレーム等）について、本スクリプトの作成者および提供者は一切の責任を負いません。通信の遮断にあたっては、システム管理者の責任において十分なログ精査および影響範囲の確認を行ってください。
4. **外部サービスの仕様変更および制限**  
   RDAP / Whois 提供元の仕様変更、一時的な障害、問い合わせ過多によるレートリミット（アクセス制限）、またはお客様環境のファイアウォール設定（ICMP / HTTP 制限）等により、正確な情報が取得できない場合があります。

---

### English
1. **Nature and Limitations of Assessment**  
   The assessment results and risk scores provided by this script are heuristic evaluations based on publicly available registry data (APNIC, JPNIC, RIPE, ARIN, etc.), Reverse DNS (PTR), and ICMP latency. This tool does not guarantee the safety, legitimacy, or harmlessness of any underlying HTTP request or communication payload.
2. **Risk of Endpoint Compromise**  
   A "LOW RISK" verdict indicates the absence of infrastructure-level anonymization/proxying; it does not preclude scenarios involving malware-infected legitimate hosts (e.g., botnets), credential stuffing, or authorized account takeovers. Operational decisions must cross-reference application-layer behavior and authentication logs.
3. **Limitation of Liability**  
   The authors and distributors of this script accept no liability for any direct, indirect, incidental, or consequential damages (including, but not limited to, business interruption, loss of profits, or service disruptions) resulting from operational actions, firewall rules, or IP-blocking measures implemented based on this tool's output. Administrators are solely responsible for verifying logs prior to enforcing containment actions.
4. **External Service Availability & Rate Limits**  
   Lookup accuracy depends on external RIR availability and local network permissions. Query limitations, rate limits, or outbound network filtering may impact the completeness of the retrieved intelligence.
