#!/usr/bin/env bash

# ============================================================
# Risk Assessment Script for IP Addresses
# ============================================================

IP="$1"

if [ -z "$IP" ]; then
    echo "Usage: $0 <IP_ADDRESS>"
    exit 1
fi

TMP_FILE="/tmp/rdap_${IP}.json"

echo "================================================================================"
echo "[1] IP information"
echo "================================================================================"
echo "Target IP       : ${IP}"
echo "RDAP Temporary File : ${TMP_FILE}"

# RDAP取得
HTTP_STATUS=$(curl -sL -w "%{http_code}" -o "${TMP_FILE}" "https://rdap.apnic.net/ip/${IP}")
if [ "$HTTP_STATUS" != "200" ]; then
    echo "Error: Failed to retrieve information (HTTP Status: ${HTTP_STATUS})"
    exit 1
fi
echo "Retrieval Status: Success (HTTP 200)"

# 逆引き(PTR)
PTR="None"
if command -v host >/dev/null 2>&1; then
    PTR=$(host "${IP}" 2>/dev/null | awk '{print $NF}' | sed 's/\.$//')
elif command -v dig >/dev/null 2>&1; then
    PTR=$(dig -x "${IP}" +short 2>/dev/null | sed 's/\.$//')
elif command -v nslookup >/dev/null 2>&1; then
    PTR=$(nslookup "${IP}" 2>/dev/null | awk -F'= ' '/name =/ {print $2}' | sed 's/\.$//')
fi
[ -z "$PTR" ] && PTR="None"

# Pingレイテンシ測定
PING_MS=""
PING_VAL=0
if command -v ping >/dev/null 2>&1; then
    PING_MS=$(ping -c 2 -w 2 "${IP}" 2>/dev/null | awk -F'/' '/rtt|round-trip/ {print $5}')
    if [ -n "$PING_MS" ]; then
        PING_VAL=$(echo "$PING_MS" | awk '{print int($1)}')
        PING_STR="${PING_MS} ms"
    else
        PING_STR="No response (ICMP blocked)"
    fi
else
    PING_STR="Command not found"
fi

# 判定不能だった項目の記録（スコアの信頼性表示に使用）
UNAVAILABLE_CHECKS=()

# Tor（匿名通信）のチェック
#   取得失敗時に「No」と誤表示しないよう、リスト取得の成否を先に確認する
TOR_STATUS="No"
TOR_HIT=0
TOR_LIST=$(curl -sf --connect-timeout 3 --max-time 10 https://check.torproject.org/torbulkexitlist 2>/dev/null)
if [ $? -ne 0 ] || [ -z "$TOR_LIST" ]; then
    TOR_STATUS="Unknown (Failed to fetch Tor exit list)"
    UNAVAILABLE_CHECKS+=("Tor Exit Node")
elif echo "$TOR_LIST" | grep -qx "${IP}"; then
    TOR_STATUS="Yes (Confirmed Tor Exit Node)"
    TOR_HIT=1
fi

# DNSBL（Spamhaus ZEN）のチェック
#   返り値の意味:
#     127.0.0.2        SBL  (スパム送信元)
#     127.0.0.3        CSS  (スパム送信元・低評価)
#     127.0.0.4-7      XBL  (マルウェア感染端末・不正プロキシ)
#     127.0.0.9        DROP (犯罪者管理下のネットワーク)
#     127.0.0.10-11    PBL  (一般回線の動的IP等。脅威ではないため加点しない)
#     127.255.255.x    エラー (公開リゾルバ経由・クエリ超過等で拒否)
REV_IP=$(echo "$IP" | awk -F'.' '{print $4"."$3"."$2"."$1}')
DNSBL_STATUS="Clean / Unlisted"
DNSBL_HIT=""        # 加点対象のリスト名 (SBL/CSS/XBL/DROP)
DNSBL_INFO=""       # 加点しない情報 (PBL)

# 戻り値: 標準出力にA レコード（改行区切り）。終了コード 0=取得成功 / 1=未登録 / 2=問い合わせ失敗
query_dnsbl() {
    local qname="${REV_IP}.$1" out status
    if command -v dig >/dev/null 2>&1; then
        out=$(dig +time=3 +tries=1 A "$qname" 2>/dev/null)
        status=$(echo "$out" | awk '/status:/ {gsub(",","",$6); print $6; exit}')
        case "$status" in
            NOERROR)
                echo "$out" | awk '$4=="A" {print $5}'
                return 0 ;;
            NXDOMAIN) return 1 ;;
            *) return 2 ;;
        esac
    elif command -v host >/dev/null 2>&1; then
        out=$(host -W 3 -t A "$qname" 2>&1)
        if echo "$out" | grep -q "has address"; then
            echo "$out" | awk '/has address/ {print $NF}'
            return 0
        elif echo "$out" | grep -q "NXDOMAIN"; then
            return 1
        fi
        return 2
    fi
    return 2
}

SPAMHAUS_RES=$(query_dnsbl "zen.spamhaus.org")
SPAMHAUS_RC=$?

if [ "$SPAMHAUS_RC" -eq 2 ]; then
    DNSBL_STATUS="Unknown (DNS query failed / dig or host not found)"
    UNAVAILABLE_CHECKS+=("DNSBL (Spamhaus ZEN)")
elif [ "$SPAMHAUS_RC" -eq 0 ]; then
    if echo "$SPAMHAUS_RES" | grep -q "^127\.255\.255\."; then
        DNSBL_STATUS="Unknown (Query refused by Spamhaus: $(echo "$SPAMHAUS_RES" | head -n1) - public resolver or rate limit)"
        UNAVAILABLE_CHECKS+=("DNSBL (Spamhaus ZEN)")
    else
        LISTS=()
        for code in $SPAMHAUS_RES; do
            case "$code" in
                127.0.0.2)          LISTS+=("SBL") ;;
                127.0.0.3)          LISTS+=("CSS") ;;
                127.0.0.[4-7])      LISTS+=("XBL") ;;
                127.0.0.9)          LISTS+=("DROP") ;;
                127.0.0.10|127.0.0.11) DNSBL_INFO="PBL" ;;
            esac
        done
        DNSBL_HIT=$(printf '%s\n' "${LISTS[@]}" | grep -v '^$' | sort -u | tr '\n' ' ' | sed 's/ $//')
        if [ -n "$DNSBL_HIT" ]; then
            DNSBL_STATUS="Listed (Spamhaus ZEN: ${DNSBL_HIT} / $(echo $SPAMHAUS_RES))"
        elif [ -n "$DNSBL_INFO" ]; then
            DNSBL_STATUS="PBL only (Policy list for end-user IP ranges / not a threat indicator)"
        fi
    fi
fi

# JSONパース
NET_NAME=$(grep -oEi '"name"\s*:\s*"[^"]+"' "${TMP_FILE}" | head -n 1 | sed -E 's/.*:\s*"([^"]+)".*/\1/')
COUNTRY=$(grep -oEi '"country"\s*:\s*"[^"]+"' "${TMP_FILE}" | head -n 1 | sed -E 's/.*:\s*"([^"]+)".*/\1/')
IP_TYPE=$(grep -oEi '"type"\s*:\s*"[^"]+"' "${TMP_FILE}" | head -n 1 | sed -E 's/.*:\s*"([^"]+)".*/\1/')
PORT43=$(grep -oEi '"port43"\s*:\s*"[^"]+"' "${TMP_FILE}" | head -n 1 | sed -E 's/.*:\s*"([^"]+)".*/\1/')

[ -z "$NET_NAME" ] && NET_NAME="Unknown"
[ -z "$COUNTRY" ] && COUNTRY="Unknown"
[ -z "$IP_TYPE" ] && IP_TYPE="Unknown"
[ -z "$PORT43" ] && PORT43="Unknown"

RIR="Other / Unknown"
RIR_COUNTRY=""
if echo "$PORT43" | grep -qi "nic.ad.jp"; then
    RIR="JPNIC (Japan / Under APNIC)"
    RIR_COUNTRY="JP"
elif echo "$PORT43" | grep -qi "apnic"; then
    RIR="APNIC (Asia-Pacific)"
    RIR_COUNTRY="AU"
elif echo "$PORT43" | grep -qi "ripe"; then
    RIR="RIPE NCC (Europe, Middle East, Central Asia)"
    RIR_COUNTRY="NL"
elif echo "$PORT43" | grep -qi "arin"; then
    RIR="ARIN (North America)"
    RIR_COUNTRY="US"
elif echo "$PORT43" | grep -qi "lacnic"; then
    RIR="LACNIC (Latin America and the Caribbean)"
    RIR_COUNTRY="UY"
elif echo "$PORT43" | grep -qi "afrinic"; then
    RIR="AFRINIC (Africa)"
    RIR_COUNTRY="MU"
fi

# 住所(label)
ADDRESS=$(grep -oEi '"label"\s*:\s*"[^"]+"' "${TMP_FILE}" | head -n 1 | sed -E 's/.*:\s*"([^"]+)".*/\1/' | tr '\n' ' ')
[ -z "$ADDRESS" ] && ADDRESS="Unknown"

# 備考(description)
REMARKS=$(grep -oEi '"description"\s*:\s*\[\s*"[^"]+"' "${TMP_FILE}" | head -n 3 | sed -E 's/.*"([^"]+)".*/\1/' | tr '\n' ' ')
[ -z "$REMARKS" ] && REMARKS="None"

# メールアドレス/ドメインの抽出
ALL_EMAILS=$(grep -oEi '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "${TMP_FILE}" | tr '[:upper:]' '[:lower:]' | sort -u)
DOMAINS=$(echo "$ALL_EMAILS" | awk -F'@' '{print $2}' | sort -u | grep -v "^$")
DOMAIN_COUNT=$(echo "$DOMAINS" | grep -c .)

# 登録名(fn)の抽出
ALL_FNS=$(grep -oEi '"fn"\s*,\s*\{[^}]*\}\s*,\s*"text"\s*,\s*"[^"]+"' "${TMP_FILE}" | sed -E 's/.*"([^"]+)"$/\1/' | sort -u)

echo ""
echo "================================================================================"
echo "[2] Network Information"
echo "================================================================================"
echo "Network Name           : ${NET_NAME}"
echo "Egress Node Country    : ${COUNTRY}"
echo "Allocation Type        : ${IP_TYPE}"
echo "RIR                    : ${RIR}"
echo "RIR Country            : ${RIR_COUNTRY}"
echo "Admin Physical Address : ${ADDRESS}"
echo "Remarks                : ${REMARKS}"
echo "Reverse DNS (PTR)      : ${PTR}"
echo "Ping Latency           : ${PING_STR}"
echo "Tor Exit Node          : ${TOR_STATUS}"
echo "DNSBL Status           : ${DNSBL_STATUS}"
echo ""
echo "--- Associated Organizations / Contacts ---"
echo "$ALL_FNS" | while read -r fn; do
    [ -n "$fn" ] && echo " - Entity Name : ${fn}"
done
echo ""
echo "--- Associated Emails & Operator Domains ---"
echo "$ALL_EMAILS" | while read -r email; do
    if [ -n "$email" ]; then
        d=$(echo "$email" | awk -F'@' '{print $2}')
        echo " - Email: ${email}  [Domain: ${d}]"
    fi
done

echo ""
echo "================================================================================"
echo "[3] Risk Analysis & Scoring"
echo "================================================================================"

TOTAL_SCORE=0
METADATA_LOWER=$(echo "${NET_NAME} ${ALL_FNS} ${REMARKS} ${DOMAINS} ${ADDRESS}" | tr '[:upper:]' '[:lower:]')
PTR_LOWER=$(echo "${PTR}" | tr '[:upper:]' '[:lower:]')

# ------------------------------------------------------------
# 減点要因: 安全な正規通信の検証
# ------------------------------------------------------------
# A. 国内一般通信キャリア・ISP・モバイル
ISP_REGEX="(ocn\.ne\.jp|kddi\.ne\.jp|bbtec\.net|mesh\.ad\.jp|plala\.or\.jp|so-net\.ne\.jp|eonet\.ne\.jp|flets|spmode\.ne\.jp|au-net\.ne\.jp|rmobile\.jp|panda-world|nuro\.jp|biglobe\.ne\.jp|iij\.ad\.jp|iijmio|zaq\.ne\.jp|asahi-net|commufa\.jp|bbiq\.jp|megaegg\.ne\.jp|pikara\.ne\.jp|dion\.ne\.jp|vectant|ucom|open-cgn)"
if echo "$PTR_LOWER" | grep -qEi "$ISP_REGEX" || echo "$METADATA_LOWER" | grep -qEi "(ntt communications|kddi corporation|softbank corp|rakuten mobile|internet initiative japan|biglobe)"; then
    echo "[o] Safe Indicator [-5 pts]: Domestic Consumer ISP / Mobile Carrier detected"
    echo "    - Evidence : PTR='${PTR}' or Domestic ISP found in Organization Metadata"
    echo "    - Reason : This is a regular access line used directly by general users in their daily lives."
    TOTAL_SCORE=$((TOTAL_SCORE - 5))
fi

# B. 企業向け SASE / 業務 VPN
SASE_REGEX="(cato networks|zscaler|cloudflare|netskope|prisma access|palo alto networks|cisco umbrella|iboss|skyhigh|menlo security|forcepoint)"
if echo "$METADATA_LOWER" | grep -qEi "$SASE_REGEX" || echo "$PTR_LOWER" | grep -qEi "$SASE_REGEX"; then
    DETECTED_SASE=$(echo "$METADATA_LOWER $PTR_LOWER" | grep -oEi "$SASE_REGEX" | head -n 1)
    echo "[o] Safe Indicator [-5 pts]: Enterprise SASE / Zero Trust Gateway detected"
    echo "    - Evidence: Vendor matched ${DETECTED_SASE}"
    echo "    - Reason  : The enterprise's business devices are relaying legitimate traffic based on internal policies."
    TOTAL_SCORE=$((TOTAL_SCORE - 5))
fi

# ------------------------------------------------------------
# 加点要因: リスク要素の検証
# ------------------------------------------------------------
# データセンター / クラウド / ホスティング (+3)
DC_REGEX="(hydra|zare|arisk|m-square|digitalocean|linode|vultr|choopa|ovh|equinix|hetzner|leaseweb|contabo|hostinger|sakura|conoha|gmo internet|xserver|amazon|aws|microsoft|azure|google cloud|alicloud|alibaba|tencent|hosting|cloud|datacenter|server|colocation|vps)"
if echo "$METADATA_LOWER" | grep -qEi "$DC_REGEX" || echo "$PTR_LOWER" | grep -qEi "(compute\.amazonaws|googleusercontent|cloudapp\.net|vultrusercontent)"; then
    DETECTED_DC=$(echo "$METADATA_LOWER $PTR_LOWER" | grep -oEi "$DC_REGEX" | head -n 3 | tr '\n' ' ')
    echo "[!] Risk Indicator [+3 pts]: Datacenter / Hosting / Cloud infrastructure detected"
    echo "    - Evidence: Keywords matched ${DETECTED_DC}"
    echo "    - Reason: This is a datacenter, hosting, or cloud infrastructure which is not typically used by individual consumers."
    TOTAL_SCORE=$((TOTAL_SCORE + 3))
fi

# IP転貸・サブリース (異なるドメインの管理者が複数関与) (+3)
if [ "$DOMAIN_COUNT" -ge 2 ]; then
    echo "[!] Risk Indicator [+3 pts]: Datacenter / Hosting / Cloud infrastructure with multiple domain operators detected"
    echo "    - Evidence: Multiple domain operators found"
    echo "    - Reason: The IP is associated with multiple domain operators, which is common for proxy services or bulletproof hosting."
    TOTAL_SCORE=$((TOTAL_SCORE + 3))
fi

# 私書箱 / バーチャルオフィスの検出 (+2)
if echo "$ADDRESS" | grep -qEi "(suite\s+[0-9]|ste\.?\s+[0-9]|po\s*box|private\s*box)"; then
    MATCH_BOX=$(echo "$ADDRESS" | grep -oEi "(suite\s+[0-9]+|ste\.?\s+[0-9]+|po\s*box\s*[0-9]+)" | head -n 1)
    echo "[!] Risk Indicator [+2 pts]: Private mailbox / Virtual office address detected"
    echo "    - Evidence  : '${MATCH_BOX}' (Full Address: ${ADDRESS})"
    echo "    - Reason: Typical of paper companies with no physical office. Used by suspicious hosting providers or attackers to conceal their identity."
    TOTAL_SCORE=$((TOTAL_SCORE + 2))
fi

# 仮想ロケーション疑い (+2)
if [ "$PING_VAL" -ge 90 ] && [ "$COUNTRY" = "JP" ]; then
    echo "[!] Risk Indicator [+2 pts]: Virtual Location (IP Registration Location and Physical Location Mismatch) Suspected"
    echo "    - Latency: ${PING_MS} (Registered Country: JP)"
    echo "    - Reason: Despite being registered in Japan, the ping response is 90ms or higher. Due to the physical limitations of optical cables, the actual server is likely located overseas, and the Japanese IP is being used to disguise its location."
    TOTAL_SCORE=$((TOTAL_SCORE + 2))
fi

# 小分けブロック (PA) (+1)
if echo "$IP_TYPE" | grep -qi "PA"; then
    echo "[!] Risk Indicator [+1 pts]: IP Type is PA (Provider Aggregatable)"
    echo "    - IP Type  : ${IP_TYPE}"
    echo "    - Reason: This is a provider-aggregatable IP address, commonly used for reselling or re-selling purposes."
    TOTAL_SCORE=$((TOTAL_SCORE + 1))
fi

# 一般回線特有の逆引きがない (+1)
if [ "$PTR" = "None" ] && [ "$TOTAL_SCORE" -gt 0 ]; then
    echo "[!] Risk Indicator [+1 pts]: No Reverse DNS (PTR) Record Found for Public Access Line"
    echo "    - Reverse DNS Result: None"
    echo "    - Reason: Major domestic ISPs typically assign PTR hostnames to dynamic/fixed IPs, but their absence suggests a high likelihood of server usage."
    TOTAL_SCORE=$((TOTAL_SCORE + 1))
fi

# 匿名通信をしている (+5)
if [ "$TOR_HIT" -eq 1 ]; then
    echo "[!] Critical Risk [+5 pts]: Confirmed Tor Exit Node"
    echo "    - Evidence : Matched official Tor Project active exit list."
    echo "    - Rationale: Traffic is routed through onion encryption; 100% anonymized."
    TOTAL_SCORE=$((TOTAL_SCORE + 5))
fi

# DNSBL登録あり (+4)  ※PBLのみの場合は加点しない
if [ -n "$DNSBL_HIT" ]; then
    echo "[!] Critical Risk [+4 pts]: Public Threat Blacklist (DNSBL) listed"
    echo "    - Evidence : ${DNSBL_STATUS}"
    echo "    - Rationale: Known source of automated exploitation, spam, botnet, or open relay."
    TOTAL_SCORE=$((TOTAL_SCORE + 4))
elif [ "$DNSBL_INFO" = "PBL" ]; then
    echo "[i] Info [0 pts]: Listed on Spamhaus PBL only"
    echo "    - Reason : PBL lists end-user / dynamic IP ranges that should not send mail directly. Not a threat indicator."
fi

echo ""
echo "================================================================================"
echo "[4] Report Summary"
echo "================================================================================"
echo "Total Risk Score : ${TOTAL_SCORE} Points"
if [ "${#UNAVAILABLE_CHECKS[@]}" -gt 0 ]; then
    echo "Confidence       : PARTIAL - the following checks could not be completed:"
    for c in "${UNAVAILABLE_CHECKS[@]}"; do
        echo "                   - ${c}"
    done
    echo "                   The actual score may be higher than shown."
else
    echo "Confidence       : FULL - all checks completed"
fi
echo "--------------------------------------------------------------------------------"

if [ "$TOTAL_SCORE" -le 0 ]; then
    echo "Test Result     : LOW RISK / RESIDENTIAL OR ENTERPRISE ACCESS"
    echo "Assessment      : Originates from a domestic ISP or verified enterprise SASE. No anonymization detected."
    echo "Note            : It is highly likely that this is a line used by general end users on a daily basis."

elif [ "$TOTAL_SCORE" -ge 4 ]; then
    echo "Test Result     : HIGH RISK / PROXY, DATACENTER, OR ANONYMIZED ACCESS"
    echo "Assessment      : Multiple indicators detected (datacenter line, IP sub-lease, or offshore routing)."
    echo "Note            : Extremely unlikely to be direct access from an authentic domestic end-user."

else
    echo "Test Result     : MEDIUM RISK / ATTRIBUTE UNKNOWN / MONITORING REQUIRED"
    echo "Assessment      : Exhibits non-consumer traits (cloud/hosting traits or PA allocation), but unconfirmed."
    echo "Note            : Potential unapproved personal VPN, web crawler, or automated scraper."
fi
echo "================================================================================"