#!/usr/bin/env bash

# ============================================================
# Risk Assessment Script for IP Addresses
# ============================================================

SCRIPT_NAME="ip-assess"
SCRIPT_VERSION="1.3.0"

usage() {
    echo "Usage: $0 [--json] <IPv4_ADDRESS>"
    echo ""
    echo "Options:"
    echo "  --json        Output the result as JSON (machine-readable) instead of the text report"
    echo "  -v, --version Show version"
    echo "  -h, --help    Show this help"
}

JSON_MODE=0
IP=""
for arg in "$@"; do
    case "$arg" in
        --json)        JSON_MODE=1 ;;
        -v|--version)  echo "${SCRIPT_NAME} ${SCRIPT_VERSION}"; exit 0 ;;
        -h|--help)     usage; exit 0 ;;
        -*)            echo "Error: Unknown option: ${arg}" >&2; usage >&2; exit 1 ;;
        *)             IP="$arg" ;;
    esac
done

if [ -z "$IP" ]; then
    usage >&2
    exit 1
fi

# 入力検証（IPv4のみ対応。ファイルパスやURLに埋め込むため、形式外の文字列は受け付けない）
OCTET='(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
if ! [[ "$IP" =~ ^${OCTET}\.${OCTET}\.${OCTET}\.${OCTET}$ ]]; then
    echo "Error: Invalid IPv4 address: ${IP}" >&2
    exit 1
fi

TMP_FILE="/tmp/rdap_${IP}.json"
EXECUTED_AT=$(date +%Y-%m-%dT%H:%M:%S%z)
DNS_RESOLVER=$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf 2>/dev/null)
[ -z "$DNS_RESOLVER" ] && DNS_RESOLVER="Unknown"

# JSONモードではテキストレポートを捨て、最後にJSONのみを標準出力（fd 3）へ書き出す
if [ "$JSON_MODE" -eq 1 ]; then
    exec 3>&1 1>/dev/null
fi

# JSON文字列のエスケープ
json_escape() {
    local v="$1"
    v="${v//\\/\\\\}"
    v="${v//\"/\\\"}"
    v="${v//$'\n'/\\n}"
    v="${v//$'\r'/\\r}"
    v="${v//$'\t'/\\t}"
    printf '%s' "$v" | tr -d '\000-\010\013\014\016-\037'
}
# 文字列を JSON 文字列リテラルにする
jstr() { printf '"%s"' "$(json_escape "$1")"; }
# 改行区切りの文字列を JSON 配列にする
jarr() {
    local first=1 line out="["
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        [ "$first" -eq 1 ] && first=0 || out="${out},"
        out="${out}$(jstr "$line")"
    done <<< "$1"
    printf '%s]' "$out"
}

echo "================================================================================"
echo "[1] IP information"
echo "================================================================================"
echo "Target IP           : ${IP}"
echo "Executed At         : ${EXECUTED_AT}"
echo "Tool Version        : ${SCRIPT_NAME} ${SCRIPT_VERSION}"
echo "DNS Resolver        : ${DNS_RESOLVER}"
echo "RDAP Temporary File : ${TMP_FILE}"

# RDAP取得
# リダイレクト後の最終URL（実際に回答したRIR）を証跡として記録する
CURL_RES=$(curl -sL -w "%{http_code} %{url_effective}" -o "${TMP_FILE}" "https://rdap.apnic.net/ip/${IP}")
HTTP_STATUS="${CURL_RES%% *}"
RDAP_URL="${CURL_RES#* }"
if [ "$HTTP_STATUS" != "200" ]; then
    echo "Error: Failed to retrieve information (HTTP Status: ${HTTP_STATUS})"
    if [ "$JSON_MODE" -eq 1 ]; then
        printf '{"tool":{"name":%s,"version":%s},"executed_at":%s,"target_ip":%s,"error":%s}\n' \
            "$(jstr "$SCRIPT_NAME")" "$(jstr "$SCRIPT_VERSION")" "$(jstr "$EXECUTED_AT")" "$(jstr "$IP")" \
            "$(jstr "Failed to retrieve RDAP (HTTP Status: ${HTTP_STATUS})")" >&3
    fi
    exit 1
fi
echo "Retrieval Status    : Success (HTTP 200)"
echo "RDAP Source URL     : ${RDAP_URL}"

# 判定不能だった項目の記録（スコアの信頼性表示に使用）
UNAVAILABLE_CHECKS=()

# 汎用DNS問い合わせ
#   引数: レコード種別 (A / PTR) と名前
#   戻り値: 標準出力にレコード値（改行区切り、末尾ドット除去）。終了コード 0=取得成功 / 1=該当なし / 2=問い合わせ失敗
dns_query() {
    local type="$1" qname="$2" out status
    if command -v dig >/dev/null 2>&1; then
        out=$(dig +time=3 +tries=1 "$type" "$qname" 2>/dev/null)
        status=$(echo "$out" | awk '/status:/ {gsub(",","",$6); print $6; exit}')
        case "$status" in
            NOERROR)
                out=$(echo "$out" | awk -v t="$type" '$4==t {print $5}' | sed 's/\.$//')
                [ -n "$out" ] || return 1
                echo "$out"
                return 0 ;;
            NXDOMAIN) return 1 ;;
            *) return 2 ;;
        esac
    elif command -v host >/dev/null 2>&1; then
        out=$(host -W 3 -t "$type" "$qname" 2>&1)
        if echo "$out" | grep -qE "domain name pointer|has address"; then
            echo "$out" | awk '/domain name pointer|has address/ {print $NF}' | sed 's/\.$//'
            return 0
        elif echo "$out" | grep -qE "NXDOMAIN|has no .* record"; then
            return 1
        fi
        return 2
    fi
    return 2
}

# 逆引き(PTR) と FCrDNS（Forward-Confirmed reverse DNS）
#   PTRは IP の管理者が自由に設定できるため、正引きで元のIPに戻ることを確認して初めて信頼できる
PTR="None"
PTR_ALL=""
PTR_VERIFIED=0
FCRDNS_STATUS="N/A (No PTR)"
REV_ARPA=$(echo "$IP" | awk -F'.' '{print $4"."$3"."$2"."$1".in-addr.arpa"}')

PTR_ALL=$(dns_query PTR "$REV_ARPA")
PTR_RC=$?
if [ "$PTR_RC" -eq 0 ]; then
    PTR=$(echo "$PTR_ALL" | head -n1)
    FCRDNS_STATUS="Not verified (forward lookup does not return ${IP})"
    FWD_FAILED=0
    for name in $PTR_ALL; do
        FWD=$(dns_query A "$name")
        rc=$?
        if [ "$rc" -eq 0 ] && echo "$FWD" | grep -qx "$IP"; then
            PTR="$name"
            PTR_VERIFIED=1
            FCRDNS_STATUS="Verified (${name} -> ${IP})"
            break
        fi
        [ "$rc" -eq 2 ] && FWD_FAILED=1
    done
    if [ "$PTR_VERIFIED" -eq 0 ] && [ "$FWD_FAILED" -eq 1 ]; then
        FCRDNS_STATUS="Unknown (forward lookup failed)"
        UNAVAILABLE_CHECKS+=("FCrDNS")
    fi
elif [ "$PTR_RC" -eq 2 ]; then
    PTR="Unknown (DNS query failed / dig or host not found)"
    FCRDNS_STATUS="Unknown"
    UNAVAILABLE_CHECKS+=("Reverse DNS (PTR)")
fi
PTR_COUNT=$(echo "$PTR_ALL" | grep -c .)

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

# ASN / BGPプレフィックスの取得（Team Cymru IP to ASN Mapping, DNS経由）
#   <逆順IP>.origin.asn.cymru.com TXT -> "ASN | BGP Prefix | CC | Registry | Allocated"
#   AS<番号>.asn.cymru.com TXT        -> "ASN | CC | Registry | Allocated | AS Name"
ASN="Unknown"
AS_NAME="Unknown"
BGP_PREFIX="Unknown"
ASN_CC="Unknown"
PREFIX_ALLOCATED="Unknown"

# 戻り値: 標準出力にTXTレコード（引用符除去済み）。終了コード 0=取得成功 / 1=該当なし / 2=問い合わせ失敗
query_txt() {
    local qname="$1" out status
    if command -v dig >/dev/null 2>&1; then
        out=$(dig +time=3 +tries=1 TXT "$qname" 2>/dev/null)
        status=$(echo "$out" | awk '/status:/ {gsub(",","",$6); print $6; exit}')
        case "$status" in
            NOERROR)
                out=$(echo "$out" | awk '$4=="TXT"' | sed -E 's/^[^"]*"//; s/"[^"]*$//')
                [ -n "$out" ] || return 1
                echo "$out"
                return 0 ;;
            NXDOMAIN) return 1 ;;
            *) return 2 ;;
        esac
    elif command -v host >/dev/null 2>&1; then
        out=$(host -W 3 -t TXT "$qname" 2>&1)
        if echo "$out" | grep -q "descriptive text"; then
            echo "$out" | awk -F'descriptive text ' '/descriptive text/ {print $2}' | tr -d '"'
            return 0
        elif echo "$out" | grep -qE "NXDOMAIN|has no TXT record"; then
            return 1
        fi
        return 2
    fi
    return 2
}

ORIGIN_RES=$(query_txt "${REV_IP}.origin.asn.cymru.com")
ORIGIN_RC=$?
if [ "$ORIGIN_RC" -eq 0 ]; then
    # 複数オリジン（MOAS）の場合は最も細かいプレフィックスを採用
    ORIGIN_LINE=$(echo "$ORIGIN_RES" | awk -F'|' '{split($2,a,"/"); gsub(/ /,"",a[2]); print a[2]"\t"$0}' | sort -rn | head -n1 | cut -f2-)
    ASN=$(echo "$ORIGIN_LINE" | awk -F'|' '{gsub(/ /,"",$1); print $1}' | awk '{print $1}')
    BGP_PREFIX=$(echo "$ORIGIN_LINE" | awk -F'|' '{gsub(/ /,"",$2); print $2}')
    ASN_CC=$(echo "$ORIGIN_LINE" | awk -F'|' '{gsub(/ /,"",$3); print $3}')
    PREFIX_ALLOCATED=$(echo "$ORIGIN_LINE" | awk -F'|' '{gsub(/ /,"",$5); print $5}')
    # 同一ASの包含プレフィックスは除き、異なるオリジンAS（MOAS）のみ数える
    OTHER_ASNS=$(echo "$ORIGIN_RES" | awk -F'|' '{gsub(/ /,"",$1); print $1}' | tr ' ' '\n' | grep -v "^${ASN}$" | grep -v '^$' | sort -u | tr '\n' ' ' | sed 's/ $//')
    [ -n "$OTHER_ASNS" ] && ASN="${ASN} (also announced by AS: ${OTHER_ASNS})"

    ASN_NUM=$(echo "$ASN" | awk '{print $1}')
    NAME_RES=$(query_txt "AS${ASN_NUM}.asn.cymru.com")
    if [ $? -eq 0 ]; then
        AS_NAME=$(echo "$NAME_RES" | head -n1 | awk -F'|' '{print $5}' | sed -E 's/^ +| +$//g')
    fi
elif [ "$ORIGIN_RC" -eq 1 ]; then
    ASN="Not announced (no BGP route)"
    BGP_PREFIX="None"
else
    ASN="Unknown (DNS query failed)"
    UNAVAILABLE_CHECKS+=("ASN Lookup (Team Cymru)")
fi
ASN_NUM=$(echo "$ASN" | grep -oE '^[0-9]+')

# JSONパース
#   jq 非依存。awk で RDAP の JSON を「パス<TAB>値」の行に展開してから取り出す
#   例) .name<TAB>EXAMPLE-NET / .events[0].eventDate<TAB>2015-01-01T00:00:00Z
#   これにより、ネストした entities や links 内の同名キーを誤って拾わない
json_flatten() {
    awk '
    function skip_ws(   c) {
        while (i <= n) {
            c = substr(s, i, 1)
            if (c == " " || c == "\t" || c == "\n" || c == "\r") i++
            else break
        }
    }
    function parse_string(   out, c, e) {
        i++; out = ""
        while (i <= n) {
            c = substr(s, i, 1)
            if (c == "\\") {
                e = substr(s, i + 1, 1)
                if (e == "\"" || e == "\\" || e == "/") out = out e
                else if (e == "n" || e == "t" || e == "r") out = out " "
                else out = out c e
                i += 2; continue
            }
            if (c == "\"") { i++; return out }
            out = out c; i++
        }
        return out
    }
    function parse_value(path,   c, k, idx, v) {
        skip_ws(); c = substr(s, i, 1)
        if (c == "{") {
            i++; skip_ws()
            if (substr(s, i, 1) == "}") { i++; return }
            while (i <= n) {
                skip_ws(); k = parse_string(); skip_ws(); i++
                parse_value(path "." k)
                skip_ws(); c = substr(s, i, 1); i++
                if (c != ",") return
            }
        } else if (c == "[") {
            i++; skip_ws()
            if (substr(s, i, 1) == "]") { i++; return }
            idx = 0
            while (i <= n) {
                parse_value(path "[" idx "]"); idx++
                skip_ws(); c = substr(s, i, 1); i++
                if (c != ",") return
            }
        } else if (c == "\"") {
            v = parse_string(); gsub(/[\t\n\r]/, " ", v); print path "\t" v
        } else {
            v = ""
            while (i <= n) {
                c = substr(s, i, 1)
                if (c == "," || c == "}" || c == "]" || c == " " || c == "\t" || c == "\n" || c == "\r") break
                v = v c; i++
            }
            print path "\t" v
        }
    }
    { s = s $0 "\n" }
    END { n = length(s); i = 1; parse_value("") }
    ' "$1"
}

# 展開結果からパスに完全一致する最初の値を取り出す
jget() {
    echo "$RDAP_FLAT" | awk -F'\t' -v p="$1" '$1 == p { print $2; exit }'
}

RDAP_FLAT=$(json_flatten "${TMP_FILE}")

# トップレベルの値を取得（取得できない場合のみ従来の grep 抽出にフォールバック）
NET_NAME=$(jget ".name")
COUNTRY=$(jget ".country")
IP_TYPE=$(jget ".type")
PORT43=$(jget ".port43")
[ -z "$NET_NAME" ] && NET_NAME=$(grep -oEi '"name"\s*:\s*"[^"]+"' "${TMP_FILE}" | head -n 1 | sed -E 's/.*:\s*"([^"]+)".*/\1/')
[ -z "$COUNTRY" ]  && COUNTRY=$(grep -oEi '"country"\s*:\s*"[^"]+"' "${TMP_FILE}" | head -n 1 | sed -E 's/.*:\s*"([^"]+)".*/\1/')
[ -z "$PORT43" ]   && PORT43=$(grep -oEi '"port43"\s*:\s*"[^"]+"' "${TMP_FILE}" | head -n 1 | sed -E 's/.*:\s*"([^"]+)".*/\1/')

# 割当ブロック（範囲・CIDR・ハンドル）
NET_HANDLE=$(jget ".handle")
NET_START=$(jget ".startAddress")
NET_END=$(jget ".endAddress")
NET_CIDRS=$(echo "$RDAP_FLAT" | awk -F'\t' '
    $1 ~ /^\.cidr0_cidrs\[[0-9]+\]\.v[46]prefix$/ { sub(/\.v[46]prefix$/, "", $1); pfx[$1] = $2; order[++m] = $1 }
    $1 ~ /^\.cidr0_cidrs\[[0-9]+\]\.length$/      { sub(/\.length$/, "", $1); len[$1] = $2 }
    END { for (j = 1; j <= m; j++) printf "%s%s/%s", (j > 1 ? ", " : ""), pfx[order[j]], len[order[j]] }')
[ -z "$NET_HANDLE" ] && NET_HANDLE="Unknown"
NET_RANGE="Unknown"
[ -n "$NET_START" ] && [ -n "$NET_END" ] && NET_RANGE="${NET_START} - ${NET_END}"
[ -z "$NET_CIDRS" ] && NET_CIDRS="Unknown"

# 登録日・最終更新日（トップレベルの events のみ。entities 内の events は対象外）
get_event_date() {
    echo "$RDAP_FLAT" | awk -F'\t' -v act="$1" '
        $1 ~ /^\.events\[[0-9]+\]\.eventAction$/ && $2 == act { k = $1; sub(/\.eventAction$/, "", k); want[k] = 1 }
        $1 ~ /^\.events\[[0-9]+\]\.eventDate$/   { k = $1; sub(/\.eventDate$/, "", k); d[k] = $2 }
        END { for (k in want) if (k in d) { print d[k]; exit } }'
}
# 経過日数を併記（GNU date が使える環境のみ）
format_event_date() {
    local d="$1" epoch now days
    [ -z "$d" ] && { echo "Unknown"; return; }
    epoch=$(date -d "$d" +%s 2>/dev/null)
    if [ -n "$epoch" ]; then
        now=$(date +%s)
        days=$(( (now - epoch) / 86400 ))
        echo "${d} (${days} days ago)"
    else
        echo "$d"
    fi
}
REG_DATE_RAW=$(get_event_date "registration")
CHANGED_DATE_RAW=$(get_event_date "last changed")
REG_DATE=$(format_event_date "$REG_DATE_RAW")
CHANGED_DATE=$(format_event_date "$CHANGED_DATE_RAW")

# Abuse 連絡先（roles に "abuse" を持つエンティティ。ARIN のように入れ子の場合も対応）
ABUSE_CONTACTS=$(echo "$RDAP_FLAT" | awk -F'\t' '
    { path[NR] = $1; val[NR] = $2 }
    $1 ~ /\.roles\[[0-9]+\]$/ && $2 == "abuse" { e = $1; sub(/\.roles\[[0-9]+\]$/, "", e); ent[e] = 1; eorder[++m] = e }
    END {
        for (j = 1; j <= m; j++) {
            e = eorder[j]; if (done[e]++) continue
            vp = e ".vcardArray[1]"; name = ""; mails = ""
            for (r = 1; r <= NR; r++) {
                if (index(path[r], vp "[") != 1) continue
                rest = substr(path[r], length(vp) + 1)
                if (rest ~ /^\[[0-9]+\]\[0\]$/) { prop[rest] = val[r] }
                if (rest ~ /^\[[0-9]+\]\[3\]$/) {
                    key = rest; sub(/\[3\]$/, "[0]", key)
                    if (prop[key] == "fn") name = val[r]
                    if (prop[key] == "email" && index(mails, val[r]) == 0) mails = mails (mails ? ", " : "") val[r]
                }
            }
            h = ""
            for (r = 1; r <= NR; r++) if (path[r] == e ".handle") { h = val[r]; break }
            printf "%s | %s | %s\n", (mails ? mails : "(no email)"), (name ? name : "-"), (h ? h : "-")
        }
    }')

[ -z "$NET_NAME" ] && NET_NAME="Unknown"
[ -z "$COUNTRY" ] && COUNTRY="Unknown"

# ------------------------------------------------------------
# Geofeed（運営者が自己申告する利用地: RFC 8805 / RFC 9632）
#   1. RDAP の links に rel=geofeed があればその URL
#   2. なければ remarks の "Geofeed https://..." 形式
#   取得した CSV から、対象 IP を含む最も細かいプレフィックスの行を採用する
# ------------------------------------------------------------
GEOFEED_URL=$(echo "$RDAP_FLAT" | awk -F'\t' '
    $1 ~ /^\.links\[[0-9]+\]\.rel$/ && $2 == "geofeed" { k = $1; sub(/\.rel$/, "", k); want[k] = 1 }
    $1 ~ /^\.links\[[0-9]+\]\.href$/ { k = $1; sub(/\.href$/, "", k); href[k] = $2 }
    END { for (k in want) if (k in href) { print href[k]; exit } }')
if [ -z "$GEOFEED_URL" ]; then
    GEOFEED_URL=$(echo "$RDAP_FLAT" | awk -F'\t' '$1 ~ /^\.remarks\[[0-9]+\]\.description\[[0-9]+\]$/' \
        | grep -oE 'Geofeed:?[[:space:]]+https://[^[:space:]]+' | head -n1 | grep -oE 'https://[^[:space:]]+')
fi
# 外部（RDAP登録者）が書いた値なので、https の URL 以外は使わない
GEOFEED_URL_RE='^https://[A-Za-z0-9._~:/?#@!&()*+,;=%-]+$'
if ! [[ "$GEOFEED_URL" =~ $GEOFEED_URL_RE ]]; then
    GEOFEED_URL=""
fi

GEOFEED_STATUS="Not published"
GEOFEED_PREFIX=""
GEOFEED_CC=""
GEOFEED_REGION=""
GEOFEED_CITY=""
if [ -n "$GEOFEED_URL" ]; then
    GEOFEED_TMP=$(mktemp 2>/dev/null || echo "/tmp/geofeed_${IP}_$$.csv")
    if curl -sfL --proto '=https' --proto-redir '=https' --connect-timeout 5 --max-time 20 \
            --max-filesize 50000000 -o "$GEOFEED_TMP" "$GEOFEED_URL" 2>/dev/null && [ -s "$GEOFEED_TMP" ]; then
        GEOFEED_LINE=$(awk -F',' -v ip="$IP" '
            function ip2n(s,   a) { split(s, a, "."); return ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4] }
            BEGIN { t = ip2n(ip); best = -1 }
            /^[ \t]*#/ { next }
            {
                gsub(/\r/, "")
                p = $1; gsub(/^[ \t]+|[ \t]+$/, "", p)
                if (p !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/) next
                n = split(p, q, "/"); len = (n == 2) ? q[2] + 0 : 32
                if (len > 32) next
                size = 1; for (k = 0; k < 32 - len; k++) size *= 2   # busybox awk はべき乗非対応のことがある
                if (int(t / size) == int(ip2n(q[1]) / size) && len > best) { best = len; line = $0 }
            }
            END { if (best >= 0) print line }' "$GEOFEED_TMP")
        if [ -n "$GEOFEED_LINE" ]; then
            GEOFEED_STATUS="Found"
            GEOFEED_PREFIX=$(echo "$GEOFEED_LINE" | awk -F',' '{gsub(/^[ \t]+|[ \t]+$/,"",$1); print $1}')
            GEOFEED_CC=$(echo "$GEOFEED_LINE" | awk -F',' '{gsub(/^[ \t]+|[ \t]+$/,"",$2); print toupper($2)}')
            GEOFEED_REGION=$(echo "$GEOFEED_LINE" | awk -F',' '{gsub(/^[ \t]+|[ \t]+$/,"",$3); print $3}')
            GEOFEED_CITY=$(echo "$GEOFEED_LINE" | awk -F',' '{gsub(/^[ \t]+|[ \t]+$/,"",$4); print $4}')
        else
            GEOFEED_STATUS="Prefix not listed"
        fi
    else
        GEOFEED_STATUS="Unknown (failed to fetch)"
        UNAVAILABLE_CHECKS+=("Geofeed")
    fi
    rm -f "$GEOFEED_TMP"
fi

if [ "$GEOFEED_STATUS" = "Found" ]; then
    GEOFEED_TEXT="${GEOFEED_CC:--}"
    [ -n "$GEOFEED_REGION" ] && GEOFEED_TEXT="${GEOFEED_TEXT} / ${GEOFEED_REGION}"
    [ -n "$GEOFEED_CITY" ] && GEOFEED_TEXT="${GEOFEED_TEXT} / ${GEOFEED_CITY}"
    GEOFEED_TEXT="${GEOFEED_TEXT} (${GEOFEED_PREFIX}, self-declared by operator)"
else
    GEOFEED_TEXT="$GEOFEED_STATUS"
fi
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

# 備考: ネットワーク自身の remarks のみ（notices の利用規約文などは除外）
REMARKS=$(echo "$RDAP_FLAT" | awk -F'\t' '$1 ~ /^\.remarks\[[0-9]+\]\.description\[[0-9]+\]$/ {print $2}' | head -n 3 | tr '\n' ' ' | sed 's/ $//')
[ -z "$REMARKS" ] && REMARKS="None"

# メールアドレス/ドメインの抽出
ALL_EMAILS=$(grep -oEi '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "${TMP_FILE}" | tr '[:upper:]' '[:lower:]' | sort -u)
DOMAINS=$(echo "$ALL_EMAILS" | awk -F'@' '{print $2}' | sort -u | grep -v "^$")
DOMAIN_COUNT=$(echo "$DOMAINS" | grep -c .)

# 登録名(fn)の抽出
ALL_FNS=$(grep -oEi '"fn"\s*,\s*\{[^}]*\}\s*,\s*"text"\s*,\s*"[^"]+"' "${TMP_FILE}" | sed -E 's/.*"([^"]+)"$/\1/' | sort -u)

echo ""
# 所在地の整合性チェック（登録国・申告所在地・遅延の突き合わせ）
#   遅延の閾値（90ms）は日本国内から実行する前提
DECLARED_JP=0
{ [ "$COUNTRY" = "JP" ] || [ "$GEOFEED_CC" = "JP" ]; } && DECLARED_JP=1
if [ -n "$GEOFEED_CC" ] && [ "$COUNTRY" != "Unknown" ] && [ "$GEOFEED_CC" != "$COUNTRY" ]; then
    LOCATION_CHECK="DECLARATIONS DIFFER (RDAP: ${COUNTRY} / Geofeed: ${GEOFEED_CC})"
elif [ "$DECLARED_JP" -eq 1 ] && [ -n "$PING_MS" ] && [ "$PING_VAL" -ge 90 ]; then
    LOCATION_CHECK="MISMATCH (declared JP, but latency is ${PING_MS} ms)"
elif [ "$DECLARED_JP" -eq 1 ] && [ -n "$PING_MS" ]; then
    LOCATION_CHECK="CONSISTENT (declared JP, latency ${PING_MS} ms)"
elif [ -z "$PING_MS" ]; then
    LOCATION_CHECK="NOT VERIFIED (no latency measurement)"
else
    LOCATION_CHECK="NOT EVALUATED (latency threshold is defined for JP only)"
fi

echo "================================================================================"
echo "[2] Network Information"
echo "================================================================================"
echo "Network Name           : ${NET_NAME}"
echo "Egress Node Country    : ${COUNTRY}"
echo "Allocation Type        : ${IP_TYPE}"
echo "Network Handle         : ${NET_HANDLE}"
echo "Allocated Range        : ${NET_RANGE}"
echo "Allocated CIDR         : ${NET_CIDRS}"
echo "Registered             : ${REG_DATE}"
echo "Last Changed           : ${CHANGED_DATE}"
echo "RIR                    : ${RIR}"
echo "RIR Country            : ${RIR_COUNTRY}"
echo "Admin Physical Address : ${ADDRESS}"
echo "Remarks                : ${REMARKS}"
echo "Reverse DNS (PTR)      : ${PTR}$( [ "$PTR_COUNT" -gt 1 ] && echo " (+$((PTR_COUNT - 1)) more)")"
echo "FCrDNS                 : ${FCRDNS_STATUS}"
echo "Ping Latency           : ${PING_STR}"
echo "Geofeed Location       : ${GEOFEED_TEXT}"
echo "Location Check         : ${LOCATION_CHECK}"
echo "Tor Exit Node          : ${TOR_STATUS}"
echo "DNSBL Status           : ${DNSBL_STATUS}"
echo "ASN                    : ${ASN}"
echo "AS Name                : ${AS_NAME}"
echo "BGP Prefix             : ${BGP_PREFIX}"
echo "ASN Registered Country : ${ASN_CC}"
echo "Prefix Allocated (RIR) : ${PREFIX_ALLOCATED}"
echo ""
echo "--- Abuse Contact (for reporting) ---"
if [ -n "$ABUSE_CONTACTS" ]; then
    echo "$ABUSE_CONTACTS" | while IFS='|' read -r mail name handle; do
        echo "  - Email : $(echo $mail)  [Name: $(echo $name) / Handle: $(echo $handle)]"
    done
else
    echo "  - Not found in RDAP response"
fi
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
echo "[3] Analysis"
echo "================================================================================"

# 判定結果の記録（テキスト出力と同時に JSON 用の配列へ保存）
#   indicator "[!] Risk Indicator [+3 pts]: Name"  /  detail "- Evidence : ..."
IND_JSON=()
indicator() {
    echo "$1"
    local kind="info" pts name
    case "$1" in
        "[X]"*) kind="threat" ;;
        "[!]"*) kind="risk" ;;
        "[o]"*) kind="safe" ;;
    esac
    if [[ "$1" == *" pts]: "* ]]; then
        pts=$(echo "$1" | sed -E 's/.*\[([+-]?[0-9]+) pts\].*/\1/')
        pts="${pts#+}"
        name="${1#*pts]: }"
    else
        pts=0
        name="${1#*: }"
    fi
    IND_JSON+=("{\"type\":$(jstr "$kind"),\"points\":${pts},\"name\":$(jstr "$name"),\"details\":[")
}
detail() {
    echo "    $1"
    local last=$(( ${#IND_JSON[@]} - 1 ))
    [ "$last" -lt 0 ] && return
    case "${IND_JSON[$last]}" in
        *\[) IND_JSON[$last]="${IND_JSON[$last]}$(jstr "${1#- }")" ;;
        *)   IND_JSON[$last]="${IND_JSON[$last]},$(jstr "${1#- }")" ;;
    esac
}

INFRA_SCORE=0
VERIFIED_CRAWLER=0
SPOOFED_CRAWLER=0
ISP_HIT=0
SASE_HIT=0
DC_HIT=0
METADATA_LOWER=$(echo "${NET_NAME} ${ALL_FNS} ${REMARKS} ${DOMAINS} ${ADDRESS}" | tr '[:upper:]' '[:lower:]')
PTR_LOWER=""
[ "$PTR_RC" -eq 0 ] && PTR_LOWER=$(echo "${PTR}" | tr '[:upper:]' '[:lower:]')
# 減点（安全側）の判定には、なりすまし防止のため FCrDNS 検証済みの PTR のみを使う
PTR_TRUSTED_LOWER=""
[ "$PTR_VERIFIED" -eq 1 ] && PTR_TRUSTED_LOWER="$PTR_LOWER"

echo "--- [3-1] Infrastructure Attributes (scored) ---"

# ------------------------------------------------------------
# 減点要因: 安全な正規通信の検証
# ------------------------------------------------------------
# 検索エンジンの正規クローラー（FCrDNS検証済みPTRで判定）
#   各社公式の検証方法に準拠: 逆引き → ドメイン確認 → 正引きで元IPに戻ることを確認
#   ※googleusercontent.com は GCP の利用者VMも含むため対象外
CRAWLER_REGEX="(\.googlebot\.com|\.google\.com|\.search\.msn\.com|\.applebot\.apple\.com|\.yandex\.(ru|net|com)|\.baidu\.(com|jp))$"
if echo "$PTR_LOWER" | grep -qE "$CRAWLER_REGEX"; then
    if [ "$PTR_VERIFIED" -eq 1 ]; then
        indicator "[o] Safe Indicator [-5 pts]: Verified Search Engine Crawler"
        detail "- Evidence : FCrDNS-verified PTR='${PTR}'"
        detail "- Reason : Officially verifiable crawler. Blocking may affect search indexing (SEO)."
        INFRA_SCORE=$((INFRA_SCORE - 5))
        VERIFIED_CRAWLER=1
    elif [[ "$FCRDNS_STATUS" == Not\ verified* ]]; then
        # なりすましは回線属性ではなく脅威シグナルとして [3-2] で扱う
        SPOOFED_CRAWLER=1
    fi
fi

# A. 国内一般通信キャリア・ISP・モバイル
ISP_REGEX="(ocn\.ne\.jp|kddi\.ne\.jp|bbtec\.net|mesh\.ad\.jp|plala\.or\.jp|so-net\.ne\.jp|eonet\.ne\.jp|flets|spmode\.ne\.jp|au-net\.ne\.jp|rmobile\.jp|panda-world|nuro\.jp|biglobe\.ne\.jp|iij\.ad\.jp|iijmio|zaq\.ne\.jp|asahi-net|commufa\.jp|bbiq\.jp|megaegg\.ne\.jp|pikara\.ne\.jp|dion\.ne\.jp|vectant|ucom|open-cgn)"
if echo "$PTR_TRUSTED_LOWER" | grep -qEi "$ISP_REGEX" || echo "$METADATA_LOWER" | grep -qEi "(ntt communications|kddi corporation|softbank corp|rakuten mobile|internet initiative japan|biglobe)"; then
    indicator "[o] Safe Indicator [-5 pts]: Domestic Consumer ISP / Mobile Carrier detected"
    if echo "$PTR_TRUSTED_LOWER" | grep -qEi "$ISP_REGEX"; then
        detail "- Evidence : FCrDNS-verified PTR='${PTR}'"
    else
        detail "- Evidence : Domestic ISP found in Organization Metadata"
    fi
    detail "- Reason : This is a regular access line used directly by general users in their daily lives."
    INFRA_SCORE=$((INFRA_SCORE - 5))
    ISP_HIT=1
fi

# B. 企業向け SASE / 業務 VPN
SASE_REGEX="(cato networks|zscaler|cloudflare|netskope|prisma access|palo alto networks|cisco umbrella|iboss|skyhigh|menlo security|forcepoint)"
if echo "$METADATA_LOWER" | grep -qEi "$SASE_REGEX" || echo "$PTR_TRUSTED_LOWER" | grep -qEi "$SASE_REGEX"; then
    DETECTED_SASE=$(echo "$METADATA_LOWER $PTR_TRUSTED_LOWER" | grep -oEi "$SASE_REGEX" | head -n 1)
    indicator "[o] Safe Indicator [-5 pts]: Enterprise SASE / Zero Trust Gateway detected"
    detail "- Evidence: Vendor matched ${DETECTED_SASE}"
    detail "- Reason  : The enterprise's business devices are relaying legitimate traffic based on internal policies."
    INFRA_SCORE=$((INFRA_SCORE - 5))
    SASE_HIT=1
fi

# ------------------------------------------------------------
# 加点要因: リスク要素の検証
# ------------------------------------------------------------
# データセンター / クラウド / ホスティング (+3)
#   根拠1: 既知のホスティング事業者ASN（キーワードより確度が高い）
#   根拠2: 登録情報・PTRのキーワード
#   ※Cloudflare(13335)はSASE/WARPの切り分けが別途必要なため、ここには含めない
HOSTING_ASNS=" 16509 14618 8075 396982 31898 45102 132203 14061 63949 20473 16276 24940 51167 60781 28753 9009 7684 9370 9371 7506 "
DC_REGEX="(hydra|zare|arisk|m-square|digitalocean|linode|vultr|choopa|ovh|equinix|hetzner|leaseweb|contabo|hostinger|sakura|conoha|gmo internet|xserver|amazon|aws|microsoft|azure|google cloud|alicloud|alibaba|tencent|hosting|cloud|datacenter|server|colocation|vps)"
DC_ASN_HIT=0
DC_KEYWORD_HIT=0
[ -n "$ASN_NUM" ] && [[ "$HOSTING_ASNS" == *" ${ASN_NUM} "* ]] && DC_ASN_HIT=1
if echo "$METADATA_LOWER" | grep -qEi "$DC_REGEX" || echo "$PTR_LOWER" | grep -qEi "(compute\.amazonaws|googleusercontent|cloudapp\.net|vultrusercontent)"; then
    DC_KEYWORD_HIT=1
fi
if [ "$DC_ASN_HIT" -eq 1 ] || [ "$DC_KEYWORD_HIT" -eq 1 ]; then
    indicator "[!] Risk Indicator [+3 pts]: Datacenter / Hosting / Cloud infrastructure detected"
    if [ "$DC_ASN_HIT" -eq 1 ]; then
        detail "- Evidence: Known hosting ASN matched AS${ASN_NUM} (${AS_NAME})"
    fi
    if [ "$DC_KEYWORD_HIT" -eq 1 ]; then
        DETECTED_DC=$(echo "$METADATA_LOWER $PTR_LOWER" | grep -oEi "$DC_REGEX" | head -n 3 | tr '\n' ' ')
        detail "- Evidence: Keywords matched ${DETECTED_DC}"
    fi
    detail "- Reason: This is a datacenter, hosting, or cloud infrastructure which is not typically used by individual consumers."
    INFRA_SCORE=$((INFRA_SCORE + 3))
    DC_HIT=1
fi

# IP転貸・サブリース (異なるドメインの管理者が複数関与) (+3)
if [ "$DOMAIN_COUNT" -ge 2 ]; then
    indicator "[!] Risk Indicator [+3 pts]: IP Sub-leasing / Domain Discrepancy (multiple operator domains)"
    detail "- Evidence: Multiple domain operators found"
    detail "- Reason: The IP is associated with multiple domain operators, which is common for proxy services or bulletproof hosting."
    INFRA_SCORE=$((INFRA_SCORE + 3))
fi

# 私書箱 / バーチャルオフィスの検出 (+2)
if echo "$ADDRESS" | grep -qEi "(suite\s+[0-9]|ste\.?\s+[0-9]|po\s*box|private\s*box)"; then
    MATCH_BOX=$(echo "$ADDRESS" | grep -oEi "(suite\s+[0-9]+|ste\.?\s+[0-9]+|po\s*box\s*[0-9]+)" | head -n 1)
    indicator "[!] Risk Indicator [+2 pts]: Private mailbox / Virtual office address detected"
    detail "- Evidence  : '${MATCH_BOX}' (Full Address: ${ADDRESS})"
    detail "- Reason: Typical of paper companies with no physical office. Used by suspicious hosting providers or attackers to conceal their identity."
    INFRA_SCORE=$((INFRA_SCORE + 2))
fi

# 仮想ロケーション疑い (+2)
if [ "$PING_VAL" -ge 90 ] && [ "$DECLARED_JP" -eq 1 ]; then
    indicator "[!] Risk Indicator [+2 pts]: Virtual Location (IP Registration Location and Physical Location Mismatch) Suspected"
    detail "- Latency: ${PING_MS} ms (Registered Country: ${COUNTRY} / Geofeed: ${GEOFEED_TEXT})"
    detail "- Reason: Despite being registered in Japan, the ping response is 90ms or higher. Due to the physical limitations of optical cables, the actual server is likely located overseas, and the Japanese IP is being used to disguise its location."
    INFRA_SCORE=$((INFRA_SCORE + 2))
fi

# 小分けブロック (PA) (+1)
if echo "$IP_TYPE" | grep -qi "PA"; then
    indicator "[!] Risk Indicator [+1 pts]: IP Type is PA (Provider Aggregatable)"
    detail "- IP Type  : ${IP_TYPE}"
    detail "- Reason: This is a provider-aggregatable IP address, commonly used for reselling or re-selling purposes."
    INFRA_SCORE=$((INFRA_SCORE + 1))
fi

# 一般回線特有の逆引きがない (+1)
if [ "$PTR" = "None" ] && [ "$INFRA_SCORE" -gt 0 ]; then
    indicator "[!] Risk Indicator [+1 pts]: No Reverse DNS (PTR) Record Found for Public Access Line"
    detail "- Reverse DNS Result: None"
    detail "- Reason: Major domestic ISPs typically assign PTR hostnames to dynamic/fixed IPs, but their absence suggests a high likelihood of server usage."
    INFRA_SCORE=$((INFRA_SCORE + 1))
fi

# ------------------------------------------------------------
# 脅威の評判（回線属性の減点で打ち消さない）
# ------------------------------------------------------------
echo ""
echo "--- [3-2] Threat Reputation (not offset by infrastructure attributes) ---"
THREAT_SIGNALS=()

# Tor 出口ノード
if [ "$TOR_HIT" -eq 1 ]; then
    indicator "[X] Threat Signal: Confirmed Tor Exit Node"
    detail "- Evidence : Matched official Tor Project active exit list."
    detail "- Rationale: Traffic is routed through onion encryption; the real source cannot be traced."
    THREAT_SIGNALS+=("Tor Exit Node")
fi

# DNSBL 登録（PBL のみの場合は脅威とみなさない）
if [ -n "$DNSBL_HIT" ]; then
    indicator "[X] Threat Signal: Public Threat Blacklist (Spamhaus ${DNSBL_HIT})"
    detail "- Evidence : ${DNSBL_STATUS}"
    detail "- Rationale: Known source of spam, malware-infected hosts (botnet), abused proxies, or criminal networks."
    THREAT_SIGNALS+=("Spamhaus ${DNSBL_HIT}")
elif [ "$DNSBL_INFO" = "PBL" ]; then
    indicator "[i] Info: Listed on Spamhaus PBL only"
    detail "- Reason : PBL lists end-user / dynamic IP ranges that should not send mail directly. Not a threat indicator."
fi

# 検索エンジンクローラーのなりすまし
if [ "$SPOOFED_CRAWLER" -eq 1 ]; then
    indicator "[X] Threat Signal: Spoofed Search Engine Crawler PTR"
    detail "- Evidence : PTR='${PTR}' claims a crawler domain, but forward lookup does not return ${IP}"
    detail "- Rationale: Reverse DNS is set to impersonate a legitimate crawler. Typical of scrapers evading bot controls."
    THREAT_SIGNALS+=("Spoofed crawler PTR")
fi

if [ "${#THREAT_SIGNALS[@]}" -eq 0 ]; then
    echo "No threat signals found in the checked sources (Tor exit list, Spamhaus ZEN, crawler PTR)."
fi

# ------------------------------------------------------------
# 回線種別の分類
# ------------------------------------------------------------
if [ "$TOR_HIT" -eq 1 ]; then
    INFRA_CLASS="Anonymization Network (Tor)"
elif [ "$VERIFIED_CRAWLER" -eq 1 ]; then
    INFRA_CLASS="Search Engine Crawler (verified)"
elif [ "$SASE_HIT" -eq 1 ]; then
    INFRA_CLASS="Enterprise SASE / Zero Trust Gateway"
elif [ "$ISP_HIT" -eq 1 ] && [ "$DC_HIT" -eq 1 ]; then
    INFRA_CLASS="Mixed (domestic ISP and hosting traits)"
elif [ "$ISP_HIT" -eq 1 ]; then
    INFRA_CLASS="Domestic Consumer ISP / Mobile"
elif [ "$DC_HIT" -eq 1 ]; then
    INFRA_CLASS="Datacenter / Hosting / Cloud"
else
    INFRA_CLASS="Unclassified"
fi

# ------------------------------------------------------------
# 脅威の評判の判定（検出 / 未検出 / 判定不能）
# ------------------------------------------------------------
REPUTATION_INCOMPLETE=0
for c in "${UNAVAILABLE_CHECKS[@]}"; do
    case "$c" in "Tor Exit Node"|"DNSBL"*) REPUTATION_INCOMPLETE=1 ;; esac
done
if [ "${#THREAT_SIGNALS[@]}" -gt 0 ]; then
    THREAT_LEVEL="DETECTED"
    THREAT_TEXT="DETECTED ($(IFS=,; echo "${THREAT_SIGNALS[*]}" | sed 's/,/, /g'))"
elif [ "$REPUTATION_INCOMPLETE" -eq 1 ]; then
    THREAT_LEVEL="UNKNOWN"
    THREAT_TEXT="UNKNOWN (some reputation checks could not be completed)"
else
    THREAT_LEVEL="NONE_FOUND"
    THREAT_TEXT="NONE FOUND (in the checked sources only)"
fi

echo ""
echo "================================================================================"
echo "[4] Report Summary"
echo "================================================================================"

# 調査優先度: 脅威シグナルがあれば回線種別に関係なく HIGH
#   NOTE は誤読による事故（LOW を安全と解釈する、正規クローラーを遮断する）を防ぐ場合のみ表示
NOTE=""
if [ "$THREAT_LEVEL" = "DETECTED" ]; then
    PRIORITY="HIGH"
elif [ "$VERIFIED_CRAWLER" -eq 1 ] && [ "$INFRA_SCORE" -le 0 ]; then
    PRIORITY="LOW"
    NOTE="Verified search engine crawler. Blocking may affect search indexing."
elif [ "$INFRA_SCORE" -ge 4 ]; then
    PRIORITY="HIGH"
elif [ "$INFRA_SCORE" -ge 1 ]; then
    PRIORITY="MEDIUM"
else
    PRIORITY="LOW"
    NOTE="LOW does not mean safe. Compromised end-user devices and residential proxies look the same."
fi
RESULT_LABEL="PRIORITY ${PRIORITY} / ${INFRA_CLASS}"

echo "Investigation Priority : ${PRIORITY}"
echo "Infrastructure Class   : ${INFRA_CLASS}"
echo "Infrastructure Score   : ${INFRA_SCORE} Points"
echo "Threat Reputation      : ${THREAT_TEXT}"
if [ "${#UNAVAILABLE_CHECKS[@]}" -gt 0 ]; then
    echo "Confidence             : PARTIAL - the following checks could not be completed:"
    for c in "${UNAVAILABLE_CHECKS[@]}"; do
        echo "                         - ${c}"
    done
else
    echo "Confidence             : FULL - all checks completed"
fi
[ -n "$NOTE" ] && echo "Note                   : ${NOTE}"
echo "================================================================================"
echo ""
echo "================================================================================"
echo "[5] Data Sources"
echo "================================================================================"
echo "RDAP             : ${RDAP_URL}"
echo "Tor Exit List    : https://check.torproject.org/torbulkexitlist"
echo "DNSBL            : zen.spamhaus.org (via ${DNS_RESOLVER})"
echo "ASN              : Team Cymru IP to ASN Mapping (origin.asn.cymru.com / asn.cymru.com)"
echo "Reverse/Forward  : DNS via ${DNS_RESOLVER}"
echo "Geofeed          : ${GEOFEED_URL:-Not published}"
echo "RDAP Raw Data    : ${TMP_FILE}"
echo "================================================================================"

# JSON 出力
if [ "$JSON_MODE" -eq 1 ]; then
    if [ "${#UNAVAILABLE_CHECKS[@]}" -gt 0 ]; then
        CONFIDENCE="PARTIAL"
        UNAVAIL_LIST=$(printf '%s\n' "${UNAVAILABLE_CHECKS[@]}")
    else
        CONFIDENCE="FULL"
        UNAVAIL_LIST=""
    fi
    IND_OUT=""
    for item in "${IND_JSON[@]}"; do
        [ -n "$IND_OUT" ] && IND_OUT="${IND_OUT},"
        IND_OUT="${IND_OUT}${item}]}"
    done
    ABUSE_EMAILS=$(echo "$ABUSE_CONTACTS" | awk -F'|' '{gsub(/^ +| +$/,"",$1); n=split($1,a,", "); for(k=1;k<=n;k++) if(a[k]!="(no email)") print a[k]}' | sort -u)
    PING_JSON="null"
    [ -n "$PING_MS" ] && PING_JSON="$PING_MS"

    cat >&3 <<JSON
{
  "tool": {"name": $(jstr "$SCRIPT_NAME"), "version": $(jstr "$SCRIPT_VERSION")},
  "executed_at": $(jstr "$EXECUTED_AT"),
  "target_ip": $(jstr "$IP"),
  "network": {
    "name": $(jstr "$NET_NAME"),
    "handle": $(jstr "$NET_HANDLE"),
    "country": $(jstr "$COUNTRY"),
    "allocation_type": $(jstr "$IP_TYPE"),
    "range": $(jstr "$NET_RANGE"),
    "cidr": $(jstr "$NET_CIDRS"),
    "registered": $(jstr "$REG_DATE_RAW"),
    "last_changed": $(jstr "$CHANGED_DATE_RAW"),
    "rir": $(jstr "$RIR"),
    "address": $(jstr "$ADDRESS"),
    "remarks": $(jstr "$REMARKS")
  },
  "asn": {
    "asn": $(jstr "$ASN"),
    "name": $(jstr "$AS_NAME"),
    "bgp_prefix": $(jstr "$BGP_PREFIX"),
    "country": $(jstr "$ASN_CC"),
    "prefix_allocated": $(jstr "$PREFIX_ALLOCATED")
  },
  "dns": {
    "ptr": $(jstr "$PTR"),
    "fcrdns": $(jstr "$FCRDNS_STATUS"),
    "fcrdns_verified": $( [ "$PTR_VERIFIED" -eq 1 ] && echo true || echo false )
  },
  "ping_ms": ${PING_JSON},
  "location": {
    "registered_country": $(jstr "$COUNTRY"),
    "geofeed": {
      "status": $(jstr "$GEOFEED_STATUS"),
      "prefix": $(jstr "$GEOFEED_PREFIX"),
      "country": $(jstr "$GEOFEED_CC"),
      "region": $(jstr "$GEOFEED_REGION"),
      "city": $(jstr "$GEOFEED_CITY")
    },
    "check": $(jstr "$LOCATION_CHECK")
  },
  "tor_exit_node": $(jstr "$TOR_STATUS"),
  "dnsbl": $(jstr "$DNSBL_STATUS"),
  "abuse_contacts": $(jarr "$ABUSE_EMAILS"),
  "entities": $(jarr "$ALL_FNS"),
  "emails": $(jarr "$ALL_EMAILS"),
  "indicators": [${IND_OUT}],
  "summary": {
    "priority": $(jstr "$PRIORITY"),
    "result": $(jstr "$RESULT_LABEL"),
    "infrastructure": {"class": $(jstr "$INFRA_CLASS"), "score": ${INFRA_SCORE}},
    "threat": {"level": $(jstr "$THREAT_LEVEL"), "signals": $(jarr "$(printf '%s\n' "${THREAT_SIGNALS[@]}")")},
    "note": $( [ -n "$NOTE" ] && jstr "$NOTE" || echo null ),
    "confidence": $(jstr "$CONFIDENCE"),
    "unavailable_checks": $(jarr "$UNAVAIL_LIST")
  },
  "sources": {
    "rdap": $(jstr "$RDAP_URL"),
    "tor_exit_list": "https://check.torproject.org/torbulkexitlist",
    "dnsbl": "zen.spamhaus.org",
    "asn": "Team Cymru IP to ASN Mapping",
    "dns_resolver": $(jstr "$DNS_RESOLVER"),
    "geofeed": $(jstr "$GEOFEED_URL"),
    "rdap_raw_file": $(jstr "$TMP_FILE")
  }
}
JSON
fi