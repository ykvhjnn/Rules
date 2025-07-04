#!/bin/bash
# =============================================================================
# 规则生成脚本 v2.0
# 作者：ykvhjnn
# 功能：生成各种格式的分流规则，支持域名和IP规则
# 支持格式：Mihomo(mrs)、Clash、Adblock、sing-box(srs)
# 使用方法：bash build-rules.sh [组名]
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# 常量定义
# -----------------------------------------------------------------------------
readonly SCRIPT_VERSION="2.0"
readonly SCRIPT_DATE="2025-07-04"
readonly MIHOMO_TOOL=".mihomo_tool"
readonly SINGBOX_TOOL=".singbox_tool"
readonly DESCRIPTION_TEMPLATE="# ============================================
# 名称：%s Rules
# 类型：%s
# 规则数量：%d
# 生成时间：%s
# 生成工具：build-rules.sh v${SCRIPT_VERSION}
# 发布地址：https://github.com/ykvhjnn/Rules
# ============================================\n\n"

# -----------------------------------------------------------------------------
# 辅助函数
# -----------------------------------------------------------------------------
function error_exit() {
    echo "[$(date '+%H:%M:%S')] [ERROR] $1" >&2
    exit 1
}

function log_info() {
    echo "[$(date '+%H:%M:%S')] [INFO] $1"
}

function log_warn() {
    echo "[$(date '+%H:%M:%S')] [WARN] $1" >&2
}

function add_description() {
    local file="$1"
    local group="$2"
    local type="$3"
    local count="$4"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    printf "$DESCRIPTION_TEMPLATE" "$group" "$type" "$count" "$timestamp" | cat - "$file" > temp && mv temp "$file"
}

# -----------------------------------------------------------------------------
# 工具下载函数
# -----------------------------------------------------------------------------
function download_mihomo() {
    if [[ -f "$MIHOMO_TOOL" && -x "$MIHOMO_TOOL" ]]; then
        log_info "Mihomo 工具已存在，跳过下载"
        return
    fi
    log_info "开始下载 Mihomo 工具..."
    wget -q https://github.com/MetaCubeX/mihomo/releases/download/Prerelease-Alpha/version.txt \
        || error_exit "下载 Mihomo 版本文件失败"
    version=$(cat version.txt)
    tool_name="mihomo-linux-amd64-$version"
    wget -q "https://github.com/MetaCubeX/mihomo/releases/download/Prerelease-Alpha/$tool_name.gz" \
        || error_exit "下载 Mihomo 工具失败"
    gzip -d "$tool_name.gz" || error_exit "解压 Mihomo 工具失败"
    chmod +x "$tool_name" || error_exit "赋予 Mihomo 工具可执行权限失败"
    mv "$tool_name" "$MIHOMO_TOOL"
    rm -f version.txt
}

function download_singbox() {
    if [[ -f "$SINGBOX_TOOL" && -x "$SINGBOX_TOOL" ]]; then
        log_info "sing-box 工具已存在，跳过下载"
        return
    fi
    log_info "开始下载 sing-box 工具..."
    latest_version=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | grep -Po '"tag_name": "\K.*?(?=")')
    [[ -z "$latest_version" ]] && error_exit "获取 sing-box 版本失败"
    
    wget -q "https://github.com/SagerNet/sing-box/releases/download/${latest_version}/sing-box-${latest_version#v}-linux-amd64.tar.gz" \
        || error_exit "下载 sing-box 工具失败"
    
    tar xzf "sing-box-${latest_version#v}-linux-amd64.tar.gz" \
        || error_exit "解压 sing-box 工具失败"
    
    mv "sing-box-${latest_version#v}-linux-amd64/sing-box" "$SINGBOX_TOOL" \
        || error_exit "移动 sing-box 工具失败"
    
    chmod +x "$SINGBOX_TOOL" || error_exit "赋予 sing-box 工具可执行权限失败"
    rm -rf "sing-box-${latest_version#v}-linux-amd64" "sing-box-${latest_version#v}-linux-amd64.tar.gz"
}

# -----------------------------------------------------------------------------
# 规则源配置
# -----------------------------------------------------------------------------
declare -A urls_map=(
    ["Proxy"]="
https://ruleset.skk.moe/Clash/domainset/speedtest.txt
https://ruleset.skk.moe/Clash/non_ip/my_proxy.txt
https://ruleset.skk.moe/Clash/non_ip/ai.txt
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/GitHub/GitHub.list
https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/proxy.list
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Global/Global_Domain_For_Clash.txt
https://raw.githubusercontent.com/ykvhjnn/Rules/refs/heads/main/Add/Proxy.txt"

    ["Directfix"]="
https://ruleset.skk.moe/Clash/non_ip/microsoft_cdn.txt
https://ruleset.skk.moe/Clash/non_ip/lan.txt
https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/private.list
https://raw.githubusercontent.com/ykvhjnn/Rules/refs/heads/main/Add/Direct.txt"

    ["Ad"]="
https://raw.githubusercontent.com/ghvjjjj/adblockfilters/refs/heads/main/rules/adblockdomain.txt
https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdomainlite.txt
https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/refs/heads/master/anti-ad-adguard.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.xiaomi.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.oppo-realme.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.vivo.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.tiktok.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.samsung.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.huawei.txt
https://raw.githubusercontent.com/ykvhjnn/Rules/refs/heads/main/Add/Ad.txt"

    ["Direct"]="
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/China/China_Domain_For_Clash.txt"
)

declare -A ip_urls_map=(
    ["Proxy"]="
https://raw.githubusercontent.com/pmkol/easymosdns/refs/heads/main/rules/gfw_ip_list.txt"
)

declare -A py_scripts=(
    ["Proxy"]="collect.py remove_domains_Proxy.py clean.py add_domains_Proxy.py"
    ["Directfix"]="collect.py clean.py"
    ["Ad"]="collect.py remove_domains_Ad.py clean.py add_domains_Ad.py"
    ["Direct"]="collect.py clean.py"
)

# -----------------------------------------------------------------------------
# 参数检查
# -----------------------------------------------------------------------------
if [[ $# -ne 1 ]]; then
    echo "用法: $0 [组名]"
    echo "可用组:"
    for k in "${!urls_map[@]}"; do
        echo "  - $k"
    done
    exit 1
fi

group="$1"
if [[ -z "${urls_map[$group]:-}" ]]; then
    error_exit "未找到组: $group"
fi

# -----------------------------------------------------------------------------
# 文件名定义
# -----------------------------------------------------------------------------
domain_file="${group}_domain.txt"
ip_file="${group}_ip.txt"
tmp_file="${group}_tmp.txt"
ip_tmp_file="${group}_ip_tmp.txt"
mihomo_txt_file="${group}_Mihomo.txt"
mihomo_mrs_file="${mihomo_txt_file%.txt}.mrs"
mihomo_ip_txt_file="${group}_Mihomo_ip.txt"
mihomo_ip_mrs_file="${mihomo_ip_txt_file%.txt}.mrs"
clash_file="${group}_clash.txt"
adblock_file="${group}_adblock.txt"
singbox_file="${group}_singbox.json"
singbox_srs_file="${group}_singbox.srs"

# -----------------------------------------------------------------------------
# 工具准备
# -----------------------------------------------------------------------------
cd "$(cd "$(dirname "$0")"; pwd)" || error_exit "无法进入脚本目录"
download_mihomo
download_singbox

# -----------------------------------------------------------------------------
# 清理临时文件
# -----------------------------------------------------------------------------
> "$domain_file"
> "$tmp_file"
> "$ip_file"
> "$ip_tmp_file"

# -----------------------------------------------------------------------------
# 下载规则源
# -----------------------------------------------------------------------------
log_info "开始并发下载规则源..."

# 处理域名规则
urls_list=()
while read -r url; do
    [[ -n "$url" ]] && urls_list+=("$url")
done <<< "${urls_map[$group]}"

for url in "${urls_list[@]}"; do
    {
        out="${tmp_file}_$RANDOM"
        if curl --http2 --compressed --max-time 30 --retry 2 -sSL "$url" >> "$out"; then
            log_info "拉取域名规则成功: $url"
        else
            log_warn "拉取域名规则失败: $url"
        fi
    } &
    if [[ $(jobs -rp | wc -l) -ge 8 ]]; then
        wait -n
    fi
done
wait

# 处理IP规则
if [[ -n "${ip_urls_map[$group]:-}" ]]; then
    ip_urls_list=()
    while read -r url; do
        [[ -n "$url" ]] && ip_urls_list+=("$url")
    done <<< "${ip_urls_map[$group]}"

    for url in "${ip_urls_list[@]}"; do
        {
            out="${ip_tmp_file}_$RANDOM"
            if curl --http2 --compressed --max-time 30 --retry 2 -sSL "$url" >> "$out"; then
                log_info "拉取IP规则成功: $url"
            else
                log_warn "拉取IP规则失败: $url"
            fi
        } &
        if [[ $(jobs -rp | wc -l) -ge 8 ]]; then
            wait -n
        fi
    done
    wait
fi

cat "${tmp_file}"_* >> "$tmp_file" 2>/dev/null || true
cat "${ip_tmp_file}"_* >> "$ip_tmp_file" 2>/dev/null || true
rm -f "${tmp_file}"_* "${ip_tmp_file}"_*

log_info "规则源全部下载合并完成"

# -----------------------------------------------------------------------------
# 规则处理
# -----------------------------------------------------------------------------
cat "$tmp_file" >> "$domain_file"
cat "$ip_tmp_file" >> "$ip_file"
rm -f "$tmp_file" "$ip_tmp_file"
sed -i 's/\r//' "$domain_file" "$ip_file"

# 执行Python清洗脚本
for py in ${py_scripts[$group]}; do
    [[ ! -f "$py" ]] && error_exit "找不到 Python 脚本: $py"
    log_info "执行脚本: $py"
    python "$py" "$domain_file" || error_exit "Python 脚本 $py 执行失败"
done

# 统计规则数量
domain_count=$(grep -vE '^\s*$|^#' "$domain_file" | wc -l)
ip_count=$(grep -vE '^\s*$|^#' "$ip_file" | wc -l)
log_info "域名规则数量: $domain_count"
log_info "IP规则数量: $ip_count"

# -----------------------------------------------------------------------------
# 规则转换
# -----------------------------------------------------------------------------
# 域名规则处理
sed "s/^/\+\./g" "$domain_file" > "$mihomo_txt_file"
add_description "$mihomo_txt_file" "$group" "Domain" "$domain_count"

# IP规则处理
if [[ -s "$ip_file" ]]; then
    grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$' "$ip_file" > "$mihomo_ip_txt_file"
    add_description "$mihomo_ip_txt_file" "$group" "IP-CIDR" "$ip_count"
fi

# 转换域名规则
if ! "./$MIHOMO_TOOL" convert-ruleset domain text "$mihomo_txt_file" "$mihomo_mrs_file"; then
    error_exit "Mihomo 工具转换域名规则失败"
fi

# 转换IP规则
if [[ -s "$mihomo_ip_txt_file" ]]; then
    if ! "./$MIHOMO_TOOL" convert-ruleset ipcidr text "$mihomo_ip_txt_file" "$mihomo_ip_mrs_file"; then
        error_exit "Mihomo 工具转换IP规则失败"
    fi
fi

# -----------------------------------------------------------------------------
# 生成其他格式
# -----------------------------------------------------------------------------
# Clash格式
{
    printf "$DESCRIPTION_TEMPLATE" "$group" "Clash" "$((domain_count + ip_count))" "$(date '+%Y-%m-%d %H:%M:%S')"
    awk '!/^(\s*$|#)/{gsub(/^[ \t]*/,"");gsub(/[ \t]*$/,""); print "DOMAIN-SUFFIX,"$0}' "$domain_file"
    if [[ -s "$ip_file" ]]; then
        awk '!/^(\s*$|#)/{gsub(/^[ \t]*/,"");gsub(/[ \t]*$/,""); print "IP-CIDR,"$0}' "$ip_file"
    fi
} > "$clash_file"

# Adblock格式
{
    printf "$DESCRIPTION_TEMPLATE" "$group" "Adblock" "$domain_count" "$(date '+%Y-%m-%d %H:%M:%S')"
    awk '!/^(\s*$|#)/{gsub(/^[ \t]*/,"");gsub(/[ \t]*$/,""); print "||"$0"^"}' "$domain_file"
} > "$adblock_file"

# sing-box格式
{
    echo "{"
    echo "  \"version\": 3,"
    echo "  \"rules\": ["
    
    # 域名规则
    echo "    {"
    echo "      \"domain_suffix\": ["
    awk -v first=1 '
    !/^(\s*$|#)/ {
        gsub(/^[ \t]*/,"")
        gsub(/[ \t]*$/,"")
        if (!first) printf ",\n"
        printf "        \"%s\"", $0
        first=0
    }' "$domain_file"
    echo
    echo "      ]"
    echo "    }"
    
    # IP规则
    if [[ -s "$ip_file" ]]; then
        echo "    ,{"
        echo "      \"ip_cidr\": ["
        awk -v first=1 '
        !/^(\s*$|#)/ {
            gsub(/^[ \t]*/,"")
            gsub(/[ \t]*$/,"")
            if (!first) printf ",\n"
            printf "        \"%s\"", $0
            first=0
        }' "$ip_file"
        echo
        echo "      ]"
        echo "    }"
    fi
    
    echo "  ]"
    echo "}"
} > "$singbox_file"

# 转换为srs格式
if ! "./$SINGBOX_TOOL" rule-set compile "$singbox_file" -o "$singbox_srs_file"; then
    error_exit "sing-box 工具转换失败"
fi

# -----------------------------------------------------------------------------
# 文件整理
# -----------------------------------------------------------------------------
repo_root="$(cd ../.. && pwd)"
mkdir -p "$repo_root/"{txt,mrs,domain,ip,clash,adblock,singbox,srs,.cache}

mv "$mihomo_txt_file" "$repo_root/txt/"
mv "$mihomo_mrs_file" "$repo_root/mrs/"
mv "$domain_file" "$repo_root/domain/"
[[ -f "$mihomo_ip_txt_file" ]] && mv "$mihomo_ip_txt_file" "$repo_root/txt/"
[[ -f "$mihomo_ip_mrs_file" ]] && mv "$mihomo_ip_mrs_file" "$repo_root/mrs/"
[[ -f "$ip_file" ]] && mv "$ip_file" "$repo_root/ip/"
mv "$clash_file" "$repo_root/clash/"
mv "$adblock_file" "$repo_root/adblock/"
mv "$singbox_file" "$repo_root/singbox/"
mv "$singbox_srs_file" "$repo_root/srs/"

rm -f "${group}_tmp.txt" "${group}_ip_tmp.txt"

log_info "[完成] $group 规则生成并清理完毕"
