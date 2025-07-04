#!/bin/bash
# =============================================================================
# 通用规则生成脚本 v2.0
# 支持域名和IP规则的转换与格式化输出
# 作者: ykvhjnn
# 最后更新: 2025-07-04
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# 【步骤1】错误输出与退出函数
# -----------------------------------------------------------------------------
function error_exit() {
    echo "[$(date '+%H:%M:%S')] [ERROR] $1" >&2
    exit 1
}

# -----------------------------------------------------------------------------
# 【步骤2】参数检查
# -----------------------------------------------------------------------------
if [[ $# -ne 1 ]]; then
    echo "[$(date '+%H:%M:%S')] 用法: $0 [组名]"
    echo "示例: $0 Proxy"
    exit 1
fi

# -----------------------------------------------------------------------------
# 【步骤3】进入脚本目录
# -----------------------------------------------------------------------------
cd "$(cd "$(dirname "$0")"; pwd)" || error_exit "无法进入脚本目录"

# -----------------------------------------------------------------------------
# 【步骤4】规则源定义
# -----------------------------------------------------------------------------
declare -A urls_map
declare -A ip_urls_map
declare -A descriptions_map

# 规则描述定义
descriptions_map["Proxy"]="! Title: Proxy Rules
! Description: Rules for proxy traffic
! Last modified: $(date -u '+%Y-%m-%d %H:%M:%S') UTC
! Author: ykvhjnn
! Homepage: https://github.com/ykvhjnn/Rules
! License: MIT"

descriptions_map["Directfix"]="! Title: Direct Fix Rules
! Description: Rules for direct connection
! Last modified: $(date -u '+%Y-%m-%d %H:%M:%S') UTC
! Author: ykvhjnn
! Homepage: https://github.com/ykvhjnn/Rules
! License: MIT"

descriptions_map["Ad"]="[Adblock Plus 2.0]
! Title: Ad Blocking Rules
! Description: Block advertisements and tracking
! Last modified: $(date -u '+%Y-%m-%d %H:%M:%S') UTC
! Expires: 12 hours
! Homepage: https://github.com/ykvhjnn/Rules
! License: MIT"

descriptions_map["Direct"]="! Title: China Direct Rules
! Description: Rules for China direct connection
! Last modified: $(date -u '+%Y-%m-%d %H:%M:%S') UTC
! Author: ykvhjnn
! Homepage: https://github.com/ykvhjnn/Rules
! License: MIT"

# 域名规则源
urls_map["Proxy"]="
https://ruleset.skk.moe/Clash/domainset/speedtest.txt
https://ruleset.skk.moe/Clash/non_ip/my_proxy.txt
https://ruleset.skk.moe/Clash/non_ip/ai.txt
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/GitHub/GitHub.list
https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/proxy.list
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Global/Global_Domain_For_Clash.txt
https://raw.githubusercontent.com/ykvhjnn/Rules/refs/heads/main/Add/Proxy.txt
"

# IP规则源
ip_urls_map["Proxy"]="
https://raw.githubusercontent.com/pmkol/easymosdns/refs/heads/main/rules/gfw_ip_list.txt
"

urls_map["Directfix"]="
https://ruleset.skk.moe/Clash/non_ip/microsoft_cdn.txt
https://ruleset.skk.moe/Clash/non_ip/lan.txt
https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/private.list
https://raw.githubusercontent.com/ykvhjnn/Rules/refs/heads/main/Add/Direct.txt
"

urls_map["Ad"]="
https://raw.githubusercontent.com/ghvjjjj/adblockfilters/refs/heads/main/rules/adblockdomain.txt
https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdomainlite.txt
https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/refs/heads/master/anti-ad-adguard.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.xiaomi.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.oppo-realme.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.vivo.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.tiktok.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.samsung.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.huawei.txt
https://raw.githubusercontent.com/ykvhjnn/Rules/refs/heads/main/Add/Ad.txt
"

urls_map["Direct"]="
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/China/China_Domain_For_Clash.txt
"

# -----------------------------------------------------------------------------
# 【步骤5】Python脚本定义
# -----------------------------------------------------------------------------
declare -A py_scripts
py_scripts["Proxy"]="collect.py remove_domains_Proxy.py clean.py add_domains_Proxy.py"
py_scripts["Directfix"]="collect.py clean.py"
py_scripts["Ad"]="collect.py remove_domains_Ad.py clean.py add_domains_Ad.py"
py_scripts["Direct"]="collect.py clean.py"

# -----------------------------------------------------------------------------
# 【步骤6】参数校验
# -----------------------------------------------------------------------------
group="$1"
if [[ -z "${urls_map[$group]:-}" ]]; then
    echo "[$(date '+%H:%M:%S')] [ERROR] 未找到组: $group"
    echo "可用组有:"
    for k in "${!urls_map[@]}"; do
        echo "  - $k"
    done
    exit 1
fi

# -----------------------------------------------------------------------------
# 【步骤7】文件名定义
# -----------------------------------------------------------------------------
domain_file="${group}_domain.txt"
ip_file="${group}_ip.txt"
tmp_file="${group}_tmp.txt"
ip_tmp_file="${group}_ip_tmp.txt"
mihomo_txt_file="${group}_Mihomo.yaml"  # 改为yaml格式
mihomo_mrs_file="${group}_Mihomo.mrs"
mihomo_ip_txt_file="${group}_Mihomo_ip.yaml"  # 改为yaml格式
mihomo_ip_mrs_file="${group}_Mihomo_ip.mrs"
clash_file="${group}_clash.yaml"  # 改为yaml格式
adblock_file="${group}_adblock.txt"
singbox_file="${group}_singbox.json"
singbox_srs_file="${group}_singbox.srs"

# -----------------------------------------------------------------------------
# 【步骤8】工具下载
# -----------------------------------------------------------------------------
MIHOMO_TOOL=".mihomo_tool"
SINGBOX_TOOL=".singbox_tool"

function download_mihomo() {
    if [[ -f "$MIHOMO_TOOL" && -x "$MIHOMO_TOOL" ]]; then
        echo "[$(date '+%H:%M:%S')] Mihomo 工具已存在，跳过下载"
        return
    fi
    echo "[$(date '+%H:%M:%S')] 开始下载 Mihomo 工具..."
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
        echo "[$(date '+%H:%M:%S')] sing-box 工具已存在，跳过下载"
        return
    fi
    echo "[$(date '+%H:%M:%S')] 开始下载 sing-box 工具..."
    latest_version=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | grep -Po '"tag_name": "\K.*?(?=")')
    if [[ -z "$latest_version" ]]; then
        error_exit "获取 sing-box 版本失败"
    fi
    wget -q "https://github.com/SagerNet/sing-box/releases/download/${latest_version}/sing-box-${latest_version#v}-linux-amd64.tar.gz" \
        || error_exit "下载 sing-box 工具失败"
    tar xzf "sing-box-${latest_version#v}-linux-amd64.tar.gz" \
        || error_exit "解压 sing-box 工具失败"
    mv "sing-box-${latest_version#v}-linux-amd64/sing-box" "$SINGBOX_TOOL" \
        || error_exit "移动 sing-box 工具失败"
    chmod +x "$SINGBOX_TOOL" || error_exit "赋予 sing-box 工具可执行权限失败"
    rm -rf "sing-box-${latest_version#v}-linux-amd64" "sing-box-${latest_version#v}-linux-amd64.tar.gz"
}

download_mihomo
download_singbox

# -----------------------------------------------------------------------------
# 【步骤9】清理临时文件
# -----------------------------------------------------------------------------
> "$domain_file"
> "$tmp_file"
> "$ip_file"
> "$ip_tmp_file"

# -----------------------------------------------------------------------------
# 【步骤10】下载规则源
# -----------------------------------------------------------------------------
echo "[$(date '+%H:%M:%S')] 开始并发下载规则源..."

# 处理域名规则
urls_list=()
while read -r url; do
    [[ -n "$url" ]] && urls_list+=("$url")
done <<< "${urls_map[$group]}"

for url in "${urls_list[@]}"; do
    {
        out="${tmp_file}_$RANDOM"
        if curl --http2 --compressed --max-time 30 --retry 2 -sSL "$url" >> "$out"; then
            echo "[$(date '+%H:%M:%S')] [成功] 拉取域名规则: $url"
        else
            echo "[$(date '+%H:%M:%S')] [警告] 拉取域名规则失败: $url" >&2
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
                echo "[$(date '+%H:%M:%S')] [成功] 拉取IP规则: $url"
            else
                echo "[$(date '+%H:%M:%S')] [警告] 拉取IP规则失败: $url" >&2
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

# -----------------------------------------------------------------------------
# 【步骤11】合并和清理
# -----------------------------------------------------------------------------
cat "$tmp_file" >> "$domain_file"
cat "$ip_tmp_file" >> "$ip_file"
rm -f "$tmp_file" "$ip_tmp_file"
sed -i 's/\r//' "$domain_file" "$ip_file"

# IP去重
if [[ -s "$ip_file" ]]; then
    sort -u "$ip_file" -o "$ip_file"
fi

# -----------------------------------------------------------------------------
# 【步骤12】执行Python清洗脚本
# -----------------------------------------------------------------------------
for py in ${py_scripts[$group]}; do
    if [[ ! -f "$py" ]]; then
        error_exit "找不到 Python 脚本: $py"
    fi
    echo "[$(date '+%H:%M:%S')] 执行脚本: $py"
    if ! python "$py" "$domain_file"; then
        error_exit "Python 脚本 $py 执行失败"
    fi
done

# -----------------------------------------------------------------------------
# 【步骤13】统计规则数量
# -----------------------------------------------------------------------------
domain_count=$(grep -vE '^\s*$|^#' "$domain_file" | wc -l)
ip_count=$(grep -vE '^\s*$|^#' "$ip_file" | wc -l)
echo "[$(date '+%H:%M:%S')] 域名规则数量: $domain_count"
echo "[$(date '+%H:%M:%S')] IP规则数量: $ip_count"

# -----------------------------------------------------------------------------
# 【步骤14】生成各种格式的规则文件
# -----------------------------------------------------------------------------
# 生成Mihomo域名规则yaml格式
{
    echo "# ${descriptions_map[$group]}"
    echo "payload:"
    sed -n '/^[^#]/s/^/  - +./p' "$domain_file"
} > "$mihomo_txt_file"

# 生成Mihomo IP规则yaml格式
if [[ -s "$ip_file" ]]; then
    {
        echo "# ${descriptions_map[$group]}"
        echo "payload:"
        sed -n '/^[^#]/s/^/  - /p' "$ip_file"
    } > "$mihomo_ip_txt_file"
fi

# -----------------------------------------------------------------------------
# 【步骤15】转换Mihomo规则
# -----------------------------------------------------------------------------
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
# 【步骤16】生成其他格式规则
# -----------------------------------------------------------------------------
# 生成Clash Classical格式
{
    echo "# ${descriptions_map[$group]}"
    echo "payload:"
    # 域名规则
    awk '!/^(\s*$|#)/{gsub(/^[ \t]*/,"");gsub(/[ \t]*$/,""); print "  - DOMAIN-SUFFIX,"$0}' "$domain_file"
    # IP规则
    if [[ -s "$ip_file" ]]; then
        awk '!/^(\s*$|#)/{gsub(/^[ \t]*/,"");gsub(/[ \t]*$/,""); print "  - IP-CIDR,"$0}' "$ip_file"
    fi
} > "$clash_file"

# 生成Adblock格式
{
    echo "${descriptions_map[$group]}"
    awk '!/^(\s*$|#)/{gsub(/^[ \t]*/,"");gsub(/[ \t]*$/,""); print "||"$0"^"}' "$domain_file"
} > "$adblock_file"

# 生成sing-box格式
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

# -----------------------------------------------------------------------------
# 【步骤17】转换sing-box格式
# -----------------------------------------------------------------------------
if ! "./$SINGBOX_TOOL" rule-set compile "$singbox_file" -o "$singbox_srs_file"; then
    error_exit "sing-box 工具转换失败"
fi

# -----------------------------------------------------------------------------
# 【步骤18】组织输出目录
# -----------------------------------------------------------------------------
repo_root="$(cd ../.. && pwd)"
mkdir -p "$repo_root/clash_domain" \
         "$repo_root/mrs" \
         "$repo_root/domain" \
         "$repo_root/ip" \
         "$repo_root/clash_classical" \
         "$repo_root/adblock" \
         "$repo_root/singbox" \
         "$repo_root/srs" \
         "$repo_root/.cache"

# 移动文件到对应目录
mv "$mihomo_txt_file" "$repo_root/clash_domain/$mihomo_txt_file"
mv "$mihomo_mrs_file" "$repo_root/mrs/$mihomo_mrs_file"
mv "$domain_file" "$repo_root/domain/$domain_file"
[[ -f "$mihomo_ip_txt_file" ]] && mv "$mihomo_ip_txt_file" "$repo_root/clash_domain/$mihomo_ip_txt_file"
[[ -f "$mihomo_ip_mrs_file" ]] && mv "$mihomo_ip_mrs_file" "$repo_root/mrs/$mihomo_ip_mrs_file"
[[ -f "$ip_file" ]] && mv "$ip_file" "$repo_root/ip/$ip_file"
mv "$clash_file" "$repo_root/clash_classical/$clash_file"
mv "$adblock_file" "$repo_root/adblock/$adblock_file"
mv "$singbox_file" "$repo_root/singbox/$singbox_file"
mv "$singbox_srs_file" "$repo_root/srs/$singbox_srs_file"

# 清理残留的临时文件
rm -f "${group}_tmp.txt" "${group}_ip_tmp.txt"

echo "[$(date '+%H:%M:%S')] [完成] $group 规则生成完毕"
echo "规则文件已保存到以下目录:"
echo "- 域名规则 (YAML): $repo_root/clash_domain"
echo "- MRS规则: $repo_root/mrs"
echo "- 原始域名: $repo_root/domain"
echo "- 原始IP: $repo_root/ip"
echo "- Clash经典规则: $repo_root/clash_classical"
echo "- Adblock规则: $repo_root/adblock"
echo "- Sing-box规则: $repo_root/singbox"
echo "- SRS规则: $repo_root/srs"
