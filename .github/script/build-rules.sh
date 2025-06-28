#!/bin/bash
# =============================================================================
# 通用规则生成脚本，支持多种规则类型（如 Proxy、Directfix、Ad、自定义等）
# 用法示例：bash build-rules.sh Proxy|Directfix|Ad|自定义组名
# =============================================================================

set -euo pipefail   # 严格模式：遇到错误立即退出，变量未定义即报错

# -----------------------------------------------------------------------------
# 【步骤1】错误输出与退出函数
# -----------------------------------------------------------------------------
function error_exit() {
    echo "[$(date '+%H:%M:%S')] [ERROR] $1" >&2
    exit 1
}

# -----------------------------------------------------------------------------
# 【步骤2】参数检查，必须指定规则类型（组名）
# -----------------------------------------------------------------------------
if [[ $# -ne 1 ]]; then
    echo "[$(date '+%H:%M:%S')] 用法: $0 [组名]"
    echo "示例: $0 Proxy"
    exit 1
fi

# -----------------------------------------------------------------------------
# 【步骤3】进入脚本目录，确保相对路径正确
# -----------------------------------------------------------------------------
cd "$(cd "$(dirname "$0")"; pwd)" || error_exit "无法进入脚本目录"

# -----------------------------------------------------------------------------
# 【步骤4】全部规则源组定义（可自定义扩展组名及规则url）
# -----------------------------------------------------------------------------
declare -A urls_map

urls_map["Proxy"]="
https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/proxy.list
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Global/Global_Domain_For_Clash.txt
https://raw.githubusercontent.com/ykvhjnn/Rules/refs/heads/main/Add/Proxy.txt
"

urls_map["Directfix"]="
https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/private.list
https://raw.githubusercontent.com/ykvhjnn/Rules/refs/heads/main/Add/Direct.txt
"

urls_map["Ad"]="
https://raw.githubusercontent.com/ghvjjjj/adblockfilters/refs/heads/main/rules/adblockdomain.txt
https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt
https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt
https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/refs/heads/master/anti-ad-domains.txt
https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/refs/heads/master/anti-ad-adguard.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.xiaomi.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.oppo-realme.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.vivo.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.roku.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.lgwebos.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.tiktok.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.samsung.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.winoffice.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.amazon.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.apple.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.huawei.txt
https://raw.githubusercontent.com/ykvhjnn/Rules/refs/heads/main/Add/Ad.txt
"

urls_map["Direct"]="
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/China/China_Domain_For_Clash.txt
"

# -----------------------------------------------------------------------------
# 【步骤5】各组对应的 Python 清洗脚本列表（组名一一对应）
# -----------------------------------------------------------------------------
declare -A py_scripts
py_scripts["Proxy"]="collect.py remove-proxy.py clean.py"
py_scripts["Directfix"]="collect.py clean.py"
py_scripts["Ad"]="collect.py remove-ad.py clean.py"
py_scripts["Direct"]="collect.py clean.py"

# -----------------------------------------------------------------------------
# 【步骤6】参数校验，必须是已定义组名
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
# 【步骤7】相关文件名变量定义
# -----------------------------------------------------------------------------
domain_file="${group}_domain.txt"
tmp_file="${group}_tmp.txt"
mihomo_txt_file="${group}_Mihomo.txt"
mihomo_mrs_file="${mihomo_txt_file%.txt}.mrs"

# -----------------------------------------------------------------------------
# 【步骤8】下载 Mihomo 工具（只下载一次，已存在则跳过）
# -----------------------------------------------------------------------------
MIHOMO_TOOL=".mihomo_tool"
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
download_mihomo

# -----------------------------------------------------------------------------
# 【步骤9】清理旧临时文件，防止数据混杂
# -----------------------------------------------------------------------------
> "$domain_file"
> "$tmp_file"

# -----------------------------------------------------------------------------
# 【步骤10】并发批量下载规则源，合并到临时文件
# -----------------------------------------------------------------------------
echo "[$(date '+%H:%M:%S')] 开始并发下载规则源..."

# 下载速度优化：最多 8 并发，失败重试，全部合并
urls_list=()
while read -r url; do
    [[ -n "$url" ]] && urls_list+=("$url")
done <<< "${urls_map[$group]}"

pids=()
for url in "${urls_list[@]}"; do
    {
        out="${tmp_file}_$RANDOM"
        if curl --http2 --compressed --max-time 30 --retry 2 -sSL "$url" >> "$out"; then
            echo "[$(date '+%H:%M:%S')] [小] 拉取成功: $url"
        else
            echo "[$(date '+%H:%M:%S')] [WARN] 拉取失败: $url" >&2
        fi
    } &
    # 限制最大并发数为8，防止过载
    if [[ $(jobs -rp | wc -l) -ge 8 ]]; then
        wait -n
    fi
done
wait
cat "${tmp_file}"_* >> "$tmp_file" 2>/dev/null || true
rm -f "${tmp_file}"_*

echo "[$(date '+%H:%M:%S')] 规则源全部下载合并完成"

# -----------------------------------------------------------------------------
# 【步骤11】合并临时文件到主文件并清理换行符
# -----------------------------------------------------------------------------
cat "$tmp_file" >> "$domain_file"
rm -f "$tmp_file"
sed -i 's/\r//' "$domain_file"

# -----------------------------------------------------------------------------
# 【步骤12】依次执行对应 Python 清洗脚本
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
# 【步骤13】统计最终规则数量，排除空行与注释
# -----------------------------------------------------------------------------
rule_count=$(grep -vE '^\s*$|^#' "$domain_file" | wc -l)
echo "[$(date '+%H:%M:%S')] 文件: $mihomo_txt_file, $mihomo_mrs_file"
echo "[$(date '+%H:%M:%S')] 规则总数: $rule_count"

# -----------------------------------------------------------------------------
# 【步骤14】格式化输出，全部加前缀 +.
# -----------------------------------------------------------------------------
sed "s/^/\\+\\./g" "$domain_file" > "$mihomo_txt_file"

# -----------------------------------------------------------------------------
# 【步骤15】调用 Mihomo 工具转换为mrs格式
# -----------------------------------------------------------------------------
if ! "./$MIHOMO_TOOL" convert-ruleset domain text "$mihomo_txt_file" "$mihomo_mrs_file"; then
    error_exit "Mihomo 工具转换 $mihomo_txt_file 失败"
fi

# -----------------------------------------------------------------------------
# 【步骤16】整理输出文件夹并清理临时文件
# -----------------------------------------------------------------------------
mkdir -p ../txt
mv "$mihomo_txt_file" "../txt/$mihomo_txt_file"
mv "$mihomo_mrs_file" "../$mihomo_mrs_file"
rm -rf ./*.txt

echo "[$(date '+%H:%M:%S')] [完成] $group 规则生成并清理完毕"
