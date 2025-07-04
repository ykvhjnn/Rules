#!/bin/bash
# =============================================================================
# 规则生成脚本 v3.0
# 作者：ykvhjnn
# 创建日期：2025-07-04
# 最后更新：2025-07-04 13:31:11
# 
# 功能：生成各种格式的分流规则，支持域名和IP规则
# 支持格式：
# - Mihomo (mrs)
# - Clash
# - Adblock
# - sing-box (srs)
#
# 使用方法：bash build-rules.sh [组名]
# =============================================================================

# 确保脚本严格执行
set -euo pipefail

# =============================================================================
# 常量定义
# =============================================================================
SCRIPT_VERSION="3.0"
SCRIPT_DATE="2025-07-04"

# 目录相关常量
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEMP_ROOT="/tmp"
TEMP_DIR="${TEMP_ROOT}/rules_build_$(date +%Y%m%d_%H%M%S)_$$"
TOOLS_DIR="${SCRIPT_DIR}"  # 工具目录与脚本目录相同
PYTHON_SCRIPTS_DIR="${SCRIPT_DIR}/python"

# 工具相关常量
MIHOMO_TOOL="mihomo"
SINGBOX_TOOL="sing-box"

# 输出目录
OUTPUT_DIRS=(
    "txt"
    "mrs"
    "domain"
    "ip"
    "clash"
    "adblock"
    "singbox"
    "srs"
)

# 描述模板
DESCRIPTION_TEMPLATE="# ============================================
# 名称：%s Rules
# 类型：%s
# 规则数量：%d
# 生成时间：%s
# 生成工具：build-rules.sh v${SCRIPT_VERSION}
# 发布地址：https://github.com/ykvhjnn/Rules
# ============================================

"

# =============================================================================
# 辅助函数
# =============================================================================

# 日志函数
log_info() {
    echo -e "\033[32m[INFO] $*\033[0m"
}

log_warn() {
    echo -e "\033[33m[WARN] $*\033[0m" >&2
}

log_error() {
    echo -e "\033[31m[ERROR] $*\033[0m" >&2
}

# 错误退出函数
error_exit() {
    log_error "$1"
    exit 1
}

# 检查并创建目录
check_and_create_dir() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir" || error_exit "创建目录失败: $dir"
    fi
}

# 检查必需的工具
check_required_tools() {
    local missing_tools=()
    
    # 检查基本命令行工具
    for tool in curl wget gzip tar python3 awk sed sort uniq; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    # 检查 Mihomo 工具
    if [[ ! -x "${TOOLS_DIR}/${MIHOMO_TOOL}" ]]; then
        missing_tools+=("mihomo")
    fi
    
    # 检查 sing-box 工具
    if [[ ! -x "${TOOLS_DIR}/${SINGBOX_TOOL}" ]]; then
        missing_tools+=("sing-box")
    fi
    
    if (( ${#missing_tools[@]} > 0 )); then
        error_exit "缺少必需的工具: ${missing_tools[*]}"
    fi
}

# 清理临时文件
cleanup() {
    local exit_code=$?
    log_info "清理临时文件..."
    
    # 删除临时目录
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
    
    if (( exit_code != 0 )); then
        log_error "脚本执行失败"
    else
        log_info "脚本执行完成"
    fi
}

# =============================================================================
# 规则处理函数
# =============================================================================

# 下载规则文件
download_rules() {
    local group="$1"
    local output_dir="$2"
    local rules_url="https://raw.githubusercontent.com/ykvhjnn/Rules/main/rules/${group}.txt"
    
    if ! wget -q "$rules_url" -O "${output_dir}/${group}.txt"; then
        error_exit "下载规则文件失败: $rules_url"
    fi
}

# 处理规则文件
process_rules() {
    local input_file="$1"
    local output_dir="$2"
    local group="$3"
    
    # 创建输出目录
    for dir in "${OUTPUT_DIRS[@]}"; do
        check_and_create_dir "${output_dir}/${dir}"
    done
    
    # 分离域名和 IP 规则
    local domains_file="${output_dir}/domain/${group}.txt"
    local ips_file="${output_dir}/ip/${group}.txt"
    
    grep -E '^[a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,}$' "$input_file" | sort -u > "$domains_file"
    grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$' "$input_file" | sort -u > "$ips_file"
    
    local domain_count=$(wc -l < "$domains_file")
    local ip_count=$(wc -l < "$ips_file")
    
    # 生成各种格式的规则
    generate_mihomo_rules "$domains_file" "$ips_file" "${output_dir}/mrs/${group}.txt" "$group" "$((domain_count + ip_count))"
    generate_clash_rules "$domains_file" "$ips_file" "${output_dir}/clash/${group}.yaml" "$group" "$((domain_count + ip_count))"
    generate_adblock_rules "$domains_file" "${output_dir}/adblock/${group}.txt" "$group" "$domain_count"
    generate_singbox_rules "$domains_file" "$ips_file" "${output_dir}/srs/${group}.json" "$group" "$((domain_count + ip_count))"
}

# 生成 Mihomo 规则
generate_mihomo_rules() {
    local domains_file="$1"
    local ips_file="$2"
    local output_file="$3"
    local group="$4"
    local total_count="$5"
    
    {
        printf "$DESCRIPTION_TEMPLATE" "$group" "Mihomo Rules" "$total_count" "$(date -u +'%Y-%m-%d %H:%M:%S')"
        
        if [[ -s "$domains_file" ]]; then
            echo "DOMAIN-SUFFIX,"
            sed 's/$/,DIRECT/' "$domains_file"
        fi
        
        if [[ -s "$ips_file" ]]; then
            echo "IP-CIDR,"
            sed 's/$/,DIRECT,no-resolve/' "$ips_file"
        fi
    } > "$output_file"
    
    "${TOOLS_DIR}/${MIHOMO_TOOL}" convert -f mrs "$output_file"
}

# 生成 Clash 规则
generate_clash_rules() {
    local domains_file="$1"
    local ips_file="$2"
    local output_file="$3"
    local group="$4"
    local total_count="$5"
    
    {
        echo "payload:"
        
        if [[ -s "$domains_file" ]]; then
            sed 's/^/  - DOMAIN-SUFFIX,/' "$domains_file"
        fi
        
        if [[ -s "$ips_file" ]]; then
            sed 's/^/  - IP-CIDR,/' "$ips_file"
        fi
        
        echo "# $group Rules"
        echo "# 规则数量：$total_count"
        echo "# 生成时间：$(date -u +'%Y-%m-%d %H:%M:%S')"
    } > "$output_file"
}

# 生成 Adblock 规则
generate_adblock_rules() {
    local domains_file="$1"
    local output_file="$2"
    local group="$3"
    local count="$4"
    
    {
        printf "$DESCRIPTION_TEMPLATE" "$group" "Adblock Rules" "$count" "$(date -u +'%Y-%m-%d %H:%M:%S')"
        sed 's/^/||/' "$domains_file" | sed 's/$/^/'
    } > "$output_file"
}

# 生成 sing-box 规则
generate_singbox_rules() {
    local domains_file="$1"
    local ips_file="$2"
    local output_file="$3"
    local group="$4"
    local total_count="$5"
    
    local temp_file="${TEMP_DIR}/singbox_temp.json"
    
    {
        echo '{'
        echo '  "version": 1,'
        echo '  "rules": ['
        
        local first=true
        
        if [[ -s "$domains_file" ]]; then
            while IFS= read -r domain; do
                if [ "$first" = true ]; then
                    first=false
                else
                    echo ','
                fi
                echo "    {\"domain_suffix\": \"$domain\"}"
            done < "$domains_file"
        fi
        
        if [[ -s "$ips_file" ]]; then
            while IFS= read -r ip; do
                if [ "$first" = true ]; then
                    first=false
                else
                    echo ','
                fi
                echo "    {\"ip_cidr\": \"$ip\"}"
            done < "$ips_file"
        fi
        
        echo
        echo '  ],'
        echo "  \"_meta\": {"
        echo "    \"group\": \"$group\","
        echo "    \"count\": $total_count,"
        echo "    \"generated_at\": \"$(date -u +'%Y-%m-%d %H:%M:%S')\""
        echo '  }'
        echo '}'
    } > "$temp_file"
    
    "${TOOLS_DIR}/${SINGBOX_TOOL}" format -w "$temp_file" > "$output_file"
}

# =============================================================================
# 主函数
# =============================================================================

main() {
    # 设置清理函数
    trap cleanup EXIT
    
    # 检查参数
    if [[ $# -ne 1 ]]; then
        error_exit "使用方法: $0 [组名]"
    fi
    
    local group="$1"
    
    # 检查必需的工具
    check_required_tools
    
    # 创建临时目录
    check_and_create_dir "$TEMP_DIR"
    
    # 下载和处理规则
    log_info "开始处理规则组: $group"
    download_rules "$group" "$TEMP_DIR"
    process_rules "${TEMP_DIR}/${group}.txt" "$REPO_ROOT/dist" "$group"
    
    log_info "规则生成完成"
}

# 执行主函数
main "$@"
