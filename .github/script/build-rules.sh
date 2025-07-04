#!/bin/bash
# =============================================================================
# 规则生成脚本 v3.0
# 作者：ykvhjnn
# 创建日期：2025-07-04
# 最后更新：2025-07-04 12:17:56
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
# 锁文件和进程控制
# =============================================================================
readonly LOCK_FILE="/tmp/build-rules.lock"
readonly PID_FILE="/tmp/build-rules.pid"

# 确保只有一个实例在运行
ensure_single_instance() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid
        pid=$(cat "$PID_FILE" 2>/dev/null || echo "0")
        if kill -0 "$pid" 2>/dev/null; then
            echo "错误: 另一个实例正在运行 (PID: $pid)"
            exit 1
        fi
    fi
    echo "$$" > "$PID_FILE"
    touch "$LOCK_FILE"
}

# 清理锁文件
cleanup_lock() {
    rm -f "$LOCK_FILE" "$PID_FILE"
}

# =============================================================================
# 常量定义
# =============================================================================
readonly SCRIPT_VERSION="3.0"
readonly SCRIPT_DATE="2025-07-04"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly UNIQUE_ID="$(date +%Y%m%d_%H%M%S)_$$"
readonly TEMP_DIR="/tmp/rules_build_${UNIQUE_ID}"
readonly TOOLS_DIR="${TEMP_DIR}/tools"
readonly PYTHON_SCRIPTS_DIR="${SCRIPT_DIR}/python"
readonly LOG_DIR="${REPO_ROOT}/logs"
readonly LOG_FILE="${LOG_DIR}/build-rules_${UNIQUE_ID}.log"

# 工具相关常量
readonly MIHOMO_TOOL="mihomo"
readonly SINGBOX_TOOL="sing-box"

# 输出目录
readonly OUTPUT_DIRS=(
    "txt"
    "mrs"
    "domain"
    "ip"
    "clash"
    "adblock"
    "singbox"
    "srs"
    "logs"
)

# 描述模板
readonly DESCRIPTION_TEMPLATE="# ============================================
# 名称：%s Rules
# 类型：%s
# 规则数量：%d
# 生成时间：%s
# 生成工具：build-rules.sh v${SCRIPT_VERSION}
# 发布地址：https://github.com/ykvhjnn/Rules
# ============================================

"

# =============================================================================
# 日志函数
# =============================================================================
setup_logging() {
    # 创建日志目录
    mkdir -p "$LOG_DIR"
    
    # 确保日志文件存在
    touch "$LOG_FILE"
    
    # 重定向所有输出到日志文件
    exec 1> >(tee -a "$LOG_FILE")
    exec 2> >(tee -a "$LOG_FILE" >&2)
}

log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*"
}

log_warn() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*" >&2
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2
}

log_debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [DEBUG] $*"
    fi
}

# =============================================================================
# 错误处理
# =============================================================================
handle_error() {
    local exit_code=$?
    local line_number=$1
    log_error "在第 ${line_number} 行发生错误，退出码: ${exit_code}"
    cleanup
    exit $exit_code
}

# 设置错误处理
trap 'handle_error ${LINENO}' ERR

# =============================================================================
# 清理函数
# =============================================================================
cleanup() {
    local exit_code=$?
    log_info "开始清理..."
    
    # 清理临时目录
    if [[ -d "${TEMP_DIR}" ]]; then
        rm -rf "${TEMP_DIR}"
        log_info "已清理临时目录: ${TEMP_DIR}"
    fi
    
    # 清理锁文件
    cleanup_lock
    
    # 记录退出状态
    if [[ $exit_code -ne 0 ]]; then
        log_error "脚本执行失败，退出码: ${exit_code}"
    else
        log_info "脚本执行成功"
    fi
}

# 设置清理钩子
trap cleanup EXIT

# =============================================================================
# 辅助函数
# =============================================================================
error_exit() {
    log_error "$1"
    exit 1
}

check_and_create_dir() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir" || error_exit "无法创建目录: $dir"
        log_info "创建目录: $dir"
    fi
}

validate_group() {
    local group="$1"
    if [[ -z "${urls_map[$group]:-}" ]]; then
        error_exit "未找到组: $group"
    fi
}

# =============================================================================
# 依赖检查
# =============================================================================
check_dependencies() {
    local missing_deps=()
    local required_deps=(
        "wget"
        "curl"
        "python3"
        "gzip"
        "tar"
        "awk"
        "sed"
        "tee"
    )

    for dep in "${required_deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        error_exit "缺少必要的依赖: ${missing_deps[*]}"
    fi
}

# =============================================================================
# Python脚本检查
# =============================================================================
check_python_scripts() {
    local group="$1"
    
    # 检查Python脚本目录
    if [[ ! -d "$PYTHON_SCRIPTS_DIR" ]]; then
        error_exit "Python脚本目录不存在: $PYTHON_SCRIPTS_DIR"
    }
    
    # 检查Python版本
    local python_version
    python_version=$(python3 --version 2>&1)
    log_info "使用的Python版本: $python_version"
    
    # 检查所需的Python脚本
    local required_scripts="${py_scripts[$group]}"
    for script in $required_scripts; do
        local script_path="${PYTHON_SCRIPTS_DIR}/${script}"
        if [[ ! -f "$script_path" ]]; then
            error_exit "缺少必要的Python脚本: ${script}"
        fi
        if [[ ! -r "$script_path" ]]; then
            error_exit "Python脚本无法读取: ${script}"
        }
        log_debug "找到Python脚本: ${script}"
    done
}

# =============================================================================
# 目录创建
# =============================================================================
create_directories() {
    log_info "创建必要的目录..."
    
    # 创建临时目录
    check_and_create_dir "${TEMP_DIR}"
    check_and_create_dir "${TOOLS_DIR}"
    
    # 创建输出目录
    for dir in "${OUTPUT_DIRS[@]}"; do
        check_and_create_dir "${REPO_ROOT}/${dir}"
    done
}

# =============================================================================
# 工具下载函数
# =============================================================================

# 下载 Mihomo 工具
download_mihomo() {
    local tool_path="${TOOLS_DIR}/${MIHOMO_TOOL}"
    
    if [[ -f "$tool_path" && -x "$tool_path" ]]; then
        log_info "Mihomo 工具已存在，跳过下载"
        return 0
    fi
    
    log_info "开始下载 Mihomo 工具..."
    
    local tmp_dir="${TEMP_DIR}/mihomo_tmp_$$"
    check_and_create_dir "$tmp_dir"
    
    local version_file="${tmp_dir}/version.txt"
    if ! wget -q "https://github.com/MetaCubeX/mihomo/releases/download/Prerelease-Alpha/version.txt" \
         -O "$version_file"; then
        rm -rf "$tmp_dir"
        error_exit "下载 Mihomo 版本文件失败"
    fi
    
    local version
    version=$(cat "$version_file") || {
        rm -rf "$tmp_dir"
        error_exit "读取 Mihomo 版本文件失败"
    }
    
    local tool_name="mihomo-linux-amd64-${version}"
    local gz_file="${tmp_dir}/${tool_name}.gz"
    
    if ! wget -q "https://github.com/MetaCubeX/mihomo/releases/download/Prerelease-Alpha/${tool_name}.gz" \
         -O "$gz_file"; then
        rm -rf "$tmp_dir"
        error_exit "下载 Mihomo 工具失败"
    fi
    
    if ! gzip -f -d "$gz_file"; then
        rm -rf "$tmp_dir"
        error_exit "解压 Mihomo 工具失败"
    fi
    
    local bin_file="${tmp_dir}/${tool_name}"
    if [[ ! -f "$bin_file" ]]; then
        rm -rf "$tmp_dir"
        error_exit "Mihomo 工具文件不存在"
    fi
    
    chmod +x "$bin_file" || {
        rm -rf "$tmp_dir"
        error_exit "设置 Mihomo 工具执行权限失败"
    }
    
    mv "$bin_file" "$tool_path" || {
        rm -rf "$tmp_dir"
        error_exit "移动 Mihomo 工具失败"
    }
    
    rm -rf "$tmp_dir"
    log_info "Mihomo 工具安装完成"
}

# 下载 sing-box 工具
download_singbox() {
    local tool_path="${TOOLS_DIR}/${SINGBOX_TOOL}"
    
    if [[ -f "$tool_path" && -x "$tool_path" ]]; then
        log_info "sing-box 工具已存在，跳过下载"
        return 0
    fi
    
    log_info "开始下载 sing-box 工具..."
    
    local tmp_dir="${TEMP_DIR}/singbox_tmp_$$"
    check_and_create_dir "$tmp_dir"
    
    local latest_version
    latest_version=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | \
                    grep -Po '"tag_name": "\K.*?(?=")') || {
        rm -rf "$tmp_dir"
        error_exit "获取 sing-box 版本失败"
    }
    
    latest_version="${latest_version#v}"
    local archive_name="sing-box-${latest_version}-linux-amd64.tar.gz"
    local temp_archive="${tmp_dir}/${archive_name}"
    
    if ! wget -q "https://github.com/SagerNet/sing-box/releases/download/v${latest_version}/${archive_name}" \
         -O "$temp_archive"; then
        rm -rf "$tmp_dir"
        error_exit "下载 sing-box 工具失败"
    fi
    
    local current_dir="$PWD"
    cd "$tmp_dir" || {
        rm -rf "$tmp_dir"
        error_exit "切换到临时目录失败"
    }
    
    if ! tar xzf "$archive_name"; then
        cd "$current_dir" || true
        rm -rf "$tmp_dir"
        error_exit "解压 sing-box 工具失败"
    fi
    
    local extracted_dir="sing-box-${latest_version}-linux-amd64"
    if [[ ! -f "${extracted_dir}/sing-box" ]]; then
        cd "$current_dir" || true
        rm -rf "$tmp_dir"
        error_exit "sing-box 工具文件不存在"
    fi
    
    mv "${extracted_dir}/sing-box" "$tool_path" || {
        cd "$current_dir" || true
        rm -rf "$tmp_dir"
        error_exit "移动 sing-box 工具失败"
    }
    
    chmod +x "$tool_path" || {
        cd "$current_dir" || true
        rm -rf "$tmp_dir"
        error_exit "设置 sing-box 工具执行权限失败"
    }
    
    cd "$current_dir" || log_warn "返回原始目录失败"
    rm -rf "$tmp_dir"
    log_info "sing-box 工具安装完成"
}

# =============================================================================
# 规则源配置
# =============================================================================

# 初始化规则源
declare -A urls_map
declare -A ip_urls_map
declare -A py_scripts

init_rule_sources() {
    # 域名规则源
    urls_map["Proxy"]="
https://ruleset.skk.moe/Clash/domainset/speedtest.txt
https://ruleset.skk.moe/Clash/non_ip/my_proxy.txt
https://ruleset.skk.moe/Clash/non_ip/ai.txt
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/GitHub/GitHub.list
https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/proxy.list
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Global/Global_Domain.txt
https://raw.githubusercontent.com/ykvhjnn/Rules/main/Add/Proxy.txt"

    urls_map["Directfix"]="
https://ruleset.skk.moe/Clash/non_ip/microsoft_cdn.txt
https://ruleset.skk.moe/Clash/non_ip/lan.txt
https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/private.list
https://raw.githubusercontent.com/ykvhjnn/Rules/main/Add/Direct.txt"

    urls_map["Ad"]="
https://raw.githubusercontent.com/ghvjjjj/adblockfilters/main/rules/adblockdomain.txt
https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdomainlite.txt
https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-adguard.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.xiaomi.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.oppo-realme.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.vivo.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.tiktok.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.samsung.txt
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.huawei.txt
https://raw.githubusercontent.com/ykvhjnn/Rules/main/Add/Ad.txt"

    urls_map["Direct"]="
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/China/China_Domain.txt"

    # IP规则源
    ip_urls_map["Proxy"]="
https://raw.githubusercontent.com/pmkol/easymosdns/main/rules/gfw_ip_list.txt"

    # Python 脚本配置
    py_scripts["Proxy"]="collect.py remove_domains_Proxy.py clean.py add_domains_Proxy.py"
    py_scripts["Directfix"]="collect.py clean.py"
    py_scripts["Ad"]="collect.py remove_domains_Ad.py clean.py add_domains_Ad.py"
    py_scripts["Direct"]="collect.py clean.py"
}

# =============================================================================
# 规则处理函数
# =============================================================================

# 下载规则
download_rules() {
    local group="$1"
    local domain_file="$2"
    local ip_file="$3"
    
    log_info "开始下载 ${group} 规则..."
    
    local max_concurrent=8
    local active_jobs=0
    declare -A downloaded_files
    
    download_url() {
        local url="$1"
        local output="$2"
        local type="$3"
        
        local temp_file="${TEMP_DIR}/${type}_${RANDOM}.tmp"
        if curl --http2 --compressed --max-time 30 --retry 2 -sSL "$url" > "$temp_file"; then
            log_info "成功下载${type}规则: $url"
            {
                flock -x 200
                cat "$temp_file" >> "$output"
            } 200>>"$output.lock"
            downloaded_files["$url"]=1
        else
            log_warn "下载${type}规则失败: $url"
        fi
        rm -f "$temp_file"
    }
    
    # 并发下载域名规则
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        
        # 等待如果当前作业数达到最大值
        while [[ $active_jobs -ge $max_concurrent ]]; do
            wait -n
            ((active_jobs--))
        done
        
        download_url "$url" "$domain_file" "域名" &
        ((active_jobs++))
        
    done <<< "${urls_map[$group]}"
    
    # 并发下载IP规则
    if [[ -n "${ip_urls_map[$group]:-}" ]]; then
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            
            while [[ $active_jobs -ge $max_concurrent ]]; do
                wait -n
                ((active_jobs--))
            done
            
            download_url "$url" "$ip_file" "IP" &
            ((active_jobs++))
            
        done <<< "${ip_urls_map[$group]}"
    fi
    
    # 等待所有下载完成
    wait
    
    # 删除锁文件
    rm -f "${domain_file}.lock" "${ip_file}.lock"
    
    # 检查是否有规则下载成功
    if [[ ${#downloaded_files[@]} -eq 0 ]]; then
        error_exit "没有成功下载任何规则"
    fi
    
    log_info "规则下载完成"
}

# 处理规则
process_rules() {
    local group="$1"
    local domain_file="$2"
    local ip_file="$3"
    
    log_info "开始处理规则..."
    
    # 转换行尾
    sed -i 's/\r//' "$domain_file" "$ip_file"
    
    # 处理空文件
    if [[ ! -s "$domain_file" && ! -s "$ip_file" ]]; then
        error_exit "域名规则文件和IP规则文件都为空"
    fi
    
    # 执行Python清洗脚本
    local current_dir="$PWD"
    cd "$PYTHON_SCRIPTS_DIR" || error_exit "无法进入Python脚本目录: $PYTHON_SCRIPTS_DIR"
    
    for script in ${py_scripts[$group]}; do
        log_info "执行脚本: $script"
        if ! python3 "$script" "$domain_file"; then
            cd "$current_dir" || true
            error_exit "Python脚本 $script 执行失败"
        fi
    done
    
    cd "$current_dir" || log_warn "返回原始目录失败"
    
    # 统计规则数量
    local domain_count=0
    local ip_count=0
    
    if [[ -f "$domain_file" ]]; then
        domain_count=$(grep -vE '^\s*$|^#' "$domain_file" | wc -l)
    fi
    
    if [[ -f "$ip_file" ]]; then
        ip_count=$(grep -vE '^\s*$|^#' "$ip_file" | wc -l)
    fi
    
    log_info "域名规则数量: $domain_count"
    log_info "IP规则数量: $ip_count"
    
    echo "$domain_count:$ip_count"
}

# 生成规则文件
generate_rules() {
    local group="$1"
    local domain_file="$2"
    local ip_file="$3"
    local counts="$4"
    
    local domain_count="${counts%:*}"
    local ip_count="${counts#*:}"
    
    local mihomo_txt_file="${TEMP_DIR}/${group}_Mihomo.txt"
    local mihomo_mrs_file="${mihomo_txt_file%.txt}.mrs"
    local mihomo_ip_txt_file="${TEMP_DIR}/${group}_Mihomo_ip.txt"
    local mihomo_ip_mrs_file="${mihomo_ip_txt_file%.txt}.mrs"
    local clash_file="${TEMP_DIR}/${group}_clash.txt"
    local adblock_file="${TEMP_DIR}/${group}_adblock.txt"
    local singbox_file="${TEMP_DIR}/${group}_singbox.json"
    local singbox_srs_file="${group}_singbox.srs"
    
    log_info "开始生成规则文件..."
    
    # 生成 Mihomo 规则
    if [[ $domain_count -gt 0 ]]; then
        sed "s/^/+./g" "$domain_file" > "$mihomo_txt_file"
        add_description "$mihomo_txt_file" "$group" "Domain" "$domain_count"
        
        if ! "${TOOLS_DIR}/${MIHOMO_TOOL}" convert-ruleset domain text "$mihomo_txt_file" "$mihomo_mrs_file"; then
            error_exit "Mihomo 工具转换域名规则失败"
        fi
    fi
    
    if [[ -s "$ip_file" ]]; then
        grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$' "$ip_file" > "$mihomo_ip_txt_file"
        add_description "$mihomo_ip_txt_file" "$group" "IP-CIDR" "$ip_count"
        
        if ! "${TOOLS_DIR}/${MIHOMO_TOOL}" convert-ruleset ipcidr text "$mihomo_ip_txt_file" "$mihomo_ip_mrs_file"; then
            error_exit "Mihomo 工具转换IP规则失败"
        fi
    fi
    
    # 生成 Clash 规则
    {
        printf "$DESCRIPTION_TEMPLATE" "$group" "Clash" "$((domain_count + ip_count))" "$(date '+%Y-%m-%d %H:%M:%S')" "${SCRIPT_VERSION}"
        if [[ $domain_count -gt 0 ]]; then
            awk '!/^(\s*$|#)/{gsub(/^[ \t]*/,"");gsub(/[ \t]*$/,""); print "DOMAIN-SUFFIX,"$0}' "$domain_file"
        fi
        if [[ -s "$ip_file" ]]; then
            awk '!/^(\s*$|#)/{gsub(/^[ \t]*/,"");gsub(/[ \t]*$/,""); print "IP-CIDR,"$0}' "$ip_file"
        fi
    } > "$clash_file"
    
    # 生成 Adblock 规则
    if [[ $domain_count -gt 0 ]]; then
        {
            printf "$DESCRIPTION_TEMPLATE" "$group" "Adblock" "$domain_count" "$(date '+%Y-%m-%d %H:%M:%S')" "${SCRIPT_VERSION}"
            awk '!/^(\s*$|#)/{gsub(/^[ \t]*/,"");gsub(/[ \t]*$/,""); print "||"$0"^"}' "$domain_file"
        } > "$adblock_file"
    fi
    
    # 生成 sing-box 规则
    {
        echo "{"
        echo "  \"version\": 3,"
        echo "  \"rules\": ["
        
        # 域名规则
        if [[ $domain_count -gt 0 ]]; then
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
        fi
        
        # IP规则
        if [[ -s "$ip_file" ]]; then
            [[ $domain_count -gt 0 ]] && echo "    ,"
            echo "    {"
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
    
    # 转换为 srs 格式
    if ! "${TOOLS_DIR}/${SINGBOX_TOOL}" rule-set compile "$singbox_file" -o "$singbox_srs_file"; then
        error_exit "sing-box 工具转换失败"
    fi
    
    # 移动文件到输出目录
    if [[ $domain_count -gt 0 ]]; then
        mv "$mihomo_txt_file" "${REPO_ROOT}/txt/"
        mv "$mihomo_mrs_file" "${REPO_ROOT}/mrs/"
        mv "$domain_file" "${REPO_ROOT}/domain/"
        mv "$adblock_file" "${REPO_ROOT}/adblock/"
    fi
    
    if [[ -s "$ip_file" ]]; then
        mv "$mihomo_ip_txt_file" "${REPO_ROOT}/txt/"
        mv "$mihomo_ip_mrs_file" "${REPO_ROOT}/mrs/"
        mv "$ip_file" "${REPO_ROOT}/ip/"
    fi
    
    mv "$clash_file" "${REPO_ROOT}/clash/"
    mv "$singbox_file" "${REPO_ROOT}/singbox/"
    mv "$singbox_srs_file" "${REPO_ROOT}/srs/"
    
    log_info "规则文件生成完成"
}

# =============================================================================
# 主函数
# =============================================================================
main() {
    local start_time
    start_time=$(date +%s)
    
    # 确保只有一个实例在运行
    ensure_single_instance
    
    # 设置日志
    setup_logging
    
    log_info "开始执行规则生成脚本 v${SCRIPT_VERSION}"
    log_info "脚本路径: $SCRIPT_DIR"
    log_info "仓库根目录: $REPO_ROOT"
    
    # 参数检查
    if [[ $# -ne 1 ]]; then
        echo "用法: $0 [组名]"
        echo "可用组:"
        init_rule_sources
        for k in "${!urls_map[@]}"; do
            echo "  - $k"
        done
        cleanup_lock
        exit 1
    fi
    
    local group="$1"
    
    # 初始化规则源
    init_rule_sources
    
    # 检查组是否存在
    validate_group "$group"
    
    # 设置清理钩子
    trap cleanup EXIT
    
    # 检查依赖
    check_dependencies
    
    # 创建目录
    create_directories
    
    # 检查Python脚本
    check_python_scripts "$group"
    
    # 下载工具
    download_mihomo
    download_singbox
    
    # 初始化文件
    local domain_file="${TEMP_DIR}/${group}_domain.txt"
    local ip_file="${TEMP_DIR}/${group}_ip.txt"
    > "$domain_file"
    > "$ip_file"
    
    # 下载规则
    download_rules "$group" "$domain_file" "$ip_file"
    
    # 处理规则
    local counts
    counts=$(process_rules "$group" "$domain_file" "$ip_file")
    
    # 生成规则文件
    generate_rules "$group" "$domain_file" "$ip_file" "$counts"
    
    # 计算执行时间
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_info "[完成] $group 规则生成完毕"
    log_info "执行时间: ${duration} 秒"
    log_info "日志文件: $LOG_FILE"
}

# 执行主程序
main "$@"
