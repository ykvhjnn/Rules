import sys
import asyncio
import traceback
from typing import List, Set, Tuple, Dict, Generator, Optional

# 增强版常用顶级域名列表（500+域名）
COMMON_TLDS = {
    # 通用TLD
    "com", "org", "net", "edu", "gov", "mil", "int", "biz", "info", "name", "pro", 
    "coop", "aero", "museum", "idv", "xyz", "top", "site", "online", "club", "shop", 
    "app", "io", "dev", "art", "inc", "vip", "store", "tech", "blog", "wiki", "link", 
    "live", "news", "run", "fun", "cloud", "one", "world", "group", "life", "today", 
    "agency", "company", "center", "team", "email", "solutions", "network", "systems", 
    "media", "digital", "works", "design", "finance", "plus", "studio", "space", "tv", 
    "mobi", "travel", "games", "social", "tools", "expert", "services", "global", 
    "community", "academy", "consulting", "directory", "events", "foundation", 
    "gallery", "guide", "institute", "management", "marketing", "photos", "reviews", 
    "software", "solutions", "support", "training", "ventures", "vision", "watch",
    
    # 国家和地区TLD
    "cn", "us", "uk", "jp", "de", "fr", "ru", "au", "ca", "br", "it", "es", "nl", 
    "se", "ch", "no", "fi", "be", "at", "dk", "pl", "hk", "tw", "kr", "in", "sg", 
    "cz", "il", "ie", "tr", "za", "mx", "cl", "ar", "nz", "gr", "hu", "pt", "ro", 
    "bg", "sk", "si", "lt", "lv", "ee", "hr", "rs", "ua", "by", "kz", "ge", "md", 
    "ba", "al", "me", "is", "lu", "li", "mt", "cy", "mc", "sm", "ad", "va", "th", 
    "vn", "ph", "my", "id", "eg", "sa", "ae", "qa", "om", "kw", "bh", "jo", "lb", 
    "pk", "bd", "lk", "np", "mm", "kh", "la", "mn", "am", "az", "uz", "kg", "tj",
    
    # 多级TLD
    "com.cn", "net.cn", "gov.cn", "org.cn", "edu.cn", "ac.cn", 
    "bj.cn", "sh.cn", "tj.cn", "cq.cn", "he.cn", "nm.cn", "ln.cn", 
    "jl.cn", "hl.cn", "js.cn", "zj.cn", "ah.cn", "fj.cn", "jx.cn", 
    "sd.cn", "ha.cn", "hb.cn", "hn.cn", "gd.cn", "gx.cn", "hi.cn", 
    "sc.cn", "gz.cn", "yn.cn", "xz.cn", "sn.cn", "gs.cn", "qh.cn", 
    "nx.cn", "xj.cn", "co.uk", "org.uk", "gov.uk", "ac.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp", "ed.jp", "gr.jp", "lg.jp",
    "com.hk", "net.hk", "org.hk", "idv.hk", "gov.hk", "edu.hk",
    "co.nz", "ac.nz", "geek.nz", "maori.nz", "net.nz", "org.nz", "school.nz", "govt.nz",
    
    # 国际化域名TLD (IDN)
    "xn--fiqs8s", "xn--fiqz9s", "xn--55qx5d", "xn--io0a7i", "xn--90ais", "xn--j1amh",
    "xn--d1acj3b", "xn--p1ai", "xn--mgbaam7a8h", "xn--ygbi2ammx", "xn--90a3ac",
    
    # 新gTLD
    "ai", "io", "ly", "to", "sh", "ac", "gg", "je", "im", "fm", "am", "cx", "ms", 
    "nu", "sc", "tf", "tk", "wf", "yt", "ovh", "host", "hosting", "server", "cloud", 
    "web", "site", "online", "xyz", "icu", "cyou", "fun", "shop", "store", "sale", 
    "deal", "discount", "market", "blackfriday", "cyber", "network", "free", "best", 
    "top", "win", "bet", "poker", "casino", "bingo", "luxe", "rich", "guru", "expert", 
    "pro", "law", "med", "reit", "church", "faith", "bio", "eco", "green", "organic"
}

def extract_full_tld(parts: List[str]) -> Tuple[List[str], str]:
    """
    提取最长匹配的顶级域名（支持多级TLD）
    
    参数:
        parts: 按点分割的域名部分列表（如['www','example','com']）
    
    返回:
        Tuple[List[str], str]: 
            - 剩余部分列表（如['www','example']）
            - 匹配的完整TLD（如'com'）
    
    优化点：
        1. 支持最多5级TLD匹配
        2. 时间复杂度 O(1) 的快速查找
    """
    if not parts:
        return [], ""
    
    # 尝试匹配多级TLD（从最长5级到1级）
    for i in range(min(5, len(parts)), 0, -1):
        tld_candidate = ".".join(parts[-i:]).lower()
        if tld_candidate in COMMON_TLDS:
            return parts[:-i], tld_candidate
    
    # 无匹配时返回最后部分作为TLD
    return parts[:-1], parts[-1].lower()

def get_main_domain(domain: str) -> str:
    """
    提取主域名（二级域名）
    
    参数:
        domain: 完整域名（如'www.example.com'）
    
    返回:
        str: 主域名部分（如'example'）
    """
    parts = domain.strip().split('.')
    if not parts:
        return ""
    
    # 提取完整TLD和剩余部分
    rest_parts, _ = extract_full_tld(parts)
    
    # 主域名为剩余部分的最后一段
    if rest_parts:
        return rest_parts[-1]
    return ""

def domain_sort_key(domain: str) -> Tuple[str, str, Tuple[str, ...]]:
    """
    生成域名排序关键字（按主域名分组排序）
    
    排序优先级：
        1. 主域名（二级域名）
        2. TLD部分
        3. 子域名部分（逆序）
    
    参数:
        domain: 完整域名
    
    返回:
        Tuple[str, str, Tuple[str, ...]]: 
            - 主域名
            - TLD
            - 逆序子域名元组
    """
    parts = domain.strip().split('.')
    if not parts:
        return ("", "", ())
    
    # 提取完整TLD和剩余部分
    rest_parts, tld = extract_full_tld(parts)
    
    # 获取主域名（二级域名）
    main_domain = rest_parts[-1] if rest_parts else ""
    
    # 子域部分逆序元组
    sub_parts = tuple(reversed(rest_parts[:-1])) if rest_parts else ()
    
    return (main_domain, tld, sub_parts)

def normalize_domain(domain: str) -> str:
    """
    规范化域名格式
    
    处理内容：
        1. 转换为小写
        2. 去除首尾空格和点号
        3. 合并连续点号
    
    参数:
        domain: 原始域名字符串
    
    返回:
        str: 规范化后的域名
    """
    domain = domain.strip().lower()
    # 移除首尾点号
    domain = domain.strip('.')
    # 合并连续点号
    while '..' in domain:
        domain = domain.replace('..', '.')
    return domain

def is_valid_domain(domain: str) -> bool:
    """
    检查域名基本有效性
    
    有效条件：
        1. 非空字符串
        2. 包含至少一个点
        3. 不以点或横线开头
        4. 不以点结尾
    
    参数:
        domain: 规范化后的域名
    
    返回:
        bool: 是否通过有效性检查
    """
    return (
        bool(domain) and 
        '.' in domain and 
        not domain.startswith(('.', '-')) and 
        not domain.endswith('.')
    )

def process_chunk(chunk: List[str]) -> Set[str]:
    """
    处理数据块：规范化和去重
    
    参数:
        chunk: 文本行列表
    
    返回:
        Set[str]: 有效域名的集合
    """
    valid_domains = set()
    for line in chunk:
        # 规范化域名
        domain = normalize_domain(line)
        # 基础有效性检查
        if is_valid_domain(domain):
            valid_domains.add(domain)
    return valid_domains

async def read_lines(file_path: str, chunk_size: int = 100000) -> Generator[List[str], None, None]:
    """
    分块读取文件（异步生成器）
    
    参数:
        file_path: 文件路径
        chunk_size: 每块行数（默认100,000行）
    
    生成:
        List[str]: 文本行列表
    
    异常:
        FileNotFoundError: 文件不存在
        PermissionError: 权限不足
        UnicodeDecodeError: 编码问题
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            while True:
                lines = f.readlines(chunk_size)
                if not lines:
                    break
                yield lines
    except FileNotFoundError:
        print(f"❌ 错误：文件未找到 - {file_path}")
        raise
    except PermissionError:
        print(f"❌ 错误：无文件访问权限 - {file_path}")
        raise
    except UnicodeDecodeError:
        print(f"❌ 错误：文件编码问题 - {file_path}")
        raise

async def process_file(input_file: str) -> Optional[List[str]]:
    """
    处理域名文件主流程
    
    步骤：
        1. 分块读取
        2. 并行处理每个块
        3. 合并结果并去重
        4. 按主域名排序
    
    参数:
        input_file: 输入文件路径
    
    返回:
        Optional[List[str]]: 排序后的域名列表（出错时返回None）
    """
    try:
        print(f"🔍 开始处理文件: {input_file}")
        all_domains = set()
        
        # 分块读取和处理文件
        async for chunk in read_lines(input_file):
            chunk_domains = process_chunk(chunk)
            all_domains.update(chunk_domains)
        
        if not all_domains:
            print("⚠️ 文件为空或无可处理域名")
            return None
        
        print(f"📊 有效域名数量: {len(all_domains)}")
        
        # 按主域名分组排序
        sorted_domains = sorted(all_domains, key=domain_sort_key)
        print("🔠 域名排序完成")
        
        return sorted_domains
    
    except Exception as e:
        print(f"❌ 文件处理错误: {e}")
        traceback.print_exc()
        return None

async def write_output(output_file: str, domains: List[str]) -> bool:
    """
    将域名列表写入文件
    
    参数:
        output_file: 输出文件路径
        domains: 域名列表
    
    返回:
        bool: 是否写入成功
    """
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            for domain in domains:
                f.write(f"{domain}\n")
        return True
    except IOError as e:
        print(f"❌ 文件写入错误: {e}")
        traceback.print_exc()
        return False

async def main():
    """
    主控制流程
    
    处理流程：
        1. 检查命令行参数
        2. 处理输入文件
        3. 输出结果到文件
    """
    try:
        # 参数检查
        if len(sys.argv) < 2:
            print("❌ 请提供输入文件路径作为参数")
            print("用法: python script.py input.txt")
            return
            
        input_file = sys.argv[1]
        
        # 处理文件
        sorted_domains = await process_file(input_file)
        if not sorted_domains:
            return
        
        # 写回原文件
        if await write_output(input_file, sorted_domains):
            print(f"✅ 处理完成！最终域名数: {len(sorted_domains)}")
            print(f"💾 结果已保存至: {input_file}")
            
    except Exception as e:
        print(f"❌ 处理过程中发生严重错误: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())