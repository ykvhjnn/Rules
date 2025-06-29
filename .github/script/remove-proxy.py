import sys
import time
import os

# ========== 黑白名单配置 ==========
REMOVE_END = {".jp", ".kr", ".in", ".id", ".th", ".sg", ".my", ".ph", ".vn", ".pk", ".bd", ".lk", ".np", ".mn", ".uz", ".kz", 
              ".kg", ".bt", ".mv", ".mm", ".uk", ".de", ".fr", ".it", ".es", ".ru", ".nl", ".be", ".ch", ".at", ".pl", ".cz", 
              ".se", ".no", ".fi", ".dk", ".gr", ".pt", ".ie", ".hu", ".ro", ".bg", ".sk", ".si", ".lt", ".lv", ".ee", ".is", 
              ".md", ".ua", ".by", ".am", ".ge", ".us", ".ca", ".mx", ".br", ".ar", ".cl", ".co", ".pe", ".ve", ".uy", ".py", 
              ".bo", ".ec", ".cr", ".pa", ".do", ".gt", ".sv", ".hn", ".ni", ".jm", ".cu", ".za", ".eg", ".ng", ".ke", ".gh", 
              ".tz", ".ug", ".dz", ".ma", ".tn", ".ly", ".ci", ".sn", ".zm", ".zw", ".ao", ".mz", ".bw", ".na", ".rw", ".mw", 
              ".sd", ".au", ".nz", ".fj", ".pg", ".sb", ".vu", ".nc", ".pf", ".ws", ".to", ".ki", ".tv", ".nr", ".as", ".sa", 
              ".ae", ".ir", ".il", ".iq", ".tr", ".sy", ".jo", ".lb", ".om", ".qa", ".ye", ".kw", ".bh"}
REMOVE_KEYWORD = {"jsdelivr", "bilibili"}
REMOVE_DOMAIN = {"gh-proxy.com", "outlook.com"}
ADD_DOMAIN = {"jp", "kr", "in", "id", "th", "sg", "my", "ph", "vn", "pk", "bd", "lk", "np", "mn", "uz", "kz", "kg", "bt", "mv", 
              "mm", "uk", "de", "fr", "it", "es", "ru", "nl", "be", "ch", "at", "pl", "cz", "se", "no", "fi", "dk", "gr", "pt", 
              "ie", "hu", "ro", "bg", "sk", "si", "lt", "lv", "ee", "is", "md", "ua", "by", "am", "ge", "us", "ca", "mx", "br", 
              "ar", "cl", "co", "pe", "ve", "uy", "py", "bo", "ec", "cr", "pa", "do", "gt", "sv", "hn", "ni", "jm", "cu", "za", 
              "eg", "ng", "ke", "gh", "tz", "ug", "dz", "ma", "tn", "ly", "ci", "sn", "zm", "zw", "ao", "mz", "bw", "na", "rw", 
              "mw", "sd", "au", "nz", "fj", "pg", "sb", "vu", "nc", "pf", "ws", "to", "ki", "tv", "nr", "as", "sa", "ae", "ir", 
              "il", "iq", "tr", "sy", "jo", "lb", "om", "qa", "ye", "kw", "bh"}

# ========== 优化工具函数 ==========
def log(event: str, major: bool = False):
    """带时间戳的日志函数"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    prefix = "[IMPORTANT] " if major else ""
    print(f"[{timestamp}] {prefix}{event}")

def should_keep(domain: str) -> bool:
    """检查域名是否符合保留条件 (O(1)复杂度)"""
    # 白名单优先判断
    if domain in ADD_DOMAIN:
        return True
        
    # 黑名单检查 (任一条件匹配即移除)
    if domain in REMOVE_DOMAIN:
        return False
    if any(keyword in domain for keyword in REMOVE_KEYWORD):
        return False
    if any(domain.endswith(suffix) for suffix in REMOVE_END):
        return False
        
    return True

# ========== 流式处理核心逻辑 ==========
def process_large_file(input_file: str):
    """处理大文件的核心函数（无去重与排序，白名单插入开头）"""
    log(f"开始处理: {input_file} (文件大小: {os.path.getsize(input_file)/1024/1024:.2f}MB)", major=True)
    output_file = f"{input_file}.processed"
    line_count = 0
    kept_count = 0

    try:
        with open(input_file, "r", encoding="utf8") as fin, \
             open(output_file, "w", encoding="utf8") as fout:

            # 先写入 ADD_DOMAIN（白名单）到文件开头
            for domain in ADD_DOMAIN:
                fout.write(f"{domain}\n")
                kept_count += 1

            # 再流式处理原始文件，按行判断是否保留
            for line in fin:
                line_count += 1
                domain = line.strip()
                if not domain or domain.startswith("#"):
                    continue

                if should_keep(domain):
                    fout.write(f"{domain}\n")
                    kept_count += 1

                # 每10万行输出进度
                if line_count % 100000 == 0:
                    log(f"已处理 {line_count} 行, 保留 {kept_count} 条规则")

    except Exception as e:
        log(f"处理失败: {str(e)}", major=True)
        if os.path.exists(output_file):
            os.remove(output_file)
        sys.exit(1)

    # 原子操作：替换原文件
    os.replace(output_file, input_file)
    log(f"处理完成: 总行数={line_count}, 保留规则={kept_count}", major=True)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <filename>")
        sys.exit(1)

    process_large_file(sys.argv[1])
