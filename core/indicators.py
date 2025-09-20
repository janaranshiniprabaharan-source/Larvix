import re

URL_REGEX = re.compile(r'(https?://[^\s\'"<>]+)|(www\.[^\s\'"<>]+)', re.IGNORECASE)
IPV4_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
AUTORUN_PATTERNS = [r"autorun\.inf", r"autorun", r"open\=", r"shell\=", r"drive\="]
PACKER_STRINGS = ["UPX", "ASPack", "Themida", "MEW", "PECompact", "FSG", "MPRESS", "UPX!"]
SUSPICIOUS_TOKENS = ["cmd.exe", "powershell", "autorun", "startup", ".vbs", ".bat", "reg add", "schtasks", "net user"]

def detect_urls_ips(strings):
    urls = set()
    ips = set()
    for s in strings:
        for m in URL_REGEX.findall(s):
            url = m[0] if m[0] else m[1]
            urls.add(url)
        for ip in IPV4_REGEX.findall(s):
            ips.add(ip)
    return list(urls), list(ips)

def has_autorun_patterns(strings):
    for s in strings:
        for pat in AUTORUN_PATTERNS:
            if re.search(pat, s, re.IGNORECASE):
                return True
    return False

def packer_hits(strings):
    count = 0
    for s in strings:
        for p in PACKER_STRINGS:
            if p in s:
                count += 1
    return count

def suspicious_tokens_count(strings):
    cnt = 0
    low = [s.lower() for s in strings]
    for token in SUSPICIOUS_TOKENS:
        for s in low:
            if token in s:
                cnt += 1
                break
    return cnt
