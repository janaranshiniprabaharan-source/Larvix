def score_indicators(strings, urls, ips, pe_info, entropy, filesize,
                     autorun_found=False, packer_hits_count=0, suspicious_token_count=0, config=None):
    scoring = (config.get("scoring") if config else {}) or {}
    score = 0
    reasons = []

    url_score = scoring.get("url_score", 30)
    ip_score = scoring.get("ip_score", 20)
    if urls:
        score += url_score
        reasons.append(f"Embedded URLs found ({len(urls)})")
    if ips:
        score += ip_score
        reasons.append(f"Embedded IPs found ({len(ips)})")

    # Suspicious API/imports (PE)
    if pe_info.get("is_pe") and pe_info.get("imports"):
        suspicious_apis = []
        SUSPICIOUS_APIS = [
            "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
            "URLDownloadToFile", "WinInet", "WSAStartup", "socket", "connect",
            "send", "recv", "sendto", "recvfrom",
            "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
            "CreateProcess", "WinExec", "ShellExecute", "OpenProcess",
            "CreateFile", "ReadFile", "WriteFile", "SetFileAttributes",
            "RegSetValueEx", "RegCreateKeyEx", "LoadLibrary", "GetProcAddress"
        ]
        for imp in pe_info.get("imports", []):
            for api in SUSPICIOUS_APIS:
                if api.lower() in imp.lower():
                    suspicious_apis.append(imp)
                    break
        if suspicious_apis:
            factor = scoring.get("suspicious_api_factor", 8)
            add = min(30, len(suspicious_apis) * factor)
            score += add
            reasons.append(f"Suspicious PE imports ({len(suspicious_apis)})")
            # also include list in pe_info for the report
            pe_info["suspicious_apis"] = suspicious_apis

    # entropy checks
    he_th = scoring.get("high_entropy_threshold", 7.5)
    he_score = scoring.get("high_entropy_score", 20)
    ee_th = scoring.get("elevated_entropy_threshold", 6.5)
    ee_score = scoring.get("elevated_entropy_score", 8)
    try:
        ent = float(entropy)
    except Exception:
        ent = 0.0
    if ent >= he_th:
        score += he_score
        reasons.append(f"High overall entropy ({ent:.2f}) - possible packing/obfuscation")
    elif ent >= ee_th:
        score += ee_score
        reasons.append(f"Elevated entropy ({ent:.2f})")

    # autorun indicators
    if autorun_found:
        score += scoring.get("autorun_score", 15)
        reasons.append("Autorun / removable-media patterns found")

    # packer signs
    if packer_hits_count:
        score += scoring.get("packer_score", 10)
        reasons.append(f"Possible packer signatures ({packer_hits_count})")

    # small executable bonus (heuristic)
    if filesize < 50_000 and (urls or ips or pe_info.get("is_pe")):
        score += scoring.get("small_exe_bonus", 5)
        reasons.append("Small executable with network indicators (suspicious)")

    # suspicious command tokens
    if suspicious_token_count:
        score += scoring.get("suspicious_token_score", 10)
        reasons.append(f"Suspicious command/shell tokens ({suspicious_token_count})")

    score = max(0, min(100, score))
    return score, reasons

def human_verdict(score, config=None):
    thr = (config.get("thresholds") if config else {}) or {}
    m = thr.get("malicious", 60)
    s = thr.get("suspicious", 30)
    if score >= m:
        return "MALICIOUS (likely worm/malware)"
    elif score >= s:
        return "SUSPICIOUS"
    else:
        return "CLEAN (no strong static indicators found)"
