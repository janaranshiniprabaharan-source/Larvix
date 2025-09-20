# core/strings.py (updated)
def _ascii_strings(data_bytes, min_len=4):
    results, current = [], []
    for b in data_bytes:
        if 32 <= b < 127:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                results.append("".join(current))
            current = []
    if len(current) >= min_len:
        results.append("".join(current))
    return results

def _utf16_strings(data_bytes, min_len=4):
    results = []
    # look for UTF-16-LE sequences of printable ASCII (e.g., 'h\x00t\x00t\x00p\x00')
    for offset in (0, 1):
        cur = []
        i = offset
        while i + 1 < len(data_bytes):
            lo = data_bytes[i]
            hi = data_bytes[i+1]
            # printable ASCII in utf16-le: lo in 32..126 and hi == 0
            if hi == 0 and 32 <= lo < 127:
                cur.append(chr(lo))
            else:
                if len(cur) >= min_len:
                    results.append("".join(cur))
                cur = []
            i += 2
        if len(cur) >= min_len:
            results.append("".join(cur))
    return results

def extract_strings_from_bytes(data_bytes, min_len=4):
    ascii_s = _ascii_strings(data_bytes, min_len)
    utf16_s = _utf16_strings(data_bytes, min_len)
    # return deduplicated list with ascii first
    seen = set()
    out = []
    for s in ascii_s + utf16_s:
        if s not in seen:
            out.append(s)
            seen.add(s)
    return out
