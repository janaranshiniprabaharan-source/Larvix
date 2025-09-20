from collections import Counter
import math

def shannon_entropy(data_bytes):
    if not data_bytes:
        return 0.0
    counts = Counter(data_bytes)
    length = len(data_bytes)
    ent = 0.0
    for cnt in counts.values():
        p = cnt / length
        ent -= p * math.log2(p)
    return ent
