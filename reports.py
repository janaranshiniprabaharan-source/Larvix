import json
from datetime import datetime

def print_report(r):
    print("----- Static Worm Scanner Report -----")
    print(f"File: {r['path']}")
    print(f"Size: {r['filesize']} bytes")
    print(f"MD5: {r['md5']}")
    print(f"SHA1: {r['sha1']}")
    print(f"SHA256: {r['sha256']}")
    print(f"Entropy: {r['entropy']:.3f}")
    print(f"Strings found: {r['num_strings']}")
    print()
    print(f"Embedded URLs: {len(r['urls'])} -> {r['urls'][:5]}")
    print(f"Embedded IPs: {len(r['ips'])} -> {r['ips'][:5]}")
    if r.get('pe_info', {}).get('is_pe'):
        print("PE file detected.")
        print(f"Imported functions: {len(r['pe_info'].get('imports',[]))}")
    print()
    print("Score:", r['score'], "/100")
    print("Verdict:", r['verdict'])
    print("Reasons:")
    for i, reason in enumerate(r.get("reasons", []), 1):
        print(f"  {i}. {reason}")
    print("Report time:", datetime.utcnow().isoformat() + "Z")

def json_report(r, out_path):
    with open(out_path, "w") as f:
        json.dump(r, f, indent=2)
    print(f"JSON report written to {out_path}")
