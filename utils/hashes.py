import hashlib

def _stream_hash(path, algo):
    h = algo()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def compute_hashes(path):
    return (
        _stream_hash(path, hashlib.md5),
        _stream_hash(path, hashlib.sha1),
        _stream_hash(path, hashlib.sha256),
    )
