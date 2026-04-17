import hashlib

def generate_id(text: str) -> int:
    return int(hashlib.sha256(text.encode()).hexdigest(), 16) % (10**12)