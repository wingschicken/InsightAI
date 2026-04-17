import json
import os

CACHE_PATH = "/data/cve_cache.json"


def load_cache():
    if not os.path.exists(CACHE_PATH):
        return {}

    with open(CACHE_PATH, "r") as f:
        return json.load(f)


def save_cache(cache):
    with open(CACHE_PATH, "w") as f:
        json.dump(cache, f)