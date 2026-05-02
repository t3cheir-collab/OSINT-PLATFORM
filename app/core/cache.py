import time

CACHE = {}
TTL = 3600  # 1 hour


def get_cached(key):
    item = CACHE.get(key)
    if not item:
        return None

    if time.time() - item["time"] > TTL:
        del CACHE[key]
        return None

    return item["data"]


def set_cache(key, data):
    CACHE[key] = {"data": data, "time": time.time()}