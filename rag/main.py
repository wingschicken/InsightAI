from fastapi import FastAPI
from pydantic import BaseModel
from typing import List

from cve_fetcher import fetch_cve
from pipeline import run_pipeline
from cache import load_cache, save_cache

app = FastAPI()

cve_queue = []


class CVERequest(BaseModel):
    cves: List[str]


# ---- ingest CVEs ----
@app.post("/ingest-cves")
def ingest(req: CVERequest):
    global cve_queue

    added = 0
    for cve in req.cves:
        if cve not in cve_queue:
            cve_queue.append(cve)
            added += 1

    return {"status": "queued", "added": added}


# ---- NEW: get CVEs (FETCH + CACHE) ----
@app.post("/get-cves")
def get_cves(req: CVERequest):
    cache = load_cache()

    results = []
    missing = []

    # check cache first
    for cve_id in req.cves:
        if cve_id in cache:
            results.append(cache[cve_id])
        else:
            missing.append(cve_id)

    # fetch missing
    for cve_id in missing:
        data = fetch_cve(cve_id)
        if data:
            cache[cve_id] = data
            results.append(data)

    save_cache(cache)

    return {
        "count": len(results),
        "cves": results
    }


# ---- run pipeline ----
@app.post("/run-pipeline")
def run():
    global cve_queue

    if not cve_queue:
        return {"status": "empty"}

    cache = load_cache()

    cve_objects = []

    for cve_id in cve_queue:
        # use cache first
        if cve_id in cache:
            cve_objects.append(cache[cve_id])
        else:
            data = fetch_cve(cve_id)
            if data:
                cache[cve_id] = data
                cve_objects.append(data)

    save_cache(cache)

    result = run_pipeline(cve_objects)

    if result.get("status") == "ok":
        cve_queue = []

    return result


@app.get("/")
def root():
    return {"status": "rag running"}