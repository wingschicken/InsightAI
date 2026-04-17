import requests
import random

RAG_URL = "http://localhost:8080"

# some real CVEs (random pick)
CVE_POOL = [
    "CVE-2024-3094",
    "CVE-2023-44487",
    "CVE-2022-22965",
    "CVE-2021-44228",
    "CVE-2020-1472",
    "CVE-2019-0708"
]

selected = random.sample(CVE_POOL, 3)

print("Sending CVEs:", selected)

# 1. ingest
r = requests.post(
    f"{RAG_URL}/ingest-cves",
    json={"cves": selected}
)
print("Ingest:", r.json())

# 2. run pipeline
r = requests.post(f"{RAG_URL}/run-pipeline")
print("Pipeline:", r.json())

# 3. fetch them back
r = requests.post(
    f"{RAG_URL}/get-cves",
    json={"cves": selected}
)
print("Fetched:", r.json())