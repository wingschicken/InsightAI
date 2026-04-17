from qdrant_client import QdrantClient
from qdrant_client.models import VectorParams, Distance, PointStruct
from embedder import embed
from utils import generate_id

import os

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
COLLECTION = "cves"

client = QdrantClient(url=QDRANT_URL)


def ensure_collection(dim):
    collections = client.get_collections().collections
    if COLLECTION not in [c.name for c in collections]:
        client.create_collection(
            collection_name=COLLECTION,
            vectors_config=VectorParams(size=dim, distance=Distance.COSINE)
        )


def get_existing(ids):
    existing = set()
    offset = None

    while True:
        points, offset = client.scroll(
            collection_name=COLLECTION,
            limit=1000,
            offset=offset
        )
        for p in points:
            existing.add(p.id)
        if offset is None:
            break

    return existing.intersection(set(ids))


def run_pipeline(cve_objects):
    if not cve_objects:
        return {"status": "no data"}

    texts = [c["text"] for c in cve_objects]
    ids = [generate_id(t) for t in texts]

    existing = get_existing(ids)
    new = [cve_objects[i] for i in range(len(ids)) if ids[i] not in existing]

    if not new:
        return {"status": "no new data"}

    texts = [c["text"] for c in new]
    vectors = embed(texts)

    ensure_collection(len(vectors[0]))

    points = []
    for i, c in enumerate(new):
        points.append(PointStruct(
            id=generate_id(c["text"]),
            vector=vectors[i],
            payload=c
        ))

    client.upsert(collection_name=COLLECTION, points=points)

    return {"status": "ok", "inserted": len(points)}