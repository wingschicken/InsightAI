import json
import os
import logging
import requests
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

PORT = int(os.getenv("RAG_PORT", os.getenv("PORT", 8080)))
QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL")
MODEL = os.getenv("MODEL", "gemma3:27b")

qdrant_client = None

def get_embeddings(texts):
    """Get embeddings from OpenAI API."""
    url = f"{OPENAI_BASE_URL}/embeddings"
    headers = {"Authorization": f"Bearer {OPENAI_API_KEY}"}
    payload = {
        "model": "bge-m3",
        "input": texts if isinstance(texts, list) else [texts]
    }
    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    data = response.json()
    embeddings = [item["embedding"] for item in data["data"]]
    return embeddings[0] if isinstance(texts, str) else embeddings

def get_answer_from_llm(context, question):
    """Get answer from LLM."""
    url = f"{OPENAI_BASE_URL}/chat/completions"
    headers = {"Authorization": f"Bearer {OPENAI_API_KEY}"}
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": f"You are a security expert. Use the following context to answer questions:\n\n{context}"},
            {"role": "user", "content": question}
        ]
    }
    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"]

def ingest_data():
    """Load data from datamy.json and ingest into Qdrant."""
    logger.info("Ingesting data...")
    
    with open("/app/datamy.json", "r") as f:
        data = json.load(f)
    
    points = []
    for idx, item in enumerate(data):
        port = item["port"]
        service = item["service"]
        vulnerabilities = item.get("vulnerabilities", [])
        
        vuln_text = ", ".join(vulnerabilities)
        text = f"Port {port} ({service}): vulnerabilities: {vuln_text}"
        
        try:
            embedding = get_embeddings(text)
        except Exception as e:
            logger.error(f"Error getting embedding for port {port}: {e}")
            continue
        
        point = PointStruct(
            id=idx,
            vector=embedding,
            payload={
                "port": port,
                "service": service,
                "vulnerabilities": vulnerabilities,
                "text": text
            }
        )
        points.append(point)
    
    qdrant_client.upsert(
        collection_name="ports",
        points=points
    )
    logger.info(f"Ingested {len(points)} records")

async def startup():
    global qdrant_client
    
    qdrant_client = QdrantClient(url=QDRANT_URL)
    logger.info(f"Connected to Qdrant at {QDRANT_URL}")
    
    try:
        collection_info = qdrant_client.get_collection("ports")
        logger.info(f"Collection 'ports' exists with {collection_info.points_count} points")
        
        if collection_info.points_count == 0:
            logger.info("Collection is empty, ingesting data...")
            ingest_data()
        else:
            logger.info("Skipping ingestion (already exists)")
    except Exception as e:
        logger.info(f"Collection 'ports' does not exist, creating and ingesting...")
        
        qdrant_client.create_collection(
            collection_name="ports",
            vectors_config=VectorParams(size=1024, distance=Distance.COSINE)
        )
        
        ingest_data()

@asynccontextmanager
async def lifespan(app: FastAPI):
    await startup()
    yield

app = FastAPI(lifespan=lifespan)

class AskRequest(BaseModel):
    question: str

class AskResponse(BaseModel):
    answer: str
    sources: list

@app.get("/")
async def health():
    """Health check."""
    return {"status": "ok"}

@app.post("/ask", response_model=AskResponse)
async def ask(request: AskRequest):
    """Answer a question using RAG."""
    try:
        question_embedding = get_embeddings(request.question)
        
        search_results = qdrant_client.search(
            collection_name="ports",
            query_vector=question_embedding,
            limit=3
        )
        
        context = ""
        sources = []
        for result in search_results:
            payload = result.payload
            context += f"- {payload['text']}\n"
            sources.append({
                "port": payload["port"],
                "service": payload["service"]
            })
        
        answer = get_answer_from_llm(context, request.question)
        
        return AskResponse(answer=answer, sources=sources)
    
    except Exception as e:
        logger.error(f"Error in /ask: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT)
