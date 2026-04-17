import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import chromadb
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

import re
load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "").rstrip("/")

CHAT_MODEL = os.getenv("CHAT_MODEL", "gemma3:27b")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "bge-m3")

KNOWLEDGE_FILE = os.getenv("KNOWLEDGE_FILE", "knowledge.md")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "vuln_knowledge")

CHROMA_HOST = os.getenv("CHROMA_HOST", "ragbase")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))

if not OPENAI_API_KEY or not OPENAI_BASE_URL:
    raise RuntimeError("Missing OPENAI_API_KEY or OPENAI_BASE_URL")

app = FastAPI(title="Simple RAG Starter")

client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
collection = client.get_or_create_collection(name=COLLECTION_NAME)


class IngestResponse(BaseModel):
    status: str
    chunks_added: int


class RetrieveRequest(BaseModel):
    query: str
    top_k: int = 4


class RetrieveResponse(BaseModel):
    query: str
    results: List[Dict[str, Any]]


class ChatRequest(BaseModel):
    query: str
    top_k: int = 4


class ChatResponse(BaseModel):
    answer: str
    context: List[Dict[str, Any]]


import re
from typing import List

def chunk_text(text: str) -> List[str]:
    text = text.strip()
    if not text:
        return []

    parts = re.split(r'(?=Port\s+\d+\s*-)', text)
    chunks = [part.strip() for part in parts if part.strip()]
    return chunks



def clean_markdown(text: str) -> str:
    text = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"^#+\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"\*\*|\*|__|_", "", text)
    text = re.sub(r"`+", "", text)
    text = re.sub(r"^\s*[-*]\s+", "", text, flags=re.MULTILINE)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()

async def embed_texts(texts: List[str]) -> List[List[float]]:
    url = f"{OPENAI_BASE_URL}/embeddings"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": EMBEDDING_MODEL,
        "input": texts,
    }

    async with httpx.AsyncClient(timeout=60) as http:
        response = await http.post(url, headers=headers, json=payload)

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail=f"Embedding error: {response.text}")

    data = response.json()
    return [item["embedding"] for item in data["data"]]


async def chat_completion(prompt: str) -> str:
    url = f"{OPENAI_BASE_URL}/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": CHAT_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You answer questions using the provided cybersecurity context. "
                    "Be accurate, concise, and practical. "
                    "If the context is insufficient, say that clearly."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }

    async with httpx.AsyncClient(timeout=90) as http:
        response = await http.post(url, headers=headers, json=payload)

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail=f"Chat error: {response.text}")

    data = response.json()
    return data["choices"][0]["message"]["content"].strip()


def build_prompt(query: str, docs: List[Dict[str, Any]]) -> str:
    context_blocks = []
    for i, doc in enumerate(docs, start=1):
        context_blocks.append(
            f"[Context {i}]\n"
            f"{doc['text']}\n"
        )

    context_text = "\n\n".join(context_blocks)

    return (
        "Use the following context to answer the question.\n"
        "Answer only from the context when possible.\n\n"
        f"{context_text}\n\n"
        f"Question: {query}"
    )


@app.get("/ping")
async def ping() -> Dict[str, str]:
    return {"status": "ok"}

@app.get("/")
async def root() -> Dict[str, str]:
    return {"status": "ok", "service": "rag"}

@app.post("/ingest-file", response_model=IngestResponse)
async def ingest_file() -> IngestResponse:
    file_path = Path(KNOWLEDGE_FILE)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"{KNOWLEDGE_FILE} not found")

    raw_text = file_path.read_text(encoding="utf-8")
    text = clean_markdown(raw_text)
    chunks = chunk_text(text)

    if not chunks:
        raise HTTPException(status_code=400, detail="Knowledge file is empty")

    embeddings = await embed_texts(chunks)

    ids = [str(uuid.uuid4()) for _ in chunks]
    metadatas = [
        {
            "source": str(file_path),
            "chunk_index": i,
            "ingested_at": datetime.utcnow().isoformat(),
            "type": "knowledge",
        }
        for i in range(len(chunks))
    ]

    collection.add(
        ids=ids,
        documents=chunks,
        embeddings=embeddings,
        metadatas=metadatas,
    )

    return IngestResponse(status="ok", chunks_added=len(chunks))


@app.post("/retrieve", response_model=RetrieveResponse)
async def retrieve(req: RetrieveRequest) -> RetrieveResponse:
    query_embedding = (await embed_texts([req.query]))[0]

    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=req.top_k,
        include=["documents", "metadatas", "distances"],
    )

    docs = results.get("documents", [[]])[0]
    metas = results.get("metadatas", [[]])[0]
    distances = results.get("distances", [[]])[0]

    output = []
    for doc, meta, distance in zip(docs, metas, distances):
        output.append(
            {
                "text": doc,
                "metadata": meta,
                "distance": distance,
            }
        )

    return RetrieveResponse(query=req.query, results=output)


@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest) -> ChatResponse:
    query_embedding = (await embed_texts([req.query]))[0]

    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=req.top_k,
        include=["documents", "metadatas", "distances"],
    )

    docs = results.get("documents", [[]])[0]
    metas = results.get("metadatas", [[]])[0]
    distances = results.get("distances", [[]])[0]

    context = []
    for doc, meta, distance in zip(docs, metas, distances):
        context.append(
            {
                "text": doc,
                "metadata": meta,
                "distance": distance,
            }
        )

    if not context:
        raise HTTPException(status_code=404, detail="No context found in database")

    prompt = build_prompt(req.query, context)
    answer = await chat_completion(prompt)

    return ChatResponse(answer=answer, context=context)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8001"))
    uvicorn.run("app:app", host="0.0.0.0", port=port)