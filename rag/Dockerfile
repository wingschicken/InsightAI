FROM python:3.11

WORKDIR /app

RUN pip install fastapi uvicorn requests qdrant-client sentence-transformers

COPY . .

VOLUME ["/data"]

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]