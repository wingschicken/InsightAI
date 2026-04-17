FROM python:3.12-slim

WORKDIR /app

# Create persistent folder (optional but good practice)
RUN mkdir -p /data

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy code
COPY . .



# Start the RAG API
CMD ["python", "app.py"]