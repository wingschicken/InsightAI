FROM python:3.11-slim

WORKDIR /app

RUN mkdir -p /data

COPY datamy.json /app/datamy.json
COPY requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -r requirements.txt

COPY main.py /app/main.py

CMD ["python", "main.py"]
