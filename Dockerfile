FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY config/ ./config/
COPY services/ ./services/

RUN mkdir ./databases

CMD ["python", "main.py"]
