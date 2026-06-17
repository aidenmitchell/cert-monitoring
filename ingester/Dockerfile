FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ingester.py .

# Unbuffered stdout so logs surface immediately in `docker compose logs`.
ENV PYTHONUNBUFFERED=1

CMD ["python", "ingester.py"]
