FROM python:3.12-slim

WORKDIR /app
COPY seed_ct_index.py .

ENV PYTHONUNBUFFERED=1

# Stdlib only — no pip install needed.
CMD ["python", "seed_ct_index.py"]
