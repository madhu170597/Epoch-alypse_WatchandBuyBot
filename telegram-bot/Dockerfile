FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
RUN pip install --no-cache-dir \
    "fastapi==0.120.2" "uvicorn==0.38.0" "httpx==0.28.1" \
    "pydantic==2.12.5" "pydantic-settings==2.12.0" \
    "google-auth==2.41.1" "cryptography==46.0.5"

COPY app ./app

ENV PORT=8080
CMD exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT}
