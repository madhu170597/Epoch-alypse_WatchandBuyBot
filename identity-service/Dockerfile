FROM python:3.12-slim

WORKDIR /app

# Install deps first for layer caching.
COPY pyproject.toml ./
RUN pip install --no-cache-dir \
    "fastapi==0.120.2" "uvicorn==0.38.0" "firebase-admin==7.1.0" \
    "webauthn==2.7.0" "pydantic==2.12.5" "pydantic-settings==2.12.0"

COPY app ./app

# Cloud Run provides $PORT.
ENV PORT=8080
CMD exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT}
