FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir uv
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN uv pip install --system --no-cache .
ENV PORT=8080 MG_BACKEND=firestore MG_SIGNER=kms MG_STAGE2=vertex
CMD ["sh", "-c", "uvicorn mandateguard.main:app --host 0.0.0.0 --port ${PORT}"]
