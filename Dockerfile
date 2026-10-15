# Blast Radius web app + agent. FalkorDB runs separately (docker compose, FalkorDB Cloud, or Fly).
FROM python:3.12-slim
RUN pip install --no-cache-dir "uv>=0.8,<0.9"
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PYTHONUNBUFFERED=1
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
COPY queries ./queries
COPY data/company.json ./data/company.json
COPY data/lockfiles ./data/lockfiles
COPY data/scenarios ./data/scenarios
COPY data/osv ./data/osv
RUN uv sync --frozen --no-dev
ENV PATH="/app/.venv/bin:$PATH" PORT=8000
EXPOSE 8000
CMD ["sh", "-c", "python -m blast_radius.seed && exec uvicorn blast_radius.web:app --host 0.0.0.0 --port ${PORT}"]
