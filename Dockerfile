# syntax=docker/dockerfile:1
#
# MCP-GuardBench image: API, dashboard, and CLI/test-runner share this one image.
# Local security lab only. It contains synthetic fixtures and no secrets.

FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
# Only what packaging needs, so source edits do not bust the dependency layer unnecessarily.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install ".[dashboard]"

FROM python:3.12-slim AS runtime
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    GUARDBENCH_LOG_JSON=true
# A fixed, unprivileged user. No shell login, no home directory of its own.
RUN groupadd --system --gid 10001 guardbench \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin guardbench
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY alembic.ini ./
COPY migrations ./migrations
COPY test_cases ./test_cases
# Reports are written here (bind-mounted by docker-compose); the rest of the image is read-only in use.
RUN mkdir -p /app/reports && chown -R guardbench:guardbench /app/reports
USER 10001:10001
EXPOSE 8000 8501
# Health checks are defined per service in docker-compose.yml (the API and dashboard listen on
# different ports, and the migrate/test-runner containers are one-shot).
ENTRYPOINT ["guardbench"]
CMD ["serve", "--host", "0.0.0.0"]
