# syntax=docker/dockerfile:1

ARG PYTHON_IMAGE=python:3.14-slim-trixie


FROM ghcr.io/astral-sh/uv:latest AS uv


# Build stage
FROM ${PYTHON_IMAGE} AS builder

COPY --from=uv /uv /usr/local/bin/uv

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev \
        libgmp-dev libmpfr-dev libmpc-dev \
        libsasl2-dev libldap2-dev \
    && rm -rf /var/lib/apt/lists/*

ENV UV_PROJECT_ENVIRONMENT=/opt/venv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev


# Runtime stage
FROM ${PYTHON_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends \
        libgmp10 libmpfr6 libmpc3 \
        libsasl2-2 libldap2 \
        default-jre-headless \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN python -c "import gmpy2, ldap" && java -version

WORKDIR /app
COPY src/ ./src

CMD ["python", "-m", "src.bot"]
