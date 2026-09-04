# syntax=docker/dockerfile:1

ARG PYTHON_IMAGE=python:3.14-slim-trixie


FROM ghcr.io/astral-sh/uv:latest AS uv


# Python source
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


# Libcdoc
FROM ${PYTHON_IMAGE} AS cdoc

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake git pkg-config \
        libxml2-dev zlib1g-dev libssl-dev \
        libflatbuffers-dev flatbuffers-compiler \
    && rm -rf /var/lib/apt/lists/*

ARG LIBCDOC_REF=master
RUN git clone --depth=1 --branch "${LIBCDOC_REF}" https://github.com/open-eid/libcdoc.git /src

WORKDIR /src
RUN cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/cdoc \
    && cmake --build build --parallel "$(nproc)" \
    && cmake --install build


# Runtime stage
FROM ${PYTHON_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends \
        libgmp10 libmpfr6 libmpc3 \
        libsasl2-2 libldap2 \
        libxml2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"


COPY --from=cdoc /opt/cdoc/bin/cdoc-tool /usr/local/bin/cdoc-tool
COPY --from=cdoc /opt/cdoc/lib/libcdoc.so* /usr/local/lib/
RUN ldconfig

RUN python -c "import gmpy2, ldap" && cdoc-tool 2>&1 | grep -q '^Usage:'

WORKDIR /app
COPY src/ ./src

CMD ["python", "-m", "src.bot"]
