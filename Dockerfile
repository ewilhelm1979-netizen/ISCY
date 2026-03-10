FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG INSTALL_LOCAL_LLM=false

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    python3 \
    python3-venv \
    python3-pip \
    python3-dev \
    build-essential \
    cmake \
    ninja-build \
    pkg-config \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv $VIRTUAL_ENV && pip install --upgrade pip setuptools wheel

WORKDIR /app

COPY requirements.txt requirements-prod.txt requirements-llm.txt ./
RUN pip install -r requirements-prod.txt

RUN if [ "$INSTALL_LOCAL_LLM" = "true" ]; then \
      apt-get update && apt-get install -y --no-install-recommends \
        clang \
        libopenblas-dev \
        g++-14 \
        libstdc++-14-dev \
        && rm -rf /var/lib/apt/lists/* && \
      CC=/usr/bin/clang \
      CXX=/usr/bin/clang++ \
      CMAKE_ARGS="-DGGML_BLAS=ON -DGGML_BLAS_VENDOR=OpenBLAS -DLLAMA_BUILD_TOOLS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_SERVER=OFF" \
      FORCE_CMAKE=1 \
      pip install --no-cache-dir --force-reinstall --no-binary=llama-cpp-python llama-cpp-python && \
      pip install 'huggingface_hub>=0.34.0'; \
    fi

COPY . .

RUN useradd -ms /bin/bash appuser && \
    mkdir -p /app/media /app/staticfiles /app/models && \
    chown -R appuser:appuser /app /opt/venv

USER appuser

EXPOSE 8000

ENTRYPOINT ["/app/docker/entrypoint.sh"]
