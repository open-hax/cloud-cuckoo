FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim@sha256:531f855bda2c73cd6ef67d56b733b357cea384185b3022bd09f05e002cd144ca
ARG SOURCE_REVISION
RUN test "${#SOURCE_REVISION}" -eq 40 && \
    case "$SOURCE_REVISION" in *[!0-9a-f]*) exit 1 ;; esac
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
LABEL org.opencontainers.image.source="https://github.com/open-hax/cloud-cuckoo" \
      org.opencontainers.image.revision="$SOURCE_REVISION" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.version="0.4.0"
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY LICENSE /usr/share/licenses/cloud-cuckoo/LICENSE
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable
ENV PATH="/app/.venv/bin:$PATH" HOME=/tmp PYTHONDONTWRITEBYTECODE=1
USER 1000:1000
CMD ["knoxx-colab-mcp", "gateway", "--port", "8024"]
