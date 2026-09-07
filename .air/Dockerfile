ARG PLAYWRIGHT_VERSION=1.55.0
FROM mcr.microsoft.com/playwright:v${PLAYWRIGHT_VERSION}-noble

USER root

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        git \
        curl \
        ca-certificates \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.7.20 \
    /uv /uvx /usr/local/bin/

# Use the version required by the project.
RUN uv python install 3.14

RUN corepack enable \
    && corepack prepare pnpm@10.7.0 --activate

WORKDIR /workspace

RUN groupadd --gid 10001 agent \
    && useradd \
        --uid 10001 \
        --gid 10001 \
        --create-home \
        --shell /bin/bash \
        agent

USER agent
