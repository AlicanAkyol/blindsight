# Build and run image for the corpus. Pinned digest-free on purpose for now;
# the exact image ID is recorded in build/manifest.json for every build.
FROM --platform=linux/amd64 debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev binutils strace \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
