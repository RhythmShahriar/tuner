# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: AGPL-3.0-only

# The Tuner container image, for `rhythm-tuner serve` (the HTTP API, PRD
# v0.4). It carries the release's static binary on a distroless base, so
# there is no shell and no package manager in the image. One multi-arch
# image (linux/amd64 and linux/arm64) at ghcr.io/rhythmshahriar/tuner.
#
# The binary is CGO-free and static, so distroless static is enough.
# Non-root (the distroless "nonroot" user, uid 65532). The default
# command starts the service on all interfaces; it refuses to start
# without TUNER_SERVE_TOKEN, so an image run with no token stops at once
# instead of serving unauthenticated.
#
# There is no Go toolchain step: the context holds the already-built
# binary at <os>/<arch>/rhythm-tuner and buildx picks the one for the
# platform it builds. On a release the image job in
# .github/workflows/release.yml fills the context from the signed release
# archives. To build it by hand:
#   make image-context
#   docker buildx build --platform linux/amd64 --load -t rhythm-tuner dist/image
# Pinned by digest (the same base as Echo's image); Dependabot's docker
# ecosystem moves the tag and digest together.
FROM gcr.io/distroless/static:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99

ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/rhythm-tuner /usr/local/bin/rhythm-tuner

USER nonroot:nonroot
EXPOSE 8080

# Vulnerability data and the check pack are cached here; mount a volume to
# keep them across runs.
ENV XDG_CACHE_HOME=/home/nonroot/.cache

ENTRYPOINT ["/usr/local/bin/rhythm-tuner"]
CMD ["serve", "--listen", "0.0.0.0:8080"]
