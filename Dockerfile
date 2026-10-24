# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: AGPL-3.0-only

# The Tuner container image, for `rhythm-tuner serve` (the HTTP API, PRD
# v0.4). It carries the GoReleaser-built static binary on a distroless
# base, so there is no shell and no package manager in the image. One
# image per architecture; GoReleaser stitches them into a multi-arch
# manifest at ghcr.io/rhythmshahriar/tuner.
#
# The binary is CGO-free and static, so distroless static is enough.
# Non-root (the distroless "nonroot" user, uid 65532). The default
# command starts the service on all interfaces; it refuses to start
# without TUNER_SERVE_TOKEN, so an image run with no token stops at once
# instead of serving unauthenticated.
#
# This Dockerfile is the context GoReleaser's dockers build: it copies the
# already-built rhythm-tuner from the build context, so there is no Go
# toolchain step here. To build it by hand for one architecture:
#   go build -o rhythm-tuner ./cmd/rhythm-tuner
#   docker build -t rhythm-tuner .
FROM gcr.io/distroless/static-debian12:nonroot

COPY rhythm-tuner /usr/local/bin/rhythm-tuner

USER nonroot:nonroot
EXPOSE 8080

# Vulnerability data and the check pack are cached here; mount a volume to
# keep them across runs.
ENV XDG_CACHE_HOME=/home/nonroot/.cache

ENTRYPOINT ["/usr/local/bin/rhythm-tuner"]
CMD ["serve", "--listen", "0.0.0.0:8080"]
