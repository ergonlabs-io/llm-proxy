# syntax=docker/dockerfile:1
#
# The llm-proxy container image. It holds the release binary and the admin UI
# bundle, nothing else: no shell and no package manager.
#
# The build context is not the source tree. It is a directory that holds the
# extracted release archives, one per architecture:
#
#   dist/linux-amd64/llm-proxy
#   dist/linux-amd64/admin-ui-dist/
#   dist/linux-arm64/llm-proxy
#   dist/linux-arm64/admin-ui-dist/
#
# so the image runs the exact binary the release ships. `.github/workflows/
# release.yml` builds it that way for both platforms, and
# `testing/helm/build-image.sh` does the same for one platform on a laptop.
#
# The binary links glibc dynamically and verifies provider certificates
# against the platform trust store, so the base must carry glibc, libgcc and
# CA certificates: distroless `cc` does. Debian 13 because the release runner
# (ubuntu-24.04) links against glibc 2.39, newer than Debian 12's 2.36.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:83b9b50586253821cf63ffcec87d3d94265a093ad30da232039af962dd8f4edf

ARG TARGETARCH

COPY --chmod=0755 dist/linux-${TARGETARCH}/llm-proxy /usr/local/bin/llm-proxy
COPY dist/linux-${TARGETARCH}/admin-ui-dist /opt/llm-proxy/admin-ui-dist

# The admin server serves the UI from this directory (`LLMPROXY_ADMIN_UI_DIR`).
ENV LLMPROXY_ADMIN_UI_DIR=/opt/llm-proxy/admin-ui-dist

# 65532 is the distroless `nonroot` user. Numeric, so Kubernetes
# `runAsNonRoot` can verify it without reading /etc/passwd.
USER 65532:65532

EXPOSE 8080 9901

ENTRYPOINT ["/usr/local/bin/llm-proxy"]
CMD ["--config", "/etc/llm-proxy/llmproxy.yaml"]
