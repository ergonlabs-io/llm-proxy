# WP-20 increment 5's conformance fixture: a real go-control-plane ADS
# server, built directly on go-control-plane's own cache/server packages
# (see main.go's top-of-file comment for why that -- and not a
# reimplementation -- is the point).
#
# Pinned versions (README.md repeats these -- keep both in sync):
#   go-control-plane: v0.13.4 (go.mod), the reference implementation this
#     whole fixture exists to test against.
#   golang builder:    1.22-alpine, digest below as of the version pin.
#   runtime base:      gcr.io/distroless/static-debian12:nonroot -- no shell,
#     no package manager; the binary is CGO_ENABLED=0 so it needs nothing else.
FROM golang:1.22-alpine@sha256:1699c10032ca2582ec89a24a1312d986a3f094aed3d5c1147b19880afe40e052 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/xds-conformance-fixture .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=builder /out/xds-conformance-fixture /xds-conformance-fixture
EXPOSE 18000
ENTRYPOINT ["/xds-conformance-fixture"]
