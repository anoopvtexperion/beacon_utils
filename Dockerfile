# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:alpine AS builder
WORKDIR /build
COPY go.mod main.go ./
RUN go build -ldflags="-s -w" -o beacontest .

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:latest
WORKDIR /app

COPY --from=builder /build/beacontest .
COPY index.html .
COPY provision/ provision/
COPY validate/ validate/
COPY read-eid/ read-eid/

# Default empty profiles store (overridden by volume mount in production)
RUN echo '[]' > profiles.json

VOLUME ["/app"]
EXPOSE 8765
CMD ["./beacontest"]
