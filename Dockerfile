FROM golang:1.27.3-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /envoy-ad-auth ./cmd/auth

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /envoy-ad-auth /envoy-ad-auth
USER 65532:65532
ENTRYPOINT ["/envoy-ad-auth"]
CMD ["-config", "/etc/envoy-ad-auth/config.yaml"]
