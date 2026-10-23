.PHONY: build test vet integration
build:
	CGO_ENABLED=0 go build -trimpath -o bin/envoy-ad-auth ./cmd/auth
test:
	go test -race ./...
vet:
	go vet ./...
integration:
	test -n "$(ENVOY_BINARY)"
	go test -race ./integration -run TestEnvoy -v
