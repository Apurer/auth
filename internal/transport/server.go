// Package transport enforces the Envoy-to-auth-service trust boundary.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Apurer/auth/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func Server(c *config.Config) (*grpc.Server, error) {
	opts := []grpc.ServerOption{grpc.MaxRecvMsgSize(128 * 1024), grpc.MaxSendMsgSize(1024 * 1024), grpc.MaxConcurrentStreams(uint32(c.Limits.MaxConcurrent))}
	if !strings.HasPrefix(c.Listen, "unix:") {
		cert, err := tls.LoadX509KeyPair(c.TLS.Certificate, c.TLS.PrivateKey)
		if err != nil {
			return nil, errors.New("cannot load server certificate and key")
		}
		pem, err := os.ReadFile(c.TLS.ClientCA)
		if err != nil {
			return nil, errors.New("cannot read client CA")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid client CA")
		}
		allowed := slices.Clone(c.TLS.AllowedClientSANs)
		tc := &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12,
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
					return errors.New("unauthorized Envoy peer")
				}
				leaf := state.PeerCertificates[0]
				for _, name := range leaf.DNSNames {
					if slices.Contains(allowed, name) {
						return nil
					}
				}
				for _, uri := range leaf.URIs {
					if slices.Contains(allowed, uri.String()) {
						return nil
					}
				}
				return errors.New("unauthorized Envoy peer")
			}}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tc)))
	}
	return grpc.NewServer(opts...), nil
}

func Listen(address string) (net.Listener, error) {
	if strings.HasPrefix(address, "unix:") {
		path := strings.TrimPrefix(address, "unix:")
		parent, err := os.Stat(filepath.Dir(path))
		if err != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
			return nil, errors.New("Unix socket requires a private parent directory")
		}
		l, err := net.Listen("unix", path)
		if err != nil {
			return nil, fmt.Errorf("cannot bind Unix socket: %w", err)
		}
		if err := os.Chmod(path, 0600); err != nil {
			l.Close()
			return nil, errors.New("cannot restrict Unix socket")
		}
		return l, nil
	}
	return (&net.ListenConfig{KeepAlive: 30 * time.Second}).Listen(context.Background(), "tcp", address)
}
