package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Apurer/auth/internal/config"
	"github.com/Apurer/auth/internal/testutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func TestMTLSRequiresAuthorizedCertificate(t *testing.T) {
	ca := testutil.NewCA(t)
	cert := ca.Issue(t, "127.0.0.1", true)
	allowed := ca.Issue(t, "envoy.example.com", false)
	other := ca.Issue(t, "other.example.com", false)
	c := &config.Config{Listen: "127.0.0.1:0", TLS: config.TLS{Certificate: cert.CertPath, PrivateKey: cert.KeyPath, ClientCA: ca.Path, AllowedClientSANs: []string{"envoy.example.com"}}, Limits: config.Limits{MaxConcurrent: 16}}
	s, err := Server(c)
	if err != nil {
		t.Fatal(err)
	}
	healthpb.RegisterHealthServer(s, health.NewServer())
	l, err := net.Listen("tcp", c.Listen)
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(l)
	defer s.Stop()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.PEM)
	for _, tc := range []struct {
		name  string
		certs []tls.Certificate
		allow bool
	}{{"authorized", []tls.Certificate{allowed.TLS}, true}, {"wrong SAN", []tls.Certificate{other.TLS}, false}, {"no certificate", nil, false}} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := grpc.NewClient(l.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: roots, Certificates: tc.certs, MinVersion: tls.VersionTLS12})))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
			if (err == nil) != tc.allow {
				t.Fatalf("allowed=%v err=%v", tc.allow, err)
			}
		})
	}
}

func TestUnixSocketPermissions(t *testing.T) {
	dir, err := os.MkdirTemp("", "s-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "auth.sock")
	l, err := Listen("unix:" + path)
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("Unix sockets are disabled by this execution environment")
		}
		t.Fatal(err)
	}
	defer l.Close()
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("socket not private", err)
	}
}
