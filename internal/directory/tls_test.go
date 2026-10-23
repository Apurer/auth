package directory

import (
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Apurer/auth/internal/config"
	"github.com/Apurer/auth/internal/testutil"
)

func TestLDAPTLSVerification(t *testing.T) {
	ca := testutil.NewCA(t)
	for _, tc := range []struct {
		name, certName   string
		trusted, allowed bool
	}{{"valid", "127.0.0.1", true, true}, {"wrong hostname", "wrong.example.com", true, false}, {"untrusted CA", "127.0.0.1", false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			cert := ca.Issue(t, tc.certName, true)
			l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert.TLS}, MinVersion: tls.VersionTLS12})
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			go func() {
				conn, err := l.Accept()
				if err == nil {
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(time.Second))
					conn.(*tls.Conn).Handshake()
					b := make([]byte, 1)
					conn.Read(b)
				}
			}()
			root := ca.Path
			if !tc.trusted {
				root = testutil.NewCA(t).Path
			}
			secret := filepath.Join(t.TempDir(), "reader-password")
			if err := os.WriteFile(secret, []byte("reader-secret"), 0600); err != nil {
				t.Fatal(err)
			}
			d, err := New(config.Directory{CAFile: root, ReaderPasswordFile: secret}, 100, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := d.dial(ctx, "ldaps://"+l.Addr().String())
			if conn != nil {
				conn.Close()
			}
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v err=%v", tc.allowed, err)
			}
		})
	}
}
