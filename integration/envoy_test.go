package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Apurer/auth/internal/auth"
	"github.com/Apurer/auth/internal/config"
	"github.com/Apurer/auth/internal/testutil"
	"github.com/Apurer/auth/internal/transport"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/prometheus/client_golang/prometheus"
)

const domain = "S-1-5-21-111111111-222222222-333333333"

type fixtureDirectory struct{}

func (fixtureDirectory) Probe(context.Context) error { return nil }
func (fixtureDirectory) Authenticate(ctx context.Context, u auth.Username, password string, admit func(string) bool) (auth.Identity, error) {
	username := strings.TrimSuffix(u.Value, "@example.com")
	if password != "test-password" {
		return auth.Identity{}, auth.ErrCredentials
	}
	if username == "down" {
		return auth.Identity{}, errors.New("directory offline")
	}
	if !admit(domain + "-1001") {
		return auth.Identity{}, auth.ErrRateLimited
	}
	groups := []string{domain + "-513"}
	if username == "alice" {
		groups = append(groups, domain+"-1101")
	}
	resolved := map[string]string{}
	for _, ref := range auth.RequestedGroups(ctx) {
		switch ref.Name {
		case "Orders Users":
			resolved[ref.Key()] = domain + "-1101"
		case "Reports Users":
			resolved[ref.Key()] = domain + "-1103"
		default:
			return auth.Identity{}, auth.ErrDirectory
		}
	}
	return auth.Identity{SID: domain + "-1001", UPN: username + "@example.com", Groups: groups, ResolvedGroups: resolved}, nil
}

// TestEnvoy exercises the actual example config and a real Envoy process. Only
// AD is replaced; LDAP transport and protocol behavior have separate tests.
func TestEnvoy(t *testing.T) {
	t.Run("mtls", func(t *testing.T) { testEnvoy(t, false) })
	t.Run("unix_named_groups", func(t *testing.T) { testEnvoy(t, true) })
}

func testEnvoy(t *testing.T, unix bool) {
	binary := os.Getenv("ENVOY_BINARY")
	if binary == "" {
		t.Skip("set ENVOY_BINARY to run real Envoy integration")
	}
	configPath := "../examples/auth.yaml"
	if unix {
		configPath = "../examples/auth-minimal.yaml"
	}
	c, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "e-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	ca := testutil.NewCA(t)
	cert := ca.Issue(t, "127.0.0.1", true)
	authCert := ca.Issue(t, "auth.example.com", true)
	envoyCert := ca.Issue(t, "envoy.example.com", false)
	c.Listen = "127.0.0.1:0"
	if unix {
		c.Listen = "unix:" + filepath.Join(dir, "a.sock")
	}
	c.TLS = config.TLS{Certificate: authCert.CertPath, PrivateKey: authCert.KeyPath, ClientCA: ca.Path, AllowedClientSANs: []string{"envoy.example.com"}}
	svc := auth.New(&auth.Snapshot{Config: c, Directory: fixtureDirectory{}}, prometheus.NewRegistry(), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	grpcServer, err := transport.Server(c)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := transport.Listen(c.Listen)
	if err != nil {
		if unix && errors.Is(err, syscall.EPERM) {
			t.Skip("Unix sockets are disabled by this execution environment")
		}
		t.Fatal(err)
	}
	authv3.RegisterAuthorizationServer(grpcServer, svc)
	go grpcServer.Serve(listener)
	defer grpcServer.Stop()
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		json.NewEncoder(w).Encode(r.Header)
	}))
	defer upstream.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	envoyPort := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	b, err := os.ReadFile("../examples/envoy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	authPort := "9001"
	if !unix {
		authPort = strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	}
	text := strings.NewReplacer("/run/secrets/service-cert.pem", cert.CertPath, "/run/secrets/service-key.pem", cert.KeyPath, "/run/secrets/envoy-cert.pem", envoyCert.CertPath, "/run/secrets/envoy-key.pem", envoyCert.KeyPath, "/run/secrets/auth-ca.pem", ca.Path, "port_value: 9001", "port_value: "+authPort, "port_value: 8443", "port_value: "+strconv.Itoa(envoyPort), "port_value: 8080", "port_value: "+port, "port_value: 8081", "port_value: "+port).Replace(string(b))
	if unix {
		cluster, err := os.ReadFile("../examples/envoy-unix-cluster.yaml")
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for _, line := range strings.Split(strings.TrimSpace(string(cluster)), "\n") {
			lines = append(lines, "    "+line)
		}
		replacement := strings.ReplaceAll(strings.Join(lines, "\n")+"\n", "/run/envoy-ad-auth/auth.sock", strings.TrimPrefix(c.Listen, "unix:"))
		start := strings.Index(text, "    - name: ad-auth\n")
		end := strings.Index(text, "    - name: orders\n")
		if start < 0 || end < start {
			t.Fatal("example cluster layout changed")
		}
		text = text[:start] + replacement + text[end:]
	}
	path := filepath.Join(dir, "envoy.yaml")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(dir, "envoy.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.Command(binary, "-c", path, "--concurrency", "1", "--disable-hot-restart", "--log-level", "error")
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.PEM)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	base := fmt.Sprintf("https://127.0.0.1:%d", envoyPort)
	ready := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		r, err := client.Get(base + "/orders/")
		if err == nil {
			r.Body.Close()
			ready = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		logs, _ := os.ReadFile(log.Name())
		t.Fatalf("Envoy did not start: %s", logs)
	}
	for _, tc := range []struct {
		name, path, user, password string
		want                       int
	}{
		{"no credentials", "/orders/", "", "", 401},
		{"allowed group", "/orders/", "alice", "test-password", 200},
		{"not in allowed group", "/orders/", "bob", "test-password", 403},
		{"wrong service group", "/reports/", "alice", "test-password", 403},
		{"wrong password", "/orders/", "alice", "wrong", 401},
		{"unconfigured route", "/unknown/", "alice", "test-password", 403},
		{"directory unavailable", "/orders/", "down", "test-password", 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", base+tc.path, nil)
			if tc.user != "" {
				req.SetBasicAuth(tc.user, tc.password)
			}
			req.Header.Set("X-Auth-User-Sid", "forged")
			req.Header.Set("X-Auth-Extra", "forged")
			before := upstreamCalls.Load()
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("got %d want %d: %s", resp.StatusCode, tc.want, body)
			}
			if tc.want != 200 {
				if upstreamCalls.Load() != before {
					t.Fatal("denied request reached upstream")
				}
				return
			}
			var headers http.Header
			if err := json.NewDecoder(resp.Body).Decode(&headers); err != nil {
				t.Fatal(err)
			}
			expectedGroups := `["` + domain + `-1101"]`
			if unix {
				expectedGroups = "[]"
			}
			if headers.Get("Authorization") != "" || headers.Get("X-Auth-Extra") != "" || headers.Get("X-Auth-User-Sid") != domain+"-1001" || headers.Get("X-Auth-Group-Sids") != expectedGroups {
				t.Fatalf("identity propagation failed: %v", headers)
			}
		})
	}
	t.Run("duplicate credentials", func(t *testing.T) {
		req, _ := http.NewRequest("GET", base+"/orders/", nil)
		header := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:test-password"))
		req.Header.Add("Authorization", header)
		req.Header.Add("Authorization", header)
		before := upstreamCalls.Load()
		r, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != 400 || upstreamCalls.Load() != before {
			t.Fatalf("duplicate credentials: %d", r.StatusCode)
		}
	})
	t.Run("auth service outage", func(t *testing.T) {
		grpcServer.Stop()
		req, _ := http.NewRequest("GET", base+"/orders/", nil)
		req.SetBasicAuth("alice", "test-password")
		before := upstreamCalls.Load()
		r, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != 503 || upstreamCalls.Load() != before {
			t.Fatalf("outage: %d", r.StatusCode)
		}
	})
}
