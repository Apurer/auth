package auth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Apurer/auth/internal/config"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const sid = "S-1-5-21-1-2-3-1001"
const group = "S-1-5-21-1-2-3-1101"

type fakeDirectory struct {
	fn    func(context.Context, Username, string, func(string) bool) (Identity, error)
	calls atomic.Int32
}

func (d *fakeDirectory) Authenticate(ctx context.Context, u Username, p string, admit func(string) bool) (Identity, error) {
	d.calls.Add(1)
	if d.fn != nil {
		return d.fn(ctx, u, p, admit)
	}
	if !admit(sid) {
		return Identity{}, ErrRateLimited
	}
	return Identity{sid, "alice@example.com", []string{group}}, nil
}
func (d *fakeDirectory) Probe(context.Context) error { return nil }

func testService(t *testing.T, d *fakeDirectory) (*Service, *config.Config) {
	t.Helper()
	c, err := config.Load("../../examples/auth.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c.Policies = map[string]config.Policy{"service": {AnyOf: []string{group}}}
	c.ExportGroups = []string{group}
	return New(&Snapshot{Config: c, Directory: d}, prometheus.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil))), c
}

func request(header string) *authv3.CheckRequest {
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{Source: &authv3.AttributeContext_Peer{Address: &core.Address{Address: &core.Address_SocketAddress{SocketAddress: &core.SocketAddress{Address: "127.0.0.1"}}}}, ContextExtensions: map[string]string{"policy_id": "service"}, Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{Headers: map[string]string{"authorization": header, "x-auth-user-sid": "spoofed"}}}}}
}

func httpStatus(r *authv3.CheckResponse) int {
	if r.GetOkResponse() != nil {
		return 200
	}
	return int(r.GetDeniedResponse().GetStatus().GetCode())
}

func TestDecisionMatrix(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		dirErr error
		policy string
		want   int
	}{
		{"allowed", basic("alice:secret"), nil, "service", 200},
		{"missing credentials", "", nil, "service", 401},
		{"malformed", "Basic !!!", nil, "service", 400},
		{"bad password", basic("alice:secret"), ErrCredentials, "service", 401},
		{"directory failure", basic("alice:secret"), errors.New("secret LDAP diagnostic"), "service", 503},
		{"account limit", basic("alice:secret"), ErrRateLimited, "service", 429},
		{"missing policy", basic("alice:secret"), nil, "", 403},
		{"unknown policy", basic("alice:secret"), nil, "other", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &fakeDirectory{}
			if tc.dirErr != nil {
				d.fn = func(context.Context, Username, string, func(string) bool) (Identity, error) {
					return Identity{}, tc.dirErr
				}
			}
			s, _ := testService(t, d)
			r := request(tc.header)
			r.Attributes.ContextExtensions["policy_id"] = tc.policy
			got, err := s.Check(context.Background(), r)
			if err != nil || httpStatus(got) != tc.want {
				t.Fatalf("status=%d err=%v", httpStatus(got), err)
			}
			if strings.Contains(got.String(), "secret") {
				t.Fatal("secret leaked")
			}
			if tc.want == 200 {
				if len(got.GetOkResponse().GetHeaders()) != 3 || got.GetOkResponse().GetHeadersToRemove()[0] != "authorization" {
					t.Fatal("identity contract")
				}
				if got.GetDynamicMetadata().GetFields()["user_sid"].GetStringValue() != sid {
					t.Fatal("metadata")
				}
			}
		})
	}
}

func TestForbiddenAndEnrichment(t *testing.T) {
	s, c := testService(t, &fakeDirectory{})
	c.Policies["service"] = config.Policy{AnyOf: []string{"S-1-5-32-544"}}
	r, _ := s.Check(context.Background(), request(basic("alice:secret")))
	if httpStatus(r) != 403 {
		t.Fatal(httpStatus(r))
	}
	c.Mode = "enrichment"
	r, _ = s.Check(context.Background(), request(basic("alice:secret")))
	if httpStatus(r) != 200 {
		t.Fatal(httpStatus(r))
	}
}

func TestRawHeaderDuplicates(t *testing.T) {
	s, _ := testService(t, &fakeDirectory{})
	r := request("")
	r.Attributes.Request.Http.HeaderMap = &core.HeaderMap{Headers: []*core.HeaderValue{{Key: "authorization", RawValue: []byte(basic("alice:secret"))}, {Key: "Authorization", RawValue: []byte(basic("alice:secret"))}}}
	got, _ := s.Check(context.Background(), r)
	if httpStatus(got) != 400 {
		t.Fatal("duplicate authorization accepted")
	}
}

func TestOutputLimitsAndProjection(t *testing.T) {
	s, c := testService(t, &fakeDirectory{})
	c.ExportGroups = nil
	r, _ := s.Check(context.Background(), request(basic("alice:secret")))
	if r.GetOkResponse().Headers[2].Header.Value != "[]" {
		t.Fatal("unlisted groups exported")
	}
	c.Limits.MaxIdentityBytes = 64
	r, _ = s.Check(context.Background(), request(basic("alice:secret")))
	if httpStatus(r) != 503 {
		t.Fatal("oversized identity allowed")
	}
}

func TestAdmissionPreventsDirectoryWork(t *testing.T) {
	d := &fakeDirectory{}
	s, c := testService(t, d)
	c.Limits.GlobalPerMinute = 1
	s.Check(context.Background(), request(basic("alice:secret")))
	r, _ := s.Check(context.Background(), request(basic("alice:secret")))
	if httpStatus(r) != 429 || d.calls.Load() != 1 {
		t.Fatal("admission bypassed")
	}
}

func TestLogsDoNotContainCredentialsOrDirectoryErrors(t *testing.T) {
	d := &fakeDirectory{fn: func(context.Context, Username, string, func(string) bool) (Identity, error) {
		return Identity{}, errors.New("private-diagnostic")
	}}
	s, _ := testService(t, d)
	var logs bytes.Buffer
	s.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	s.Check(context.Background(), request(basic("alice:private-password")))
	for _, secret := range []string{"alice", "private-password", "private-diagnostic", "Basic"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("sensitive data logged")
		}
	}
}

func TestGRPCWireAndCancellation(t *testing.T) {
	d := &fakeDirectory{}
	s, _ := testService(t, d)
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	authv3.RegisterAuthorizationServer(server, s)
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///auth", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := authv3.NewAuthorizationClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := client.Check(ctx, request(basic("alice:secret")))
	if err != nil || httpStatus(r) != 200 {
		t.Fatal(r, err)
	}
	cancelled := make(chan struct{})
	d.fn = func(ctx context.Context, _ Username, _ string, _ func(string) bool) (Identity, error) {
		<-ctx.Done()
		close(cancelled)
		return Identity{}, ctx.Err()
	}
	short, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	_, err = client.Check(short, request(basic("alice:secret")))
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("expected RPC deadline, got %v", err)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("RPC cancellation did not reach directory")
	}
}

func TestDeadlineAndOverload(t *testing.T) {
	started := make(chan struct{})
	d := &fakeDirectory{fn: func(ctx context.Context, _ Username, _ string, _ func(string) bool) (Identity, error) {
		close(started)
		<-ctx.Done()
		return Identity{}, ctx.Err()
	}}
	s, c := testService(t, d)
	s.slots = make(chan struct{}, 1)
	c.Limits.Timeout = 50 * time.Millisecond
	done := make(chan *authv3.CheckResponse, 1)
	go func() { r, _ := s.Check(context.Background(), request(basic("alice:secret"))); done <- r }()
	<-started
	r, _ := s.Check(context.Background(), request(basic("bob:secret")))
	if httpStatus(r) != 503 {
		t.Fatal("overload accepted")
	}
	if httpStatus(<-done) != 503 {
		t.Fatal("deadline accepted")
	}
}

func TestReloadRetainsOldSnapshotOnInvalidChange(t *testing.T) {
	s, c := testService(t, &fakeDirectory{})
	next := *c
	next.Listen = "unix:/different.sock"
	if err := s.Reload(&Snapshot{Config: &next, Directory: &fakeDirectory{}}); err == nil || s.Snapshot().Config != c {
		t.Fatal("invalid reload applied")
	}
	next = *c
	next.Version = "new"
	if err := s.Reload(&Snapshot{Config: &next, Directory: &fakeDirectory{}}); err != nil || s.Snapshot().Config.Version != "new" {
		t.Fatal("reload failed")
	}
}

func TestInFlightCheckRetainsPolicySnapshot(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	d := &fakeDirectory{fn: func(context.Context, Username, string, func(string) bool) (Identity, error) {
		close(started)
		<-release
		return Identity{sid, "alice@example.com", []string{group}}, nil
	}}
	s, c := testService(t, d)
	done := make(chan *authv3.CheckResponse, 1)
	go func() { r, _ := s.Check(context.Background(), request(basic("alice:secret"))); done <- r }()
	<-started
	next := *c
	next.Version = "changed"
	next.Policies = map[string]config.Policy{"service": {AnyOf: []string{"S-1-5-32-544"}}}
	if err := s.Reload(&Snapshot{Config: &next, Directory: &fakeDirectory{}}); err != nil {
		t.Fatal(err)
	}
	r, _ := s.Check(context.Background(), request(basic("bob:secret")))
	if httpStatus(r) != 403 {
		t.Fatal("new policy not applied")
	}
	close(release)
	if httpStatus(<-done) != 200 {
		t.Fatal("in-flight policy changed")
	}
}
