// Package auth implements Envoy's v3 external authorization API.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Apurer/auth/internal/config"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/genproto/googleapis/rpc/code"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type Identity struct {
	SID, UPN       string
	Groups         []string
	ResolvedGroups map[string]string
}

type Directory interface {
	Authenticate(context.Context, Username, string, func(string) bool) (Identity, error)
	Probe(context.Context) error
}

// Snapshot is immutable after publication. In-flight checks retain one version.
type Snapshot struct {
	Config    *config.Config
	Directory Directory
}

type Service struct {
	authv3.UnimplementedAuthorizationServer
	current   atomic.Pointer[Snapshot]
	admission *Admission
	slots     chan struct{}
	checks    *prometheus.CounterVec
	latency   prometheus.Histogram
	inflight  prometheus.Gauge
	logger    *slog.Logger
}

func New(s *Snapshot, registry prometheus.Registerer, logger *slog.Logger) *Service {
	v := &Service{admission: NewAdmission(s.Config.Limits.MaxRateKeys), slots: make(chan struct{}, s.Config.Limits.MaxConcurrent), logger: logger,
		checks:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "auth_checks_total", Help: "Checks by bounded result category."}, []string{"outcome"}),
		latency:  prometheus.NewHistogram(prometheus.HistogramOpts{Name: "auth_check_duration_seconds", Help: "Total authorization latency.", Buckets: []float64{.01, .025, .05, .1, .25, .5, 1, 2, 5}}),
		inflight: prometheus.NewGauge(prometheus.GaugeOpts{Name: "auth_inflight", Help: "Checks currently using a directory slot."})}
	registry.MustRegister(v.checks, v.latency, v.inflight)
	v.current.Store(s)
	return v
}

func (s *Service) Snapshot() *Snapshot { return s.current.Load() }

func (s *Service) Reload(next *Snapshot) error {
	old := s.current.Load().Config
	// Listener credentials and admission state require restart, not a partial reload.
	if next.Config.Listen != old.Listen || next.Config.AdminListen != old.AdminListen || next.Config.Limits != old.Limits || !slices.Equal(next.Config.TLS.AllowedClientSANs, old.TLS.AllowedClientSANs) || next.Config.TLS.Certificate != old.TLS.Certificate || next.Config.TLS.PrivateKey != old.TLS.PrivateKey || next.Config.TLS.ClientCA != old.TLS.ClientCA {
		return errors.New("listener or admission changes require restart")
	}
	s.current.Store(next)
	return nil
}

func (s *Service) Check(ctx context.Context, req *authv3.CheckRequest) (resp *authv3.CheckResponse, err error) {
	start := time.Now()
	outcome := "internal_error"
	defer func() {
		if recover() != nil {
			outcome = "internal_error"
			resp = deny(503, "authentication service unavailable", false)
		}
		s.checks.WithLabelValues(outcome).Inc()
		s.latency.Observe(time.Since(start).Seconds())
		// Never log request objects, usernames, credentials, or directory errors.
		s.logger.Info("authorization check", "outcome", outcome, "duration_ms", time.Since(start).Milliseconds())
	}()
	snap := s.current.Load()
	c := snap.Config
	ctx, cancel := context.WithTimeout(ctx, c.Limits.Timeout)
	defer cancel()
	attrs := req.GetAttributes()
	http := attrs.GetRequest().GetHttp()
	if http == nil {
		outcome = "malformed"
		return deny(400, "invalid request", false), nil
	}
	var policy config.Policy
	if c.Mode == "group_policy" {
		var ok bool
		policy, ok = c.Policies[attrs.GetContextExtensions()["policy_id"]]
		if !ok {
			outcome = "policy_missing"
			return deny(403, "access denied", false), nil
		}
	}
	source := attrs.GetSource().GetAddress().GetSocketAddress().GetAddress()
	if source == "" {
		outcome = "malformed"
		return deny(400, "missing source address", false), nil
	}
	if !s.admission.Allow("global", "", c.Limits.GlobalPerMinute) || !s.admission.Allow("source", source, c.Limits.SourcePerMinute) {
		outcome = "rate_limited"
		return deny(429, "too many requests", false), nil
	}
	header, parseErr := authorization(http)
	if parseErr != nil {
		outcome = "malformed"
		return deny(400, "invalid credentials", false), nil
	}
	u, password, parseErr := ParseCredentials(header, c.Directory, c.Limits.MaxCredentialBytes)
	if parseErr != nil {
		switch {
		case errors.Is(parseErr, ErrCredentials):
			outcome = "unauthenticated"
			return deny(401, "authentication required", true), nil
		case errors.Is(parseErr, ErrOversized):
			outcome = "oversized"
			return deny(431, "credentials too large", false), nil
		default:
			outcome = "malformed"
			return deny(400, "invalid credentials", false), nil
		}
	}
	defer func() { password = "" }()
	if !s.admission.Allow("input", strings.ToLower(u.Attribute+":"+u.Value), c.Limits.AccountPerMinute) {
		outcome = "rate_limited"
		return deny(429, "too many requests", false), nil
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		outcome = "overloaded"
		return deny(503, "authentication service unavailable", false), nil
	}
	s.inflight.Inc()
	defer s.inflight.Dec()
	identity, authErr := snap.Directory.Authenticate(WithGroupRefs(ctx, policy.NamedGroups()), u, password, func(sid string) bool { return s.admission.Allow("account", sid, c.Limits.AccountPerMinute) })
	if authErr != nil {
		switch {
		case errors.Is(authErr, ErrCredentials):
			outcome = "unauthenticated"
			return deny(401, "authentication required", true), nil
		case errors.Is(authErr, ErrRateLimited):
			outcome = "rate_limited"
			return deny(429, "too many requests", false), nil
		default:
			outcome = "directory_error"
			return deny(503, "authentication service unavailable", false), nil
		}
	}
	if ctx.Err() != nil {
		outcome = "directory_error"
		return deny(503, "authentication service unavailable", false), nil
	}
	if !config.ValidSID(identity.SID) || identity.UPN == "" || len(identity.Groups) > c.Limits.MaxGroups {
		outcome = "directory_error"
		return deny(503, "authentication service unavailable", false), nil
	}
	groups := slices.Clone(identity.Groups)
	slices.Sort(groups)
	groups = slices.Compact(groups)
	for _, g := range groups {
		if !config.ValidSID(g) {
			outcome = "directory_error"
			return deny(503, "authentication service unavailable", false), nil
		}
	}
	if c.Mode == "group_policy" && !policy.ValidateResolved(identity.ResolvedGroups) {
		outcome = "directory_error"
		return deny(503, "authentication service unavailable", false), nil
	}
	if c.Mode == "group_policy" && !policy.Allows(groups, identity.ResolvedGroups) {
		outcome = "forbidden"
		return deny(403, "access denied", false), nil
	}
	exported := make([]string, 0, len(groups))
	for _, g := range groups {
		if slices.Contains(c.ExportGroups, g) {
			exported = append(exported, g)
		}
	}
	b, _ := json.Marshal(exported)
	headers := []*core.HeaderValueOption{headerValue("x-auth-user-sid", identity.SID), headerValue("x-auth-user-upn", url.PathEscape(identity.UPN)), headerValue("x-auth-group-sids", string(b))}
	total := 0
	for _, h := range headers {
		total += len(h.Header.Key) + len(h.Header.Value) + 4
	}
	if total > c.Limits.MaxIdentityBytes {
		outcome = "identity_oversized"
		return deny(503, "authentication service unavailable", false), nil
	}
	values := make([]any, len(groups))
	for i, g := range groups {
		values[i] = g
	}
	metadata, _ := structpb.NewStruct(map[string]any{"user_sid": identity.SID, "user_upn": identity.UPN, "group_sids": values, "config_version": c.Version})
	outcome = "allowed"
	return &authv3.CheckResponse{Status: &statuspb.Status{Code: int32(code.Code_OK)}, HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: &authv3.OkHttpResponse{Headers: headers, HeadersToRemove: []string{"authorization"}}}, DynamicMetadata: metadata}, nil
}

// Raw headers preserve duplicates. Also support older Envoy's map representation,
// where duplicate Authorization fields are comma-joined and rejected by parsing.
func authorization(h *authv3.AttributeContext_HttpRequest) (string, error) {
	count := 0
	value := ""
	if h.HeaderMap != nil {
		for _, v := range h.HeaderMap.Headers {
			if strings.EqualFold(v.Key, "authorization") {
				count++
				value = string(v.RawValue)
				if value == "" {
					value = v.Value
				}
			}
		}
	} else {
		for k, v := range h.Headers {
			if strings.EqualFold(k, "authorization") {
				count++
				value = v
			}
		}
	}
	if count > 1 {
		return "", ErrMalformed
	}
	return value, nil
}

func headerValue(key, value string) *core.HeaderValueOption {
	return &core.HeaderValueOption{Header: &core.HeaderValue{Key: key, Value: value}, AppendAction: core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD}
}

func deny(http int, body string, challenge bool) *authv3.CheckResponse {
	h := []*core.HeaderValueOption{headerValue("content-type", "text/plain; charset=utf-8"), headerValue("cache-control", "no-store")}
	if challenge {
		h = append(h, headerValue("www-authenticate", `Basic realm="ad", charset="UTF-8"`))
	}
	if http == 429 {
		h = append(h, headerValue("retry-after", "60"))
	}
	return &authv3.CheckResponse{Status: &statuspb.Status{Code: int32(code.Code_PERMISSION_DENIED)}, HttpResponse: &authv3.CheckResponse_DeniedResponse{DeniedResponse: &authv3.DeniedHttpResponse{Status: &typev3.HttpStatus{Code: typev3.StatusCode(http)}, Headers: h, Body: body + "\n"}}}
}
