// Package directory authenticates against AD DS over verified LDAPS.
package directory

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Apurer/auth/internal/auth"
	"github.com/Apurer/auth/internal/config"
	"github.com/go-ldap/ldap/v3"
	"github.com/prometheus/client_golang/prometheus"
)

type connection interface {
	Bind(string, string) error
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
	SetTimeout(time.Duration)
}
type dialFunc func(context.Context, string) (connection, error)

type LDAP struct {
	c         config.Directory
	maxGroups int
	password  string
	dial      dialFunc
	next      atomic.Uint64
	metrics   *Metrics
}

type Metrics struct {
	operations *prometheus.CounterVec
	latency    *prometheus.HistogramVec
	groups     prometheus.Histogram
}

func NewMetrics(r prometheus.Registerer) *Metrics {
	m := &Metrics{operations: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "auth_ldap_operations_total", Help: "LDAP operations by phase and result."}, []string{"phase", "result"}), latency: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "auth_ldap_duration_seconds", Help: "LDAP phase latency.", Buckets: prometheus.DefBuckets}, []string{"phase"}), groups: prometheus.NewHistogram(prometheus.HistogramOpts{Name: "auth_group_count", Help: "Number of resolved group SIDs.", Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2048}})}
	r.MustRegister(m.operations, m.latency, m.groups)
	return m
}

func New(c config.Directory, maxGroups int, m *Metrics) (*LDAP, error) {
	ca, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, errors.New("cannot read directory CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid directory CA")
	}
	password, err := os.ReadFile(c.ReaderPasswordFile)
	if err != nil || len(password) == 0 {
		return nil, errors.New("cannot read nonempty reader password")
	}
	d := &LDAP{c: c, maxGroups: maxGroups, password: string(password), metrics: m}
	clear(password)
	d.dial = func(ctx context.Context, endpoint string) (connection, error) {
		u, _ := url.Parse(endpoint)
		port := u.Port()
		if port == "" {
			port = "636"
		}
		tcp, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
		if err != nil {
			return nil, auth.ErrDirectory
		}
		secure := tls.Client(tcp, &tls.Config{RootCAs: roots, ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
		if err = secure.HandshakeContext(ctx); err != nil {
			tcp.Close()
			return nil, auth.ErrDirectory
		}
		conn := ldap.NewConn(secure, true)
		conn.Start()
		return conn, nil
	}
	return d, nil
}

func (d *LDAP) record(phase string, start time.Time, err error) {
	if d.metrics == nil {
		return
	}
	result := "success"
	if err != nil {
		result = "failure"
	}
	d.metrics.operations.WithLabelValues(phase, result).Inc()
	d.metrics.latency.WithLabelValues(phase).Observe(time.Since(start).Seconds())
}

func attach(ctx context.Context, c connection) func() {
	if deadline, ok := ctx.Deadline(); ok {
		c.SetTimeout(max(time.Until(deadline), time.Nanosecond))
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	return func() { stop(); c.Close() }
}

// connectReader fails over only connection setup, before a bind is submitted.
func (d *LDAP) connectReader(ctx context.Context) (connection, string, func(), error) {
	start := int(d.next.Add(1)-1) % len(d.c.Endpoints)
	for i := 0; i < len(d.c.Endpoints); i++ {
		endpoint := d.c.Endpoints[(start+i)%len(d.c.Endpoints)]
		// Reserve time for another configured endpoint when connection setup fails.
		dialCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		conn, err := d.dial(dialCtx, endpoint)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			continue
		}
		cleanup := attach(ctx, conn)
		t := time.Now()
		err = conn.Bind(d.c.ReaderDN, d.password)
		d.record("reader_bind", t, err)
		if err != nil {
			cleanup()
			return nil, "", nil, auth.ErrDirectory
		}
		return conn, endpoint, cleanup, nil
	}
	return nil, "", nil, auth.ErrDirectory
}

func (d *LDAP) Probe(ctx context.Context) error {
	_, _, close, err := d.connectReader(ctx)
	if err != nil {
		return auth.ErrDirectory
	}
	close()
	return nil
}

func (d *LDAP) search(conn connection, base string, scope int, filter string, attrs []string, limit int, phase string) (*ldap.SearchResult, error) {
	t := time.Now()
	r, err := conn.Search(ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, limit, 0, false, filter, attrs, nil))
	if err == nil && (r == nil || len(r.Referrals) > 0) {
		err = auth.ErrDirectory
	}
	d.record(phase, t, err)
	if err != nil {
		return nil, auth.ErrDirectory
	}
	return r, nil
}

func (d *LDAP) Authenticate(ctx context.Context, u auth.Username, password string, beforeBind func(string) bool) (auth.Identity, error) {
	if password == "" {
		return auth.Identity{}, auth.ErrCredentials
	}
	if u.Attribute != "sAMAccountName" && u.Attribute != "userPrincipalName" {
		return auth.Identity{}, auth.ErrCredentials
	}
	reader, endpoint, cleanup, err := d.connectReader(ctx)
	if err != nil {
		return auth.Identity{}, err
	}
	defer cleanup()
	filter := "(&(objectCategory=person)(objectClass=user)(" + u.Attribute + "=" + ldap.EscapeFilter(u.Value) + "))"
	r, err := d.search(reader, d.c.UserBase, ldap.ScopeWholeSubtree, filter, []string{"objectSid", "objectGUID", "userPrincipalName", "primaryGroupID", "sIDHistory"}, 2, "user_lookup")
	if err != nil {
		return auth.Identity{}, err
	}
	if len(r.Entries) == 0 {
		return auth.Identity{}, auth.ErrCredentials
	}
	if len(r.Entries) != 1 {
		return auth.Identity{}, auth.ErrDirectory
	}
	user := r.Entries[0]
	sid, err := DecodeSID(user.GetRawAttributeValue("objectSid"))
	guid := user.GetRawAttributeValue("objectGUID")
	upn := user.GetAttributeValue("userPrincipalName")
	if err != nil || len(guid) != 16 || upn == "" || !strings.HasPrefix(sid, d.c.DomainSID+"-") || len(strings.Split(sid, "-")) != 8 || len(user.GetRawAttributeValues("sIDHistory")) > 0 {
		return auth.Identity{}, auth.ErrDirectory
	}
	if !beforeBind(sid) {
		return auth.Identity{}, auth.ErrRateLimited
	}
	// No failover or retry after credentials are submitted, including ambiguous binds.
	userConn, err := d.dial(ctx, endpoint)
	if err != nil {
		return auth.Identity{}, auth.ErrDirectory
	}
	closeUser := attach(ctx, userConn)
	t := time.Now()
	err = userConn.Bind(user.DN, password)
	closeUser()
	d.record("user_bind", t, err)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return auth.Identity{}, auth.ErrCredentials
		}
		return auth.Identity{}, auth.ErrDirectory
	}
	if ctx.Err() != nil {
		return auth.Identity{}, auth.ErrDirectory
	}
	r, err = d.search(reader, user.DN, ldap.ScopeBaseObject, "(objectClass=user)", []string{"objectGUID", "objectSid", "tokenGroups", "primaryGroupID", "sIDHistory"}, 1, "membership")
	if err != nil || len(r.Entries) != 1 {
		return auth.Identity{}, auth.ErrDirectory
	}
	member := r.Entries[0]
	if !bytes.Equal(member.GetRawAttributeValue("objectGUID"), guid) || !bytes.Equal(member.GetRawAttributeValue("objectSid"), user.GetRawAttributeValue("objectSid")) || len(member.GetRawAttributeValues("sIDHistory")) > 0 {
		return auth.Identity{}, auth.ErrDirectory
	}
	// Missing/ranged attributes can represent insufficient permissions or partial data.
	for _, a := range member.Attributes {
		if strings.Contains(strings.ToLower(a.Name), ";range=") {
			return auth.Identity{}, auth.ErrDirectory
		}
	}
	raw := member.GetRawAttributeValues("tokenGroups")
	if len(raw) == 0 || len(raw) > d.maxGroups {
		return auth.Identity{}, auth.ErrDirectory
	}
	rid, err := strconv.ParseUint(member.GetAttributeValue("primaryGroupID"), 10, 32)
	if err != nil || rid == 0 {
		return auth.Identity{}, auth.ErrDirectory
	}
	groups := map[string][]byte{}
	for _, b := range raw {
		g, err := DecodeSID(b)
		if err != nil {
			return auth.Identity{}, auth.ErrDirectory
		}
		groups[g] = b
	}
	primary := fmt.Sprintf("%s-%d", d.c.DomainSID, rid)
	pb, _ := EncodeSID(primary)
	groups[primary] = pb
	if len(groups) > d.maxGroups {
		return auth.Identity{}, auth.ErrDirectory
	}
	// Verify every returned SID resolves to a current security group in the
	// configured group base. SID history and foreign/unresolved grants fail closed.
	all := make([]string, 0, len(groups))
	for g := range groups {
		all = append(all, g)
	}
	slices.Sort(all)
	for offset := 0; offset < len(all); offset += 100 {
		batch := all[offset:min(offset+100, len(all))]
		var f strings.Builder
		f.WriteString("(&(objectClass=group)(|")
		for _, g := range batch {
			f.WriteString("(objectSid=" + binaryFilter(groups[g]) + ")")
		}
		f.WriteString("))")
		r, err = d.search(reader, d.c.GroupBase, ldap.ScopeWholeSubtree, f.String(), []string{"objectSid", "groupType", "sIDHistory"}, len(batch), "group_validation")
		if err != nil || len(r.Entries) != len(batch) {
			return auth.Identity{}, auth.ErrDirectory
		}
		seen := map[string]bool{}
		for _, entry := range r.Entries {
			g, err := DecodeSID(entry.GetRawAttributeValue("objectSid"))
			if err != nil || !slices.Contains(batch, g) || seen[g] || len(entry.GetRawAttributeValues("sIDHistory")) > 0 {
				return auth.Identity{}, auth.ErrDirectory
			}
			kind, err := strconv.ParseInt(entry.GetAttributeValue("groupType"), 10, 64)
			if err != nil || kind&0x80000000 == 0 {
				return auth.Identity{}, auth.ErrDirectory
			}
			seen[g] = true
		}
	}
	if ctx.Err() != nil {
		return auth.Identity{}, auth.ErrDirectory
	}
	if d.metrics != nil {
		d.metrics.groups.Observe(float64(len(all)))
	}
	return auth.Identity{SID: sid, UPN: upn, Groups: all}, nil
}
