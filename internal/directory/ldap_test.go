package directory

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Apurer/auth/internal/auth"
	"github.com/Apurer/auth/internal/config"
	"github.com/go-ldap/ldap/v3"
)

const domain = "S-1-5-21-1-2-3"
const userSID = domain + "-1001"
const primarySID = domain + "-513"
const allowedSID = domain + "-1101"

type fakeConn struct {
	bindErr   error
	binds     int
	requests  []*ldap.SearchRequest
	results   []*ldap.SearchResult
	searchErr error
	closed    chan struct{}
	once      sync.Once
	block     bool
}

func (c *fakeConn) Bind(string, string) error { c.binds++; return c.bindErr }
func (c *fakeConn) Search(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
	c.requests = append(c.requests, r)
	if c.block {
		<-c.closed
		return nil, errors.New("closed")
	}
	if c.searchErr != nil {
		return nil, c.searchErr
	}
	if len(c.results) == 0 {
		return nil, errors.New("unexpected search")
	}
	out := c.results[0]
	c.results = c.results[1:]
	return out, nil
}
func (c *fakeConn) Close() error {
	c.once.Do(func() {
		if c.closed != nil {
			close(c.closed)
		}
	})
	return nil
}
func (c *fakeConn) SetTimeout(time.Duration) {}

func rawSID(s string) []byte                                 { b, _ := EncodeSID(s); return b }
func entry(dn string, attrs map[string][]string) *ldap.Entry { return ldap.NewEntry(dn, attrs) }
func result(e ...*ldap.Entry) *ldap.SearchResult             { return &ldap.SearchResult{Entries: e} }

func fixture() (*LDAP, *fakeConn, *fakeConn) {
	dn := "CN=Alice,DC=example,DC=com"
	guid := "0123456789abcdef"
	reader := &fakeConn{closed: make(chan struct{}), results: []*ldap.SearchResult{
		result(entry(dn, map[string][]string{"objectSid": {string(rawSID(userSID))}, "objectGUID": {guid}, "userPrincipalName": {"alice@example.com"}, "primaryGroupID": {"513"}})),
		result(entry(dn, map[string][]string{"objectSid": {string(rawSID(userSID))}, "objectGUID": {guid}, "tokenGroups": {string(rawSID(allowedSID))}, "primaryGroupID": {"513"}})),
		result(entry("CN=Allowed,DC=example,DC=com", map[string][]string{"objectSid": {string(rawSID(allowedSID))}, "groupType": {"-2147483646"}}), entry("CN=Domain Users,DC=example,DC=com", map[string][]string{"objectSid": {string(rawSID(primarySID))}, "groupType": {"-2147483646"}})),
	}}
	user := &fakeConn{closed: make(chan struct{})}
	n := 0
	d := &LDAP{c: config.Directory{Endpoints: []string{"ldaps://dc.example.com"}, ReaderDN: "CN=reader", UserBase: "DC=example,DC=com", GroupBase: "DC=example,DC=com", DomainSID: domain}, maxGroups: 2048, password: "reader-secret", dial: func(context.Context, string) (connection, error) {
		n++
		if n == 1 {
			return reader, nil
		}
		return user, nil
	}}
	return d, reader, user
}

func TestLDAPAuthenticationAndPrimaryGroup(t *testing.T) {
	d, reader, user := fixture()
	id, err := d.Authenticate(context.Background(), auth.Username{Attribute: "sAMAccountName", Value: "a*)(objectClass=*)"}, "secret", func(s string) bool { return s == userSID })
	if err != nil {
		t.Fatal(err)
	}
	if id.SID != userSID || id.UPN != "alice@example.com" || len(id.Groups) != 2 {
		t.Fatal(id)
	}
	if reader.binds != 1 || user.binds != 1 {
		t.Fatal("bind isolation")
	}
	if !strings.Contains(reader.requests[0].Filter, `a\2a\29\28objectClass=\2a\29`) {
		t.Fatal(reader.requests[0].Filter)
	}
	if reader.requests[1].Scope != ldap.ScopeBaseObject || reader.requests[0].SizeLimit != 2 {
		t.Fatal("query scope or lookup limit")
	}
	select {
	case <-user.closed:
	default:
		t.Fatal("user connection retained")
	}
	select {
	case <-reader.closed:
	default:
		t.Fatal("reader connection retained")
	}
}

func TestLDAPFailuresClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*LDAP, *fakeConn, *fakeConn)
		want   error
	}{
		{"unknown user", func(d *LDAP, r, u *fakeConn) { r.results[0] = result() }, auth.ErrCredentials},
		{"duplicate user", func(d *LDAP, r, u *fakeConn) {
			r.results[0].Entries = append(r.results[0].Entries, r.results[0].Entries[0])
		}, auth.ErrDirectory},
		{"reader credentials", func(d *LDAP, r, u *fakeConn) { r.bindErr = ldap.NewError(49, errors.New("sensitive diagnostic")) }, auth.ErrDirectory},
		{"wrong password", func(d *LDAP, r, u *fakeConn) { u.bindErr = ldap.NewError(49, errors.New("sensitive diagnostic")) }, auth.ErrCredentials},
		{"ambiguous bind", func(d *LDAP, r, u *fakeConn) { u.bindErr = errors.New("network lost") }, auth.ErrDirectory},
		{"missing tokenGroups", func(d *LDAP, r, u *fakeConn) {
			r.results[1].Entries[0].Attributes = r.results[1].Entries[0].Attributes[:0]
		}, auth.ErrDirectory},
		{"identity changed", func(d *LDAP, r, u *fakeConn) {
			r.results[1].Entries[0] = entry("CN=Alice", map[string][]string{"objectGUID": {"fedcba9876543210"}})
		}, auth.ErrDirectory},
		{"partial groups", func(d *LDAP, r, u *fakeConn) { r.results[2].Entries = r.results[2].Entries[:1] }, auth.ErrDirectory},
		{"distribution group", func(d *LDAP, r, u *fakeConn) {
			r.results[2].Entries[0] = entry("CN=distribution", map[string][]string{"objectSid": {string(rawSID(allowedSID))}, "groupType": {"2"}})
		}, auth.ErrDirectory},
		{"referral", func(d *LDAP, r, u *fakeConn) { r.results[0].Referrals = []string{"ldap://evil"} }, auth.ErrDirectory},
		{"size limit", func(d *LDAP, r, u *fakeConn) { r.searchErr = ldap.NewError(4, errors.New("partial")) }, auth.ErrDirectory},
		{"too many groups", func(d *LDAP, r, u *fakeConn) { d.maxGroups = 1 }, auth.ErrDirectory},
		{"SID history", func(d *LDAP, r, u *fakeConn) {
			r.results[0].Entries[0].Attributes = append(r.results[0].Entries[0].Attributes, &ldap.EntryAttribute{Name: "sIDHistory", Values: []string{"history"}, ByteValues: [][]byte{[]byte("history")}})
		}, auth.ErrDirectory},
		{"ranged tokenGroups", func(d *LDAP, r, u *fakeConn) {
			r.results[1].Entries[0].Attributes = append(r.results[1].Entries[0].Attributes, &ldap.EntryAttribute{Name: "tokenGroups;range=0-1499"})
		}, auth.ErrDirectory},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, r, u := fixture()
			tc.change(d, r, u)
			_, err := d.Authenticate(context.Background(), auth.Username{Attribute: "sAMAccountName", Value: "alice"}, "secret", func(string) bool { return true })
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}

func TestAccountLimitBeforeUserBind(t *testing.T) {
	d, _, user := fixture()
	_, err := d.Authenticate(context.Background(), auth.Username{Attribute: "sAMAccountName", Value: "alice"}, "secret", func(string) bool { return false })
	if !errors.Is(err, auth.ErrRateLimited) || user.binds != 0 {
		t.Fatal("account limit did not precede bind")
	}
}

func TestCancellationClosesLDAPConnection(t *testing.T) {
	d, r, _ := fixture()
	r.block = true
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := d.Authenticate(ctx, auth.Username{Attribute: "sAMAccountName", Value: "alice"}, "secret", func(string) bool { return true })
	if !errors.Is(err, auth.ErrDirectory) {
		t.Fatal(err)
	}
}

func TestFailoverOnlyBeforeBind(t *testing.T) {
	d, r, u := fixture()
	d.c.Endpoints = append(d.c.Endpoints, "ldaps://second.example.com")
	calls := 0
	d.dial = func(ctx context.Context, s string) (connection, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("connection unavailable")
		}
		if calls == 2 {
			return r, nil
		}
		return u, nil
	}
	if _, err := d.Authenticate(context.Background(), auth.Username{Attribute: "sAMAccountName", Value: "alice"}, "secret", func(string) bool { return true }); err != nil || calls != 3 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestSIDRoundTrip(t *testing.T) {
	for _, s := range []string{userSID, primarySID, "S-1-5-32-545", "S-1-281474976710655-4294967295"} {
		raw, err := EncodeSID(s)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeSID(raw)
		if err != nil || got != s {
			t.Fatal(got, err)
		}
	}
	for _, raw := range [][]byte{nil, {1, 2, 3}, make([]byte, 8), append(rawSID(userSID), 0)} {
		if _, err := DecodeSID(raw); err == nil {
			t.Fatal("malformed SID accepted")
		}
	}
}

func FuzzSID(f *testing.F) {
	f.Add(rawSID(userSID))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := DecodeSID(b)
		if err == nil {
			encoded, err := EncodeSID(s)
			if err != nil || string(encoded) != string(b) {
				t.Fatal("round trip")
			}
		}
	})
}
