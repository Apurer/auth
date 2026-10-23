package directory

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Apurer/auth/internal/auth"
	"github.com/Apurer/auth/internal/config"
	"github.com/go-ldap/ldap/v3"
)

func userFixture() (*LDAP, *fakeConn) {
	d, r, _ := fixture()
	d.c = config.Directory{Domain: "example.com", Endpoints: []string{"ldaps://dc.example.com"}, BindMode: "user"}
	r.results = append([]*ldap.SearchResult{result(entry("", map[string][]string{"defaultNamingContext": {"DC=example,DC=com"}})), result(entry("DC=example,DC=com", map[string][]string{"objectSid": {string(rawSID(domain))}}))}, r.results...)
	d.dial = func(context.Context, string) (connection, error) { return r, nil }
	d.password = ""
	return d, r
}

func TestUserBoundDiscoveryAndNamedGroups(t *testing.T) {
	d, r := userFixture()
	ref := config.GroupRef{Name: "Orders*)(Users", Domain: "example.com"}
	r.results = append(r.results, result(entry("CN=Orders", map[string][]string{"objectSid": {string(rawSID(allowedSID))}, "groupType": {"-2147483646"}})))
	id, err := d.Authenticate(auth.WithGroupRefs(context.Background(), []config.GroupRef{ref}), auth.Username{Attribute: "userPrincipalName", Value: "alice@example.com"}, "secret", func(s string) bool { return s == userSID })
	if err != nil {
		t.Fatal(err)
	}
	if id.SID != userSID || id.ResolvedGroups[ref.Key()] != allowedSID || len(id.Groups) != 2 {
		t.Fatal("wrong identity/group resolution")
	}
	if r.binds != 2 || r.bindNames[0] != "alice@example.com" || r.bindNames[1] != "CN=Alice,DC=example,DC=com" {
		t.Fatal("expected UPN bind followed by canonical DN confirmation")
	}
	if r.requests[0].BaseDN != "" || r.requests[1].BaseDN != "DC=example,DC=com" || r.requests[2].BaseDN != "DC=example,DC=com" {
		t.Fatal("discovery scopes")
	}
	if !strings.Contains(r.requests[len(r.requests)-1].Filter, `Orders\2a\29\28Users`) {
		t.Fatal("group filter was not escaped")
	}
}

func TestUserBoundFailuresClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*LDAP, *fakeConn)
		want   error
	}{
		{"bad initial credentials", func(d *LDAP, r *fakeConn) { r.bindErr = ldap.NewError(49, errors.New("private")) }, auth.ErrCredentials},
		{"ambiguous initial bind", func(d *LDAP, r *fakeConn) { r.bindErr = errors.New("connection lost") }, auth.ErrDirectory},
		{"canonical confirmation fails", func(d *LDAP, r *fakeConn) {
			r.bindErrors = []error{nil, ldap.NewError(49, errors.New("other account"))}
		}, auth.ErrCredentials},
		{"missing rootDSE", func(d *LDAP, r *fakeConn) { r.results[0] = result() }, auth.ErrDirectory},
		{"wrong domain", func(d *LDAP, r *fakeConn) {
			r.results[0] = result(entry("", map[string][]string{"defaultNamingContext": {"DC=foreign,DC=com"}}))
		}, auth.ErrDirectory},
		{"bad discovered SID", func(d *LDAP, r *fakeConn) {
			r.results[1] = result(entry("DC=example,DC=com", map[string][]string{"objectSid": {string(rawSID(userSID))}}))
		}, auth.ErrDirectory},
		{"explicit SID mismatch", func(d *LDAP, r *fakeConn) { d.c.DomainSID = "S-1-5-21-4-5-6" }, auth.ErrDirectory},
		{"search base outside domain", func(d *LDAP, r *fakeConn) { d.c.GroupBase = "DC=foreign,DC=com" }, auth.ErrDirectory},
		{"ambiguous user", func(d *LDAP, r *fakeConn) {
			r.results[2].Entries = append(r.results[2].Entries, r.results[2].Entries[0])
		}, auth.ErrDirectory},
		{"lookup permission denied", func(d *LDAP, r *fakeConn) { r.searchErr = ldap.NewError(50, errors.New("denied")) }, auth.ErrDirectory},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, r := userFixture()
			tc.change(d, r)
			_, err := d.Authenticate(context.Background(), auth.Username{Attribute: "userPrincipalName", Value: "alice@example.com"}, "secret", func(string) bool { return true })
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v", err)
			}
			if tc.name == "bad initial credentials" && (r.binds != 1 || len(r.requests) != 0) {
				t.Fatal("rejected user bind retried or used for lookup")
			}
			if tc.name == "canonical confirmation fails" && len(r.requests) != 3 {
				t.Fatal("membership read before canonical password confirmation")
			}
		})
	}
}

func TestNamedLookupFailuresIncludingDeny(t *testing.T) {
	ref := config.GroupRef{Name: "Blocked", Domain: "example.com"}
	for _, tc := range []struct {
		name    string
		entries []*ldap.Entry
	}{
		{"missing", nil},
		{"ambiguous", []*ldap.Entry{entry("CN=a", nil), entry("CN=b", nil)}},
		{"distribution", []*ldap.Entry{entry("CN=a", map[string][]string{"objectSid": {string(rawSID(allowedSID))}, "groupType": {"2"}})}},
		{"foreign", []*ldap.Entry{entry("CN=a", map[string][]string{"objectSid": {string(rawSID("S-1-5-21-4-5-6-1101"))}, "groupType": {"-2147483646"}})}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, r := userFixture()
			r.results = append(r.results, result(tc.entries...))
			_, err := d.Authenticate(auth.WithGroupRefs(context.Background(), []config.GroupRef{ref}), auth.Username{Attribute: "userPrincipalName", Value: "alice@example.com"}, "secret", func(string) bool { return true })
			if !errors.Is(err, auth.ErrDirectory) {
				t.Fatal("unresolved named group did not fail closed", err)
			}
		})
	}
}

func TestUserModeProbeUsesNoCredentials(t *testing.T) {
	d, r := userFixture()
	if err := d.Probe(context.Background()); err != nil || r.binds != 0 || len(r.requests) != 0 {
		t.Fatal("user mode readiness attempted authentication", err)
	}
}

func TestReaderModeCanDiscoverOmittedMetadata(t *testing.T) {
	d, r, u := fixture()
	d.c.Domain = "example.com"
	d.c.UserBase = ""
	d.c.GroupBase = ""
	d.c.DomainSID = ""
	r.results = append([]*ldap.SearchResult{result(entry("", map[string][]string{"defaultNamingContext": {"DC=example,DC=com"}})), result(entry("DC=example,DC=com", map[string][]string{"objectSid": {string(rawSID(domain))}}))}, r.results...)
	if _, err := d.Authenticate(context.Background(), auth.Username{Attribute: "sAMAccountName", Value: "alice"}, "secret", func(string) bool { return true }); err != nil || r.binds != 1 || u.binds != 1 {
		t.Fatal("reader override discovery failed", err)
	}
}

func TestNamedBuiltinGroupAndPermissionFailure(t *testing.T) {
	d, r := userFixture()
	ref := config.GroupRef{Name: "Administrators", Domain: "example.com"}
	r.results = []*ldap.SearchResult{result(entry("CN=Administrators,CN=Builtin,DC=example,DC=com", map[string][]string{"objectSid": {string(rawSID("S-1-5-32-544"))}, "groupType": {"-2147483643"}}))}
	m := metadata{userBase: "DC=example,DC=com", groupBase: "DC=example,DC=com", domainSID: domain}
	resolved, err := d.resolveNamed(r, m, []config.GroupRef{ref})
	if err != nil || resolved[ref.Key()] != "S-1-5-32-544" {
		t.Fatal("built-in group in the selected domain was rejected", err)
	}
	r.searchErr = ldap.NewError(50, errors.New("denied"))
	if _, err := d.resolveNamed(r, m, []config.GroupRef{ref}); !errors.Is(err, auth.ErrDirectory) {
		t.Fatal("permission error did not fail closed")
	}
}
