package config

import (
	"os"
	"strings"
	"testing"
)

func example(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../examples/auth.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestExampleAndStrictValidation(t *testing.T) {
	b := example(t)
	if _, err := Decode(b); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, old, new string }{
		{"unknown field", "version: v1", "versoin: v1"},
		{"plaintext LDAP", "ldaps://dc1", "ldap://dc1"},
		{"URL credentials", "ldaps://dc1", "ldaps://user:password@dc1"},
		{"public admin", "127.0.0.1:9002", "0.0.0.0:9002"},
		{"bad domain SID", "S-1-5-21-111111111-222222222-333333333\n", "S-1-5-21-1\n"},
		{"zero limit", "max_concurrent: 16", "max_concurrent: 0"},
		{"bad timeout", "timeout: 1800ms", "timeout: 0s"},
		{"bad mode", "mode: group_policy", "mode: permissive"},
		{"missing policy condition", "any_of:", "deny_any_of:"},
		{"invalid DN", "user_base: DC=example,DC=com", "user_base: not-a-dn"},
		{"missing allowed Envoy identities", "allowed_client_sans: [envoy.example.com]", "allowed_client_sans: []"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decode([]byte(strings.ReplaceAll(string(b), tc.old, tc.new))); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
	if _, err := Decode(append(b, []byte("\n---\nversion: other\n")...)); err == nil {
		t.Fatal("multiple documents accepted")
	}
}

func TestPolicySemantics(t *testing.T) {
	for _, tc := range []struct {
		name   string
		p      Policy
		groups []string
		want   bool
	}{
		{"one allowed", Policy{AnyOf: SIDs("a", "b")}, []string{"b"}, true},
		{"nested result allowed", Policy{AnyOf: SIDs("a")}, []string{"child", "a"}, true},
		{"none allowed", Policy{AnyOf: SIDs("a")}, []string{"other"}, false},
		{"all required", Policy{AllOf: SIDs("a", "b")}, []string{"a"}, false},
		{"all matched", Policy{AllOf: SIDs("a", "b")}, []string{"b", "a"}, true},
		{"deny precedence", Policy{AnyOf: SIDs("a"), DenyAnyOf: SIDs("blocked")}, []string{"a", "blocked"}, false},
		{"all and any", Policy{AnyOf: SIDs("a"), AllOf: SIDs("b")}, []string{"a"}, false},
		{"authenticated", Policy{AllowAuthenticated: true}, nil, true},
		{"empty denied", Policy{}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.Allows(tc.groups); got != tc.want {
				t.Fatalf("got %v", got)
			}
		})
	}
}

func TestSIDValidation(t *testing.T) {
	for _, s := range []string{"S-1-5-32-545", "S-1-5-21-1-2-3-1101", "S-1-281474976710655-4294967295"} {
		if !ValidSID(s) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"", "S-1-5", "S-2-5-1", "S-1-5-01", "S-1-5--1", "S-1-5-4294967296", "S-1-281474976710656-1", "S-1-5-99999999999999999999"} {
		if ValidSID(s) {
			t.Fatal(s)
		}
	}
}
