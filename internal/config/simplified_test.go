package config

import (
	"os"
	"strings"
	"testing"
)

func minimal(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../examples/auth-minimal.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestMinimalDefaultsAndLegacyCompatibility(t *testing.T) {
	c, err := Decode([]byte(minimal(t)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Directory.EffectiveBindMode() != "user" || !c.Directory.AllowBareUsername || c.Directory.UPNSuffixes[0] != "example.com" {
		t.Fatal("incorrect simplified defaults")
	}
	if c.Directory.TLS.InsecureSkipVerify || c.Directory.EffectiveCAFile() != "" || c.Directory.ReaderPasswordFile != "" {
		t.Fatal("insecure or secret defaults")
	}
	g := c.Policies["orders"].AnyOf[0]
	if g.Name != "Orders Users" || g.Domain != "example.com" {
		t.Fatal("group domain was not defaulted")
	}
	legacy, err := Decode(example(t))
	if err != nil || legacy.Directory.EffectiveBindMode() != "reader" {
		t.Fatal("legacy reader mode is not compatible", err)
	}
}

func TestStrictSimplifiedConfiguration(t *testing.T) {
	for _, tc := range []struct{ name, old, new string }{
		{"unknown named field", "name: Orders Users", "nmae: Orders Users"},
		{"duplicate named field", "name: Orders Users", "name: Orders Users\n        name: Other"},
		{"ambiguous reference", "name: Orders Users", "name: Orders Users\n        sid: S-1-5-32-544"},
		{"empty name", "name: Orders Users", "name: ''"},
		{"foreign group", "name: Orders Users", "name: Orders Users\n        domain: foreign.example.com"},
		{"missing domain", "domain: example.com", "domain: ''"},
		{"invalid domain", "domain: example.com", "domain: bad/domain"},
		{"invalid bind mode", "domain: example.com", "domain: example.com\n  bind_mode: anonymous"},
		{"partial reader", "domain: example.com", "domain: example.com\n  reader_dn: CN=reader,DC=example,DC=com"},
		{"mixed user and reader", "domain: example.com", "domain: example.com\n  bind_mode: user\n  reader_dn: CN=reader,DC=example,DC=com\n  reader_password_file: /secret"},
		{"unknown TLS field", "domain: example.com", "domain: example.com\n  tls:\n    insecure: true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decode([]byte(strings.Replace(minimal(t), tc.old, tc.new, 1))); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestNamedPolicyFailClosed(t *testing.T) {
	allow := GroupRef{Name: "Allowed", Domain: "example.com"}
	deny := GroupRef{Name: "Blocked", Domain: "example.com"}
	p := Policy{AnyOf: []GroupRef{allow}, DenyAnyOf: []GroupRef{deny}}
	a, b := "S-1-5-32-544", "S-1-5-32-545"
	if p.Allows([]string{a}, map[string]string{allow.Key(): a}) {
		t.Fatal("unresolved deny group ignored")
	}
	resolved := map[string]string{allow.Key(): a, deny.Key(): b}
	if !p.Allows([]string{a}, resolved) || p.Allows([]string{a, b}, resolved) {
		t.Fatal("named allow/deny precedence")
	}
	if p.ValidateResolved(map[string]string{allow.Key(): "invalid", deny.Key(): b}) {
		t.Fatal("invalid resolved SID accepted")
	}
}
