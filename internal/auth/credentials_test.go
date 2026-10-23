package auth

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/Apurer/auth/internal/config"
)

func basic(s string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(s)) }

func TestCredentials(t *testing.T) {
	d := config.Directory{NetBIOS: "EXAMPLE", UPNSuffixes: []string{"example.com"}, AllowBareUsername: true}
	for _, tc := range []struct {
		input, attr, user, password string
		err                         error
	}{
		{basic("alice:secret"), "sAMAccountName", "alice", "secret", nil},
		{basic(`EXAMPLE\alice:secret`), "sAMAccountName", "alice", "secret", nil},
		{basic("Alice@EXAMPLE.com:p:a ss "), "userPrincipalName", "Alice@EXAMPLE.com", "p:a ss ", nil},
		{basic("żółć@EXAMPLE.com:密碼"), "userPrincipalName", "żółć@EXAMPLE.com", "密碼", nil},
		{"", "", "", "", ErrCredentials}, {"Bearer token", "", "", "", ErrMalformed},
		{"Basic !!!", "", "", "", ErrMalformed}, {"Basic YQ==,YQ==", "", "", "", ErrMalformed},
		{basic(":secret"), "", "", "", ErrMalformed}, {basic("alice:"), "", "", "", ErrMalformed},
		{basic("alice:s\necret"), "", "", "", ErrMalformed}, {basic("alice\x00:secret"), "", "", "", ErrMalformed},
		{basic("alice@foreign.com:secret"), "", "", "", ErrCredentials},
		{basic(`FOREIGN\alice:secret`), "", "", "", ErrCredentials},
		{basic("alice@x@example.com:secret"), "", "", "", ErrMalformed},
	} {
		t.Run(tc.input[:min(20, len(tc.input))], func(t *testing.T) {
			u, p, err := ParseCredentials(tc.input, d, 8192)
			if !errors.Is(err, tc.err) || u.Attribute != tc.attr || u.Value != tc.user || p != tc.password {
				t.Fatalf("unexpected parse result (error=%v)", err)
			}
		})
	}
	if _, _, err := ParseCredentials(strings.Repeat("a", 100), d, 64); !errors.Is(err, ErrOversized) {
		t.Fatal(err)
	}
	d.AllowBareUsername = false
	if _, _, err := ParseCredentials(basic("alice:secret"), d, 8192); !errors.Is(err, ErrCredentials) {
		t.Fatal(err)
	}
}

func FuzzCredentials(f *testing.F) {
	f.Add(basic("alice:secret"))
	f.Add("Basic !!!")
	f.Fuzz(func(t *testing.T, header string) {
		d := config.Directory{NetBIOS: "D", UPNSuffixes: []string{"example.com"}, AllowBareUsername: true}
		u, p, err := ParseCredentials(header, d, 8192)
		if err == nil && (u.Value == "" || p == "") {
			t.Fatal("empty successful credentials")
		}
	})
}

func TestSimplifiedUsernameNormalization(t *testing.T) {
	d := config.Directory{Domain: "example.com", BindMode: "user", AllowBareUsername: true, UPNSuffixes: []string{"example.com"}}
	u, _, err := ParseCredentials(basic("alice:secret"), d, 8192)
	if err != nil || u.Attribute != "userPrincipalName" || u.Value != "alice@example.com" {
		t.Fatal("bare username not normalized", err)
	}
	d.AllowBareUsername = false
	if _, _, err := ParseCredentials(basic("alice:secret"), d, 8192); err == nil {
		t.Fatal("explicit bare-name disable ignored")
	}
	if _, _, err := ParseCredentials(basic(`EXAMPLE\alice:secret`), d, 8192); err == nil {
		t.Fatal("guessed NetBIOS domain")
	}
}
