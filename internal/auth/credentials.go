package auth

import (
	"encoding/base64"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Apurer/auth/internal/config"
)

var (
	ErrCredentials = errors.New("authentication failed")
	ErrMalformed   = errors.New("malformed credentials")
	ErrOversized   = errors.New("credentials too large")
	ErrDirectory   = errors.New("directory unavailable")
	ErrRateLimited = errors.New("admission limit exceeded")
)

// Username carries only a validated LDAP attribute name and an unescaped value.
// The directory adapter MUST escape Value before placing it in a filter.
type Username struct{ Attribute, Value string }

func ParseCredentials(header string, d config.Directory, maxBytes int) (Username, string, error) {
	if len(header) > maxBytes {
		return Username{}, "", ErrOversized
	}
	if header == "" {
		return Username{}, "", ErrCredentials
	}
	scheme, encoded, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") || strings.ContainsAny(encoded, " \t\r\n,") {
		return Username{}, "", ErrMalformed
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || !utf8.Valid(raw) {
		return Username{}, "", ErrMalformed
	}
	defer clear(raw)
	name, password, ok := strings.Cut(string(raw), ":")
	if !ok || name == "" || password == "" {
		return Username{}, "", ErrMalformed
	}
	for _, r := range name + password {
		if unicode.IsControl(r) {
			return Username{}, "", ErrMalformed
		}
	}
	u, err := ParseUsername(name, d)
	if err != nil {
		return Username{}, "", err
	}
	return u, password, nil
}

func ParseUsername(name string, d config.Directory) (Username, error) {
	if name == "" || strings.TrimSpace(name) != name {
		return Username{}, ErrMalformed
	}
	if strings.Contains(name, "\\") {
		prefix, user, _ := strings.Cut(name, "\\")
		if !strings.EqualFold(prefix, d.NetBIOS) || user == "" || strings.ContainsAny(user, "\\@") {
			return Username{}, ErrCredentials
		}
		return Username{"sAMAccountName", user}, nil
	}
	if strings.Contains(name, "@") {
		user, suffix, _ := strings.Cut(name, "@")
		if user == "" || strings.Contains(suffix, "@") {
			return Username{}, ErrMalformed
		}
		for _, allowed := range d.UPNSuffixes {
			if strings.EqualFold(suffix, allowed) {
				return Username{"userPrincipalName", name}, nil
			}
		}
		return Username{}, ErrCredentials
	}
	if !d.AllowBareUsername {
		return Username{}, ErrCredentials
	}
	if d.Domain != "" && d.EffectiveBindMode() == "user" {
		return Username{"userPrincipalName", name + "@" + d.Domain}, nil
	}
	return Username{"sAMAccountName", name}, nil
}
