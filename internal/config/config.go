// Package config loads a strictly validated, immutable service configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Version      string            `yaml:"version"`
	Listen       string            `yaml:"listen"`
	AdminListen  string            `yaml:"admin_listen"`
	TLS          TLS               `yaml:"tls"`
	Directory    Directory         `yaml:"directory"`
	Mode         string            `yaml:"mode"`
	Policies     map[string]Policy `yaml:"policies"`
	ExportGroups []string          `yaml:"export_groups"`
	Limits       Limits            `yaml:"limits"`
}

type TLS struct {
	Certificate       string   `yaml:"certificate"`
	PrivateKey        string   `yaml:"private_key"`
	ClientCA          string   `yaml:"client_ca"`
	AllowedClientSANs []string `yaml:"allowed_client_sans"`
}

type Directory struct {
	Endpoints          []string `yaml:"endpoints"`
	CAFile             string   `yaml:"ca_file"`
	UserBase           string   `yaml:"user_base"`
	GroupBase          string   `yaml:"group_base"`
	DomainSID          string   `yaml:"domain_sid"`
	NetBIOS            string   `yaml:"netbios"`
	UPNSuffixes        []string `yaml:"upn_suffixes"`
	AllowBareUsername  bool     `yaml:"allow_bare_username"`
	ReaderDN           string   `yaml:"reader_dn"`
	ReaderPasswordFile string   `yaml:"reader_password_file"`
}

type Limits struct {
	Timeout            time.Duration `yaml:"timeout"`
	MaxConcurrent      int           `yaml:"max_concurrent"`
	MaxGroups          int           `yaml:"max_groups"`
	MaxCredentialBytes int           `yaml:"max_credential_bytes"`
	MaxIdentityBytes   int           `yaml:"max_identity_bytes"`
	GlobalPerMinute    int           `yaml:"global_per_minute"`
	SourcePerMinute    int           `yaml:"source_per_minute"`
	AccountPerMinute   int           `yaml:"account_per_minute"`
	MaxRateKeys        int           `yaml:"max_rate_keys"`
}

type Policy struct {
	AnyOf              []string `yaml:"any_of"`
	AllOf              []string `yaml:"all_of"`
	DenyAnyOf          []string `yaml:"deny_any_of"`
	AllowAuthenticated bool     `yaml:"allow_authenticated"`
}

func (p Policy) Allows(groups []string) bool {
	for _, sid := range p.DenyAnyOf {
		if slices.Contains(groups, sid) {
			return false
		}
	}
	for _, sid := range p.AllOf {
		if !slices.Contains(groups, sid) {
			return false
		}
	}
	if len(p.AnyOf) > 0 {
		for _, sid := range p.AnyOf {
			if slices.Contains(groups, sid) {
				return true
			}
		}
		return false
	}
	return p.AllowAuthenticated || len(p.AllOf) > 0
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read configuration")
	}
	return Decode(b)
}

func Decode(b []byte) (*Config, error) {
	c := &Config{Listen: "127.0.0.1:9001", AdminListen: "127.0.0.1:9002", Limits: Limits{
		Timeout: 1800 * time.Millisecond, MaxConcurrent: 16, MaxGroups: 2048,
		MaxCredentialBytes: 8192, MaxIdentityBytes: 8192,
		GlobalPerMinute: 600, SourcePerMinute: 120, AccountPerMinute: 30, MaxRateKeys: 10000,
	}}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(c); err != nil {
		return nil, errors.New("invalid configuration YAML or unknown field")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, errors.New("configuration must contain one YAML document")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) Validate() error {
	if c.Version == "" || len(c.Version) > 128 {
		return errors.New("version is required and must be at most 128 bytes")
	}
	if c.Mode != "enrichment" && c.Mode != "group_policy" {
		return errors.New("mode must be enrichment or group_policy")
	}
	if c.Listen == "" {
		return errors.New("listen is required")
	}
	if strings.HasPrefix(c.Listen, "unix:") {
		if !strings.HasPrefix(strings.TrimPrefix(c.Listen, "unix:"), "/") {
			return errors.New("unix socket requires an absolute path")
		}
	} else {
		if _, _, err := net.SplitHostPort(c.Listen); err != nil {
			return errors.New("listen must be host:port or unix:/absolute/path")
		}
		if c.TLS.Certificate == "" || c.TLS.PrivateKey == "" || c.TLS.ClientCA == "" || len(c.TLS.AllowedClientSANs) == 0 {
			return errors.New("TCP listener requires mTLS files and allowed_client_sans")
		}
	}
	h, _, err := net.SplitHostPort(c.AdminListen)
	if err != nil || net.ParseIP(h) == nil || !net.ParseIP(h).IsLoopback() {
		return errors.New("admin_listen must use a loopback IP")
	}
	d := c.Directory
	if len(d.Endpoints) == 0 || len(d.Endpoints) > 16 {
		return errors.New("configure 1 to 16 LDAPS endpoints")
	}
	for _, endpoint := range d.Endpoints {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "ldaps" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("directory endpoints must be ldaps://host[:port] without credentials or paths")
		}
		if u.Port() != "" {
			if _, err := net.LookupPort("tcp", u.Port()); err != nil {
				return errors.New("invalid LDAPS port")
			}
		}
	}
	if d.CAFile == "" || d.ReaderDN == "" || d.ReaderPasswordFile == "" || d.NetBIOS == "" || len(d.UPNSuffixes) == 0 {
		return errors.New("directory CA, reader, domain and UPN suffixes are required")
	}
	if !ValidSID(d.DomainSID) || len(strings.Split(d.DomainSID, "-")) != 7 || !strings.HasPrefix(d.DomainSID, "S-1-5-21-") {
		return errors.New("domain_sid must be a canonical AD domain SID")
	}
	for _, dn := range []string{d.UserBase, d.GroupBase, d.ReaderDN} {
		if parsed, err := ldap.ParseDN(dn); err != nil || len(parsed.RDNs) == 0 {
			return errors.New("invalid directory distinguished name")
		}
	}
	for _, s := range d.UPNSuffixes {
		if s == "" || strings.ContainsAny(s, "@\\ /\t\r\n") {
			return errors.New("invalid UPN suffix")
		}
	}
	if strings.ContainsAny(d.NetBIOS, "@\\ /\t\r\n") {
		return errors.New("invalid NetBIOS domain")
	}
	l := c.Limits
	if l.Timeout < 10*time.Millisecond || l.Timeout > 30*time.Second {
		return errors.New("timeout must be between 10ms and 30s")
	}
	if l.MaxConcurrent < 1 || l.MaxConcurrent > 1024 || l.MaxGroups < 1 || l.MaxGroups > 10000 || l.MaxCredentialBytes < 64 || l.MaxCredentialBytes > 32768 || l.MaxIdentityBytes < 64 || l.MaxIdentityBytes > 32768 || l.GlobalPerMinute < 1 || l.SourcePerMinute < 1 || l.AccountPerMinute < 1 || l.MaxRateKeys < 1 || l.MaxRateKeys > 1000000 {
		return errors.New("invalid request or admission limits")
	}
	for name, p := range c.Policies {
		if name == "" || len(name) > 128 {
			return errors.New("invalid policy ID")
		}
		if len(p.AnyOf) == 0 && len(p.AllOf) == 0 && !p.AllowAuthenticated {
			return fmt.Errorf("policy %q needs a positive condition or allow_authenticated", name)
		}
		if p.AllowAuthenticated && (len(p.AnyOf) > 0 || len(p.AllOf) > 0) {
			return fmt.Errorf("policy %q mixes allow_authenticated and positive groups", name)
		}
		for _, list := range [][]string{p.AnyOf, p.AllOf, p.DenyAnyOf} {
			for _, sid := range list {
				if !ValidSID(sid) {
					return errors.New("policy contains an invalid SID")
				}
			}
		}
		for _, sid := range append(slices.Clone(p.AnyOf), p.AllOf...) {
			if slices.Contains(p.DenyAnyOf, sid) {
				return fmt.Errorf("policy %q has contradictory groups", name)
			}
		}
	}
	if c.Mode == "group_policy" && len(c.Policies) == 0 {
		return errors.New("group_policy mode requires policies")
	}
	for _, sid := range c.ExportGroups {
		if !ValidSID(sid) {
			return errors.New("export_groups contains an invalid SID")
		}
	}
	return nil
}

func ValidSID(s string) bool {
	p := strings.Split(s, "-")
	if len(p) < 4 || len(p) > 18 || p[0] != "S" || p[1] != "1" {
		return false
	}
	for i, v := range p[2:] {
		if v == "" || (len(v) > 1 && v[0] == '0') {
			return false
		}
		var n uint64
		for _, r := range v {
			if r < '0' || r > '9' {
				return false
			}
			if n > 281474976710655/10 {
				return false
			}
			n = n*10 + uint64(r-'0')
		}
		if (i == 0 && n > 281474976710655) || (i > 0 && n > 4294967295) {
			return false
		}
	}
	return true
}
