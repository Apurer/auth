package config

import (
	"errors"
	"slices"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// GroupRef accepts a scalar SID or an explicit name/domain mapping. Names are
// resolved within the configured AD domain on the request's authenticated LDAP
// connection; they are never treated as proof of membership by themselves.
type GroupRef struct {
	SID    string `yaml:"sid"`
	Name   string `yaml:"name"`
	Domain string `yaml:"domain"`
}

func (g *GroupRef) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode && n.Tag == "!!str" {
		g.SID = n.Value
		return nil
	}
	if n.Kind != yaml.MappingNode {
		return errors.New("group must be a SID or a name/domain mapping")
	}
	seen := map[string]bool{}
	for i := 0; i < len(n.Content); i += 2 {
		key, value := n.Content[i], n.Content[i+1]
		if seen[key.Value] || value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
			return errors.New("invalid group reference")
		}
		seen[key.Value] = true
		switch key.Value {
		case "sid":
			g.SID = value.Value
		case "name":
			g.Name = value.Value
		case "domain":
			g.Domain = value.Value
		default:
			return errors.New("unknown group reference field")
		}
	}
	return nil
}

func (g GroupRef) Key() string {
	if g.SID != "" {
		return g.SID
	}
	return strings.ToLower(g.Domain) + "\x00" + strings.ToLower(g.Name)
}

func SIDs(sids ...string) []GroupRef {
	out := make([]GroupRef, len(sids))
	for i, sid := range sids {
		out[i] = GroupRef{SID: sid}
	}
	return out
}

func (g GroupRef) Validate(domain string) error {
	if g.SID != "" {
		if !ValidSID(g.SID) || g.Name != "" || g.Domain != "" {
			return errors.New("invalid SID group reference")
		}
		return nil
	}
	if g.Name == "" || len(g.Name) > 256 || strings.TrimSpace(g.Name) != g.Name {
		return errors.New("group name is required")
	}
	for _, r := range g.Name {
		if unicode.IsControl(r) {
			return errors.New("invalid group name")
		}
	}
	if domain == "" || !strings.EqualFold(g.Domain, domain) {
		return errors.New("named groups must belong to the configured directory domain")
	}
	return nil
}

func (p Policy) NamedGroups() []GroupRef {
	var refs []GroupRef
	for _, list := range [][]GroupRef{p.AnyOf, p.AllOf, p.DenyAnyOf} {
		for _, g := range list {
			if g.Name != "" && !slices.Contains(refs, g) {
				refs = append(refs, g)
			}
		}
	}
	return refs
}

// ValidateResolved checks deny groups as well as allow groups. An unreadable
// deny group must never silently disappear from an authorization decision.
func (p Policy) ValidateResolved(resolved map[string]string) bool {
	for _, g := range p.NamedGroups() {
		if !ValidSID(resolved[g.Key()]) {
			return false
		}
	}
	return true
}
