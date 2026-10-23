package directory

import (
	"strconv"
	"strings"

	"github.com/Apurer/auth/internal/auth"
	"github.com/Apurer/auth/internal/config"
	"github.com/go-ldap/ldap/v3"
)

func securityGroupSID(e *ldap.Entry) (string, error) {
	for _, a := range e.Attributes {
		if strings.Contains(strings.ToLower(a.Name), ";range=") {
			return "", auth.ErrDirectory
		}
	}
	sid, err := DecodeSID(e.GetRawAttributeValue("objectSid"))
	if err != nil || len(e.GetRawAttributeValues("sIDHistory")) > 0 {
		return "", auth.ErrDirectory
	}
	kind, err := strconv.ParseInt(e.GetAttributeValue("groupType"), 10, 64)
	if err != nil || kind&0x80000000 == 0 {
		return "", auth.ErrDirectory
	}
	return sid, nil
}

type metadata struct{ userBase, groupBase, domainSID string }

func (d *LDAP) discover(c connection, force bool) (metadata, error) {
	m := metadata{d.c.UserBase, d.c.GroupBase, d.c.DomainSID}
	if !force && m.userBase != "" && m.groupBase != "" && m.domainSID != "" {
		return m, nil
	}
	r, err := d.search(c, "", ldap.ScopeBaseObject, "(objectClass=*)", []string{"defaultNamingContext"}, 1, "discovery")
	if err != nil || len(r.Entries) != 1 {
		return m, auth.ErrDirectory
	}
	base := r.Entries[0].GetAttributeValue("defaultNamingContext")
	dn, err := ldap.ParseDN(base)
	if err != nil || len(dn.RDNs) == 0 {
		return m, auth.ErrDirectory
	}
	var labels []string
	for _, rdn := range dn.RDNs {
		if len(rdn.Attributes) != 1 || !strings.EqualFold(rdn.Attributes[0].Type, "DC") {
			return m, auth.ErrDirectory
		}
		labels = append(labels, rdn.Attributes[0].Value)
	}
	if !strings.EqualFold(strings.Join(labels, "."), d.c.Domain) {
		return m, auth.ErrDirectory
	}
	if m.userBase == "" {
		m.userBase = base
	}
	if m.groupBase == "" {
		m.groupBase = base
	}
	for _, value := range []string{m.userBase, m.groupBase} {
		child, err := ldap.ParseDN(value)
		if err != nil || !(dn.EqualFold(child) || dn.AncestorOfFold(child)) {
			return m, auth.ErrDirectory
		}
	}
	r, err = d.search(c, base, ldap.ScopeBaseObject, "(objectClass=domainDNS)", []string{"objectSid"}, 1, "discovery")
	if err != nil || len(r.Entries) != 1 {
		return m, auth.ErrDirectory
	}
	sid, err := DecodeSID(r.Entries[0].GetRawAttributeValue("objectSid"))
	if err != nil || !config.ValidSID(sid) || !strings.HasPrefix(sid, "S-1-5-21-") || len(strings.Split(sid, "-")) != 7 {
		return m, auth.ErrDirectory
	}
	if m.domainSID != "" && m.domainSID != sid {
		return m, auth.ErrDirectory
	}
	m.domainSID = sid
	return m, nil
}

func (d *LDAP) resolveNamed(c connection, m metadata, refs []config.GroupRef) (map[string]string, error) {
	resolved := make(map[string]string, len(refs))
	if len(refs) > 256 {
		return nil, auth.ErrDirectory
	}
	for _, ref := range refs {
		if err := ref.Validate(d.c.Domain); err != nil || ref.Name == "" {
			return nil, auth.ErrDirectory
		}
		if _, ok := resolved[ref.Key()]; ok {
			continue
		}
		// Match CN rather than fuzzy display names; duplicated names fail closed.
		filter := "(&(objectClass=group)(cn=" + ldap.EscapeFilter(ref.Name) + "))"
		r, err := d.search(c, m.groupBase, ldap.ScopeWholeSubtree, filter, []string{"objectSid", "groupType", "sIDHistory"}, 2, "group_resolution")
		if err != nil || len(r.Entries) != 1 {
			return nil, auth.ErrDirectory
		}
		e := r.Entries[0]
		sid, err := securityGroupSID(e)
		inDomain := strings.HasPrefix(sid, m.domainSID+"-") && len(strings.Split(sid, "-")) == 8
		builtin := strings.HasPrefix(sid, "S-1-5-32-") && len(strings.Split(sid, "-")) == 5
		if err != nil || !(inDomain || builtin) {
			return nil, auth.ErrDirectory
		}
		resolved[ref.Key()] = sid
	}
	return resolved, nil
}
