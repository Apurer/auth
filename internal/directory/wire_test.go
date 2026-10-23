package directory

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/Apurer/auth/internal/auth"
	"github.com/Apurer/auth/internal/config"
	"github.com/Apurer/auth/internal/testutil"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// ldapFixture serves the LDAP wire protocol over real TLS. It intentionally
// models a tiny directory, not AD's implementation of tokenGroups semantics.
func ldapFixture(t *testing.T) (string, string) {
	t.Helper()
	ca := testutil.NewCA(t)
	cert := ca.Issue(t, "127.0.0.1", true)
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert.TLS}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go serveLDAPFixture(conn)
		}
	}()
	return "ldaps://" + l.Addr().String(), ca.Path
}

func ldapMessage(id int64, op *ber.Packet) *ber.Packet {
	p := ber.NewSequence("message")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "id"))
	p.AppendChild(op)
	return p
}

func ldapResult(id int64, tag ber.Tag, code uint16) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "result")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(code), "code"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matched DN"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnostic"))
	return ldapMessage(id, p)
}

func ldapEntry(id int64, e *ldap.Entry) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "entry")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.DN, "DN"))
	attrs := ber.NewSequence("attributes")
	for _, a := range e.Attributes {
		p := ber.NewSequence("attribute")
		p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a.Name, "name"))
		values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "values")
		for _, b := range a.ByteValues {
			values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(b), "value"))
		}
		p.AppendChild(values)
		attrs.AppendChild(p)
	}
	op.AppendChild(attrs)
	return ldapMessage(id, op)
}

func serveLDAPFixture(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	bound := false
	for {
		packet, err := ber.ReadPacket(c)
		if err != nil || len(packet.Children) < 2 {
			return
		}
		id, _ := packet.Children[0].Value.(int64)
		op := packet.Children[1]
		switch op.Tag {
		case 0:
			name, _ := op.Children[1].Value.(string)
			password := op.Children[2].Data.String()
			bound = password == "secret" && (name == "alice@example.com" || name == "CN=Alice,DC=example,DC=com")
			code := uint16(49)
			if bound {
				code = 0
			}
			if _, err := c.Write(ldapResult(id, 1, code).Bytes()); err != nil {
				return
			}
		case 3:
			if !bound {
				c.Write(ldapResult(id, 5, 50).Bytes())
				continue
			}
			base, _ := op.Children[0].Value.(string)
			scope, _ := op.Children[1].Value.(int64)
			filter, _ := ldap.DecompileFilter(op.Children[6])
			_, fixture, _ := fixture()
			var entries []*ldap.Entry
			switch {
			case base == "":
				entries = []*ldap.Entry{entry("", map[string][]string{"defaultNamingContext": {"DC=example,DC=com"}})}
			case base == "DC=example,DC=com" && scope == 0:
				entries = []*ldap.Entry{entry(base, map[string][]string{"objectSid": {string(rawSID(domain))}})}
			case base == "CN=Alice,DC=example,DC=com":
				entries = fixture.results[1].Entries
			case filter == "(&(objectClass=group)(cn=Orders Users))":
				entries = fixture.results[2].Entries[:1]
			case len(filter) >= len("(&(objectClass=group)") && filter[:len("(&(objectClass=group)")] == "(&(objectClass=group)":
				entries = fixture.results[2].Entries
			default:
				entries = fixture.results[0].Entries
			}
			for _, e := range entries {
				if _, err := c.Write(ldapEntry(id, e).Bytes()); err != nil {
					return
				}
			}
			if _, err := c.Write(ldapResult(id, 5, 0).Bytes()); err != nil {
				return
			}
		default:
			return
		}
	}
}

func TestUserBoundLDAPOverTLSWire(t *testing.T) {
	endpoint, ca := ldapFixture(t)
	d, err := New(config.Directory{Domain: "example.com", BindMode: "user", Endpoints: []string{endpoint}, TLS: config.DirectoryTLS{CAFile: ca}}, 2048, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ref := config.GroupRef{Name: "Orders Users", Domain: "example.com"}
	id, err := d.Authenticate(auth.WithGroupRefs(ctx, []config.GroupRef{ref}), auth.Username{Attribute: "userPrincipalName", Value: "alice@example.com"}, "secret", func(string) bool { return true })
	if err != nil || id.SID != userSID || id.ResolvedGroups[ref.Key()] != allowedSID {
		t.Fatal("LDAP/TLS user-mode integration failed", err)
	}
	if _, err := d.Authenticate(ctx, auth.Username{Attribute: "userPrincipalName", Value: "alice@example.com"}, "wrong", func(string) bool { return true }); err != auth.ErrCredentials {
		t.Fatal("wrong password accepted", err)
	}
}
