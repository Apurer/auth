package auth

import (
	"context"
	"slices"

	"github.com/Apurer/auth/internal/config"
)

type groupContextKey struct{}

// WithGroupRefs carries only the selected server-controlled policy's lookup
// requirements. LDAP adapters must not accept these references from clients.
func WithGroupRefs(ctx context.Context, refs []config.GroupRef) context.Context {
	return context.WithValue(ctx, groupContextKey{}, slices.Clone(refs))
}

func RequestedGroups(ctx context.Context) []config.GroupRef {
	refs, _ := ctx.Value(groupContextKey{}).([]config.GroupRef)
	return slices.Clone(refs)
}
