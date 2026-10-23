package integration

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Apurer/auth/internal/auth"
	"github.com/Apurer/auth/internal/config"
	"github.com/Apurer/auth/internal/directory"
)

// TestLiveAD requires a disposable AD test account. Passwords are read from a
// file and neither credentials nor directory diagnostics are printed.
func TestLiveAD(t *testing.T) {
	path := os.Getenv("AUTH_AD_CONFIG")
	if path == "" {
		t.Skip("set AUTH_AD_CONFIG and fixture variables for live AD acceptance")
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	d, err := directory.New(c.Directory, c.Limits.MaxGroups, nil)
	if err != nil {
		t.Fatal(err)
	}
	user, err := auth.ParseUsername(os.Getenv("AUTH_AD_USERNAME"), c.Directory)
	if err != nil {
		t.Fatal("invalid test username")
	}
	password, err := os.ReadFile(os.Getenv("AUTH_AD_PASSWORD_FILE"))
	if err != nil || len(password) == 0 {
		t.Fatal("test password file required")
	}
	defer clear(password)
	expected := strings.Split(os.Getenv("AUTH_AD_EXPECT_GROUPS"), ",")
	if len(expected) == 0 || expected[0] == "" {
		t.Fatal("AUTH_AD_EXPECT_GROUPS requires expected nested and primary SIDs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.Limits.Timeout)
	defer cancel()
	id, err := d.Authenticate(ctx, user, string(password), func(string) bool { return true })
	if err != nil {
		t.Fatal("live AD authentication or group resolution failed")
	}
	for _, sid := range expected {
		if !slices.Contains(id.Groups, sid) {
			t.Error("an expected fixture group was not returned")
		}
	}
}
