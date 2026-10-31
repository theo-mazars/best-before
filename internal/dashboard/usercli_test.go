package dashboard

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/theo-mazars/best-before/internal/dashboard/store"
)

// The interactive commands (add, reset-password, reset-totp) need a terminal
// and are exercised by hand; these cover the rest.
func TestUserCLI(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	var out bytes.Buffer
	cli := &UserCLI{Config: Config{DataDir: dir}, In: os.Stdin, Out: &out}

	st, err := cli.open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st.CreateUser(ctx, "admin@example.org", "x", store.RoleAdmin, make([]byte, 20), time.Now())
	st.CreateUser(ctx, "user@example.org", "x", store.RoleUser, nil, time.Now())
	st.Close()

	if err := cli.List(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "admin@example.org") || !strings.Contains(out.String(), "missing") {
		t.Errorf("list:\n%s", out.String())
	}

	if err := cli.SetRole(ctx, "user@example.org", "superuser"); err == nil {
		t.Error("unknown role accepted")
	}
	if err := cli.SetRole(ctx, "admin@example.org", store.RoleUser); err == nil || !strings.Contains(err.Error(), "last admin") {
		t.Errorf("demoting the last admin: %v", err)
	}
	if err := cli.SetRole(ctx, "user@example.org", store.RoleAdmin); err != nil {
		t.Error(err)
	}
	if err := cli.Delete(ctx, "nobody@example.org", true); err == nil {
		t.Error("deleting an unknown user succeeded")
	}
	if err := cli.Delete(ctx, "admin@example.org", false); err == nil {
		t.Error("deleted without confirmation outside a terminal")
	}
	out.Reset()
	if err := cli.Delete(ctx, "admin@example.org", true); err != nil || !strings.Contains(out.String(), "has been deleted") {
		t.Errorf("delete: %v, %s", err, out.String())
	}
}
