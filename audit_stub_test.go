//go:build !audit

package arapuca

import (
	"context"
	"strings"
	"testing"
)

// TestAuditCallback_RequiresAuditTag verifies a callback set without
// the audit tag fails the launch instead of silently dropping the
// audit stream.
func TestAuditCallback_RequiresAuditTag(t *testing.T) {
	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	_, err = sb.Launch(context.Background(), Config{
		AuditCallback: func(AuditEvent) {},
	}, trueBin(), nil, nil)
	if err == nil {
		t.Fatal("expected an error for AuditCallback without -tags audit")
	}
	if !strings.Contains(err.Error(), "-tags audit") {
		t.Errorf("expected the error to mention -tags audit, got: %v", err)
	}
}
