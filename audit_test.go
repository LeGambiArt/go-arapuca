//go:build audit

package arapuca

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// collectAuditEvents launches trueBin with an audit callback and
// returns every event observed through Cleanup. Synchronous delivery
// means the slice is complete once Cleanup returns.
func collectAuditEvents(t *testing.T, cfg Config) ([]AuditEvent, error) {
	t.Helper()

	var mu sync.Mutex
	var events []AuditEvent
	cfg.AuditCallback = func(e AuditEvent) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	}

	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proc, err := sb.Launch(ctx, cfg, trueBin(), nil, nil)
	if err != nil {
		return nil, err
	}
	if _, err := proc.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	proc.Cleanup()

	mu.Lock()
	defer mu.Unlock()
	return events, nil
}

// TestAuditCallback_EventsDuringLifecycle verifies the event stream of
// a plain launch: SandboxInit first, SandboxReady and ProcessStarted
// in between, SandboxCleanup last — all present once Cleanup returns,
// which is the synchronous-delivery oracle — with a consistent
// envelope on every event and monotonic timestamps.
func TestAuditCallback_EventsDuringLifecycle(t *testing.T) {
	if WrapperPath() == "" {
		t.Skip("arapuca wrapper binary not found")
	}

	events, err := collectAuditEvents(t, Config{
		TaskID:  "audit-events",
		Profile: Profile{ReadPaths: []string{"/usr", "/lib", "/lib64", "/bin"}},
	})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected audit events, got none")
	}

	kinds := make(map[string]int)
	for i, e := range events {
		if e.EventType == "" {
			t.Errorf("event %d has an empty EventType (serialization-failure sentinel should not occur here)", i)
		}
		var raw map[string]any
		if err := json.Unmarshal(e.Payload, &raw); err != nil {
			t.Errorf("event %d payload is not valid JSON: %v", i, err)
		} else if raw["event_type"] != e.EventType {
			t.Errorf("event %d envelope EventType %q disagrees with payload %v", i, e.EventType, raw["event_type"])
		}
		if i > 0 && events[i-1].Timestamp > e.Timestamp {
			t.Errorf("timestamps not monotonic at event %d: %d after %d", i, e.Timestamp, events[i-1].Timestamp)
		}
		kinds[e.EventType]++
	}

	if events[0].EventType != "SandboxInit" {
		t.Errorf("first event is %q, want SandboxInit", events[0].EventType)
	}
	for _, want := range []string{"SandboxReady", "ProcessStarted", "SandboxCleanup"} {
		if kinds[want] == 0 {
			t.Errorf("expected a %s event, kinds seen: %v", want, kinds)
		}
	}
	if last := events[len(events)-1].EventType; last != "SandboxCleanup" {
		t.Errorf("last event is %q, want SandboxCleanup", last)
	}
}

// TestAuditCallback_RegistryReleased verifies the registration is gone
// once Cleanup has returned — no handler leak per launch.
func TestAuditCallback_RegistryReleased(t *testing.T) {
	if WrapperPath() == "" {
		t.Skip("arapuca wrapper binary not found")
	}

	_, err := collectAuditEvents(t, Config{
		TaskID:  "audit-registry-release",
		Profile: Profile{ReadPaths: []string{"/usr", "/lib", "/lib64", "/bin"}},
	})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}

	auditRegistry.mu.Lock()
	defer auditRegistry.mu.Unlock()
	if len(auditRegistry.handlers) != 0 {
		t.Errorf("registry still holds %d handlers after Cleanup", len(auditRegistry.handlers))
	}
}

// TestAuditCallback_LaunchErrorReleasesRegistration verifies a failed
// launch does not leak the registration it set up beforehand.
func TestAuditCallback_LaunchErrorReleasesRegistration(t *testing.T) {
	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	// UseUserNS+UseNetNS fails the library's launch validation.
	_, err = sb.Launch(context.Background(), Config{
		Profile:       Profile{UseUserNS: true, UseNetNS: true},
		AuditCallback: func(AuditEvent) {},
	}, trueBin(), nil, nil)
	if err == nil {
		t.Fatal("expected the launch to fail")
	}

	auditRegistry.mu.Lock()
	defer auditRegistry.mu.Unlock()
	if len(auditRegistry.handlers) != 0 {
		t.Errorf("registry still holds %d handlers after a failed launch", len(auditRegistry.handlers))
	}
}
