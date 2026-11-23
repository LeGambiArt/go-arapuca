package arapuca

import (
	"encoding/json"
	"unsafe"
)

// AuditEvent is one audit event emitted during a sandbox lifecycle,
// delivered to a Config.AuditCallback handler.
//
// EventType is the upstream variant name (for example "SandboxInit",
// "SandboxReady", "FileAccess"); it is empty for the library's
// serialization-failure sentinel. Timestamp is monotonic nanoseconds
// since sandbox creation, NOT wall-clock time: anchor it with the
// wall_clock_epoch_ns field inside the SandboxInit payload. Payload
// is the complete event JSON, preserved verbatim, so a consumer can
// decode variant-specific fields or forward the bytes to a sink.
type AuditEvent struct {
	EventType string          `json:"event_type"`
	Timestamp uint64          `json:"timestamp"`
	Payload   json.RawMessage `json:"-"`
}

// auditRegistration ties a launched process to its audit-callback
// registry entry and the C-allocated slot holding the key. The zero
// value means "not registered".
type auditRegistration struct {
	key  uint64
	slot unsafe.Pointer
}
