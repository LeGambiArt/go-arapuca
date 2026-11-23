//go:build audit

package arapuca

/*
#include <stdint.h>
*/
import "C"

import (
	"encoding/json"
	"sync"
	"unsafe"
)

// auditRegistry maps registration keys to live handlers. Keys come
// from a monotonically increasing counter and are never reused, so a
// late in-flight callback after release can never dispatch to a new
// handler.
var auditRegistry = struct {
	mu       sync.Mutex
	nextKey  uint64
	handlers map[uint64]func(AuditEvent)
}{handlers: make(map[uint64]func(AuditEvent))}

func registerAuditHandler(h func(AuditEvent)) uint64 {
	auditRegistry.mu.Lock()
	defer auditRegistry.mu.Unlock()
	auditRegistry.nextKey++
	key := auditRegistry.nextKey
	auditRegistry.handlers[key] = h
	return key
}

func lookupAuditHandler(key uint64) func(AuditEvent) {
	auditRegistry.mu.Lock()
	defer auditRegistry.mu.Unlock()
	return auditRegistry.handlers[key]
}

func unregisterAuditHandler(key uint64) {
	auditRegistry.mu.Lock()
	defer auditRegistry.mu.Unlock()
	delete(auditRegistry.handlers, key)
}

// goAuditTrampoline is the C-visible callback passed to
// arapuca_config_set_audit_callback. The event buffer is valid only
// for the duration of the call, so it is copied before dispatch, and
// a panic must never cross back into C.
//
//export goAuditTrampoline
func goAuditTrampoline(eventJSON *C.char, eventJSONLen C.uintptr_t, userData unsafe.Pointer) {
	defer func() { _ = recover() }()
	if eventJSON == nil || userData == nil {
		return
	}
	key := uint64(*(*C.uint64_t)(userData))
	handler := lookupAuditHandler(key)
	if handler == nil {
		return
	}
	buf := C.GoBytes(unsafe.Pointer(eventJSON), C.int(eventJSONLen))
	var env struct {
		EventType string `json:"event_type"`
		Timestamp uint64 `json:"timestamp"`
	}
	_ = json.Unmarshal(buf, &env)
	handler(AuditEvent{
		EventType: env.EventType,
		Timestamp: env.Timestamp,
		Payload:   json.RawMessage(buf),
	})
}
