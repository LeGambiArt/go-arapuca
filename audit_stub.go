//go:build !audit

package arapuca

/*
#include <arapuca.h>
*/
import "C"

import "errors"

// setAuditCallback errors on any callback when built without the
// audit tag: silently dropping an audit stream a caller asked for is
// a security-relevant silent failure, not a graceful degradation.
func setAuditCallback(_ *C.struct_arapuca_ArapucaConfig, _ func(AuditEvent)) (auditRegistration, error) {
	return auditRegistration{}, errors.New("arapuca: Config.AuditCallback requires building with -tags audit (and libarapuca.a installed with serde)")
}

// releaseAuditRegistration is a no-op without the audit tag: the stub
// setter never produces a registration.
func releaseAuditRegistration(auditRegistration) {}
