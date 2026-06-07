// Package otavalidator implements the server-side OTA artifact upload
// validation pipeline specified in
// docs/research/main_specs/1.0.0-mvp/server/artifact_validation.md (the S1..S6
// ordered decision table) and the signing/verification rules in
// security/signing_verification.md.
//
// The package is a pure library: it operates on bytes / io.Reader / interface
// ports only. It performs no disk, network, HTTP, or database access — the
// caller (the control-plane upload handler, or CI) supplies all inputs and
// implements the lookup ports. This keeps the validator decoupled and
// independently testable (HelixConstitution §11.4.28).
//
// Each stage is a composable validator returning a typed Verdict carrying a
// stable RejectCode. The top-level Validate function runs the ordered,
// fail-fast pipeline and returns the first rejecting verdict with its code.
package otavalidator

// Stage identifies an ordered pipeline stage (S1..S6) from the decision table.
// S1 (structure / ZIP_STORED parsing) is out of scope for this pure-bytes
// library — it is handled by the upload handler's archive reader — so the
// stages implemented here are S2..S6.
type Stage string

const (
	// StageHash is S2 — SHA-256 vs hash file.
	StageHash Stage = "S2"
	// StageSignature is S3 — detached signature verification.
	StageSignature Stage = "S3"
	// StageVersion is S4 — version monotonicity.
	StageVersion Stage = "S4"
	// StageTarget is S5 — target compatibility (os_type / board).
	StageTarget Stage = "S5"
	// StageMetadata is S6 — metadata sanity.
	StageMetadata Stage = "S6"
)

// RejectCode is a stable, operator-actionable reason a stage rejected an
// artifact. Codes mirror the decision table in artifact_validation.md §5 and
// leak no key material.
type RejectCode string

const (
	// S2 — SHA-256 vs hash file.
	RejectHashFileMissing   RejectCode = "S2_HASH_FILE_MISSING"
	RejectHashFileMalformed RejectCode = "S2_HASH_FILE_MALFORMED"
	RejectHashMismatch      RejectCode = "S2_HASH_MISMATCH"

	// S3 — signature.
	RejectSignatureMissing       RejectCode = "S3_SIGNATURE_MISSING"
	RejectSignatureKeyInvalid    RejectCode = "S3_SIGNATURE_KEY_INVALID"
	RejectSignatureInvalid       RejectCode = "S3_SIGNATURE_INVALID"
	RejectSignatureScopeMismatch RejectCode = "S3_SIGNATURE_SCOPE_MISMATCH"

	// S4 — version monotonicity.
	RejectVersionUnparseable RejectCode = "S4_VERSION_UNPARSEABLE"
	RejectNotMonotonic       RejectCode = "S4_NOT_MONOTONIC"
	RejectDuplicateVersion   RejectCode = "S4_DUPLICATE_VERSION"

	// S5 — target compatibility.
	RejectTargetUndeclared  RejectCode = "S5_TARGET_UNDECLARED"
	RejectTargetUnknown     RejectCode = "S5_TARGET_UNKNOWN"
	RejectTargetUnsupported RejectCode = "S5_TARGET_UNSUPPORTED"

	// S6 — metadata sanity.
	RejectMetadataIncomplete   RejectCode = "S6_METADATA_INCOMPLETE"
	RejectMetadataInconsistent RejectCode = "S6_METADATA_INCONSISTENT"
)

// Verdict is the typed outcome of a single stage (or of the whole pipeline).
// A passing verdict has Passed == true and an empty Code. A rejecting verdict
// has Passed == false, the failing Stage, its RejectCode, and an
// operator-actionable Message.
type Verdict struct {
	Passed  bool
	Stage   Stage
	Code    RejectCode
	Message string
}

// pass returns a passing verdict for the given stage.
func pass(s Stage) Verdict { return Verdict{Passed: true, Stage: s} }

// reject returns a rejecting verdict for the given stage / code / message.
func reject(s Stage, code RejectCode, msg string) Verdict {
	return Verdict{Passed: false, Stage: s, Code: code, Message: msg}
}

// IsReject reports whether the verdict denotes a rejection.
func (v Verdict) IsReject() bool { return !v.Passed }

// String renders the verdict for logs (no key material).
func (v Verdict) String() string {
	if v.Passed {
		return "PASS " + string(v.Stage)
	}
	return "REJECT " + string(v.Stage) + " " + string(v.Code) + ": " + v.Message
}
