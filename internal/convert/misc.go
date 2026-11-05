package convert

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
)

// RandomPassword generates the password an imported admin arrives with.
//
// Password hashes do not travel between panels — the algorithms and costs
// differ, and even where they match, moving a hash moves a credential the
// operator never chose to re-issue. So every imported admin gets a fresh
// password, shown once in the review table and in the final report, and never
// written to disk by this tool.
func RandomPassword() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand does not fail in practice; if it ever does, refusing is
		// better than handing out a predictable password.
		return ""
	}
	s := base64.RawURLEncoding.EncodeToString(buf)
	// Avoid characters an operator will mistype when reading it off a screen.
	s = strings.NewReplacer("-", "x", "_", "y").Replace(s)
	return s
}

// DisabledInboundNote is said on an inbound its old panel had switched off.
// NX has no such switch: an inbound serves wherever a template selects it.
func DisabledInboundNote(panel string) string {
	return "this inbound was switched off in " + panel + "; NX has no off switch for an inbound, so it serves on every node whose template selects it — untick it here if it should stay off"
}
