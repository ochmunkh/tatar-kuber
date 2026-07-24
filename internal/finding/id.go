package finding

import (
	"crypto/sha256"
	"encoding/hex"
)

// StableID — content-hash дээр суурилсан тогтвортой finding ID (Doc #1 §7.1).
// Дараалсан дугаар БИШ тул scan хооронд ижил асуудал ижил ID-тай гарч,
// SARIF/GitHub дедуп ба diff эвдрэхгүй.
func StableID(canonicalControl, resource, namespace string) string {
	h := sha256.Sum256([]byte(canonicalControl + "|" + resource + "|" + namespace))
	return "TK-" + hex.EncodeToString(h[:])[:6]
}
