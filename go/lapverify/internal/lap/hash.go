package lap

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// SHA256Hex returns lowercase hex SHA-256 digest.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// SafeHashEncode matches the Python reference implementation.
func SafeHashEncode(components []string) []byte {
	var buf bytes.Buffer
	for _, c := range components {
		enc := []byte(c)
		var lenb [8]byte
		binary.BigEndian.PutUint64(lenb[:], uint64(len(enc)))
		buf.Write(lenb[:])
		buf.Write(enc)
	}
	return buf.Bytes()
}
