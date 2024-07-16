package utils

import (
	"bytes"
	"crypto/sha256"
	"io"
)

type Checksum []byte

func FileChecksum(buf *bytes.Buffer) (Checksum, error) {
	hash := sha256.New()
	bufCopy := bytes.NewBuffer(buf.Bytes())
	if _, err := io.Copy(hash, bufCopy); err != nil {
		return nil, err
	}
	checksum := hash.Sum(nil)
	return checksum, nil
}

func ContentHasChanged(newChecksum Checksum, prevChecksum Checksum) bool {
	if prevChecksum != nil {
		if bytes.Equal(newChecksum, prevChecksum) {
			return false
		}
	}
	return true
}
