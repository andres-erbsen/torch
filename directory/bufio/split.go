package bufio

import (
	"bytes"
	"encoding/pem"
)

func ScanUntilByte(delim byte, splitter SplitFunc) SplitFunc {
	return func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, delim); i >= 0 {
			return splitter(data[:i], true)
		}
		return splitter(data, atEOF)
	}
}

func ScanByteDelimited(delim byte) SplitFunc {
	return func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, delim); i >= 0 {
			return i + 1, data[:i], nil
		}
		if atEOF {
			return len(data), data, nil
		}
		return 0, nil, nil
	}
}

// ScanPEM scans a PEM block and consumes leading newlines, but not trailing newlines
// Returns DECODED pem data.
func ScanPEM(data []byte, atEOF bool) (int, []byte, error) {
	var pemBytes []byte
	pemBlock, rest := pem.Decode(data)
	if pemBlock != nil {
		pemBytes = pemBlock.Bytes
	}
	token := data[:len(data)-len(rest)]
	for len(token) != 0 && token[len(token)-1] == '\n' {
		token = token[:len(token)-1]
	}
	return len(token), pemBytes, nil
}
