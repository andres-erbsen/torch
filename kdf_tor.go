package torch

import (
	"crypto/sha1"
	"io"
)

type kdf_tor struct {
	seed []byte
	// possible optimization: hash the seed and copy the hash state each time
	blockNumber   int
	bytesBuffered int
	buf           [sha1.Size]byte
}

func kdf_tor_new(seed []byte) io.Reader {
	return &kdf_tor{seed: seed}
}

func (kdf *kdf_tor) Read(out []byte) (int, error) {
	n := len(out)
	for len(out) != 0 {
		if kdf.bytesBuffered == 0 {
			h := sha1.New()
			if _, err := h.Write(kdf.seed); err != nil {
				panic(err)
			}
			if _, err := h.Write([]byte{byte(kdf.blockNumber)}); err != nil {
				panic(err)
			}
			h.Sum(kdf.buf[:0])
			kdf.bytesBuffered = sha1.Size
			kdf.blockNumber++
		}

		step := kdf.bytesBuffered
		if len(out) < step {
			step = len(out)
		}

		copy(out, kdf.buf[sha1.Size-kdf.bytesBuffered:])
		kdf.bytesBuffered -= step
		out = out[step:]
	}
	return n, nil
}
