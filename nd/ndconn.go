package nd

import (
	"fmt"
	"github.com/andres-erbsen/torch"
	"io"
	"sync"

	"golang.org/x/crypto/nacl/secretbox"
)

type Conn struct {
	TorConn *torch.TorConn
	Circuit *torch.Circuit
	Bit     bool
	KDF     io.Reader
	key     [32]byte

	readMu, writeMu       sync.Mutex
	writeBuf              [torch.PAYLOAD_LEN]byte
	readNonce, writeNonce [24]byte
}

func (ndc *Conn) Close() error {
	err := ndc.TorConn.Close()

	ndc.writeMu.Lock()
	defer ndc.writeMu.Unlock()
	ndc.readMu.Lock()
	defer ndc.readMu.Unlock()
	for i := 0; i < len(ndc.key); i++ {
		ndc.key[i] = 0
	}
	for i := 0; i < len(ndc.writeBuf); i++ {
		ndc.writeBuf[i] = 0
	}

	return err
}

const FRAMESIZE = torch.PAYLOAD_LEN - secretbox.Overhead

func (ndc *Conn) FrameSize() int {
	return FRAMESIZE
}

func inc(nonce *[24]byte) {
	for i := 0; i < 24; i++ {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}

// Write takes a buf with len(buf) = FRAMESIZE and sends it over the connection.
// Encryption, authentication, and ordering preservation are applied using the
// seed given to ND().
func (ndc *Conn) SendFrame(data []byte) error {
	if len(data) != FRAMESIZE {
		return fmt.Errorf("Write(buf) must be called with len(buf) = %d (but got %d)", FRAMESIZE, len(data))
	}
	ndc.writeMu.Lock()
	defer ndc.writeMu.Unlock()

	b := secretbox.Seal(ndc.writeBuf[:0], data, &ndc.writeNonce, &ndc.key)
	if &b[0] != &ndc.writeBuf[0] {
		panic("writebuf overflow?")
	}
	inc(&ndc.writeNonce)
	inc(&ndc.writeNonce)
	return ndc.Circuit.WriteRaw(ndc.writeBuf[:])
}

// Read writes 493 bytes and possibly returns an error.
func (ndc *Conn) RecvFrame(b []byte) error {
	ndc.readMu.Lock()
	defer ndc.readMu.Unlock()

	ct, err := ndc.Circuit.ReadRaw()
	if err != nil {
		return fmt.Errorf("nd Conn Circuit ReadRaw: %s", err)
	}
	ret, ok := secretbox.Open(b[:0], ct[:], &ndc.readNonce, &ndc.key)
	if !ok {
		return fmt.Errorf("frame authentication failed")
	}
	if &ret[0] != &b[0] {
		panic("openct overflow?")
	}
	inc(&ndc.readNonce)
	inc(&ndc.readNonce)
	return nil
}
