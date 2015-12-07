package nd

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

type Stream struct {
	ndc               *Conn
	readMu, writeMu   sync.Mutex
	readBuf, writeBuf [FRAMESIZE]byte
	readCached        []byte // slice into readBuf
	readEOF           bool
}

func (nds *Stream) Write(data []byte) (int, error) {
	nds.writeMu.Lock()
	defer nds.writeMu.Unlock()

	var bytesWritten int
	step := FRAMESIZE - 1
	for i := step; i < len(data); i += step {
		if err := nds.writeChunk(data[i-step:i], false); err != nil {
			return bytesWritten, err
		}
		bytesWritten += step
	}
	if err := nds.writeChunk(data[bytesWritten:], false); err != nil {
		return bytesWritten, err
	}
	return len(data), nil
}

func (nds *Stream) CloseWrite() error {
	nds.writeMu.Lock()
	defer nds.writeMu.Unlock()
	return nds.writeChunk(nil, true)
}

func (nds *Stream) Close() error {
	return nds.ndc.Close()
}

// writeChunk writes at most FRAMESIZE-1 bytes and a header
func (nds *Stream) writeChunk(data []byte, eof bool) error {
	// The header must fit in a 2-byte uvarint and is thus at most 14 bits long.
	// The bits are allocated as follows, starting from the least significant:
	// 0: EOF (active high)
	// 1..3: reserved
	// 4..13 (9 bits): FRAMESIZE-1-len(data)
	// Encoding the FRAMESIZE-1-len(data) instead of len(data) makes the header
	// uvarint fit into a single byte when there is less padding (and more
	// data), leaving one byte more room for the data (up to 492 bytes).
	var header uint64
	if eof {
		header |= 1
	}
	header |= uint64(FRAMESIZE-1-len(data)) << 4
	n := binary.PutUvarint(nds.writeBuf[:2], header)
	if n+len(data) > FRAMESIZE {
		panic("Stream.writeChunk space accounting failed")
	}
	n += copy(nds.writeBuf[n:], data)
	for i := n; i < len(nds.writeBuf); i++ {
		nds.writeBuf[i] = 0
	}
	return nds.ndc.SendFrame(nds.writeBuf[:])
}

func (nds *Stream) Read(out []byte) (int, error) {
	nds.readMu.Lock()
	defer nds.readMu.Unlock()

	if len(nds.readCached) == 0 {
		if nds.readEOF {
			return 0, io.EOF
		}

		if err := nds.ndc.RecvFrame(nds.readBuf[:]); err != nil {
			return 0, err
		}
		header, headersize := binary.Uvarint(nds.readBuf[:])
		if !(1 <= headersize && headersize <= 2) {
			return 0, fmt.Errorf("nd.Stream: incorrect header size")
		}
		nds.readEOF = header&1 == 1
		datasize := int(FRAMESIZE - 1 - ((header >> 4) & 0x1ff))

		nds.readCached = nds.readBuf[headersize : headersize+datasize]
	}

	n := copy(out[:], nds.readCached)
	nds.readCached = nds.readCached[n:]
	return n, nil
}
