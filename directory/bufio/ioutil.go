package bufio

import (
	"bytes"
	"io"
)

// WriteUntil returns a writer that passes all writes to w until the beginning
// of the first occurrance of delim
func WriteUntil(w io.Writer, delim []byte) io.Writer {
	return &writeUntil{w: w, delim: delim}
}

type writeUntil struct {
	w      io.Writer
	delim  []byte
	buf    []byte
	closed bool
}

func (u *writeUntil) Write(b []byte) (int, error) {
	if u.closed {
		return len(b), nil
	}
	l, b := len(b), append(u.buf, b...)
	var i int
	if i = bytes.Index(b, u.delim); i >= 0 {
		u.closed = true
	} else {
		i = len(b) - len(u.delim) + 1 // earliest possible prefix match
		if i < 0 {
			i = 0
		}
		for i < len(b) && !bytes.Equal(b[i:], u.delim[:len(b[i:])]) {
			i++
		}
		u.buf = b[i:]
	}
	if _, err := u.w.Write(b[:i]); err != nil {
		return 0, err
	}
	return l, nil
}

// delimitedReader splits the incoming stream into separate readers based on delim
type DelimitedReader struct {
	r     io.Reader
	delim []byte
	buf   []byte
	open  bool
	err   error
}

func NewDelimitedReader(r io.Reader, delim []byte) *DelimitedReader {
	return &DelimitedReader{r: r, delim: delim}
}

// Next moves delimitedReader from one delimited block to another if it is at
// the block boundary. noop otherwise. The delimiters will be removed from the
// stream. If there are no blocks remaining, Next returns false.
func (d *DelimitedReader) Next() bool {
	if d.open {
		buf := make([]byte, 10*len(d.delim))
		for d.open {
			if _, err := d.Read(buf); err != nil {
				return false
			}
		}
	}
	if d.err == io.EOF && len(d.buf) == 0 {
		return false
	}
	d.open = true
	return true
}

func (d *DelimitedReader) Read(out []byte) (int, error) {
	if !d.open {
		return 0, io.EOF
	}
	copy(out, d.buf)
	var keep, remaining []byte
	if len(out) > len(d.buf) {
		n := 0
		if d.err == nil {
			n, d.err = d.r.Read(out[len(d.buf):])
		}
		out = out[:len(d.buf)+n]
	} else {
		remaining = d.buf[len(out):]
	}

	if i := bytes.Index(out, d.delim); i >= 0 { // delimiter starts at i
		d.open = false
		out, keep = out[:i], out[i+len(d.delim):]
	} else if d.err == nil { // the delimier may be at frame boundary
		i := len(out) - len(d.delim) + 1 // earliest possible prefix match
		if i < 0 {
			i = 0
		}
		for i < len(out) && !bytes.Equal(out[i:], d.delim[:len(out[i:])]) {
			i++
		}
		out, keep = out[:i], out[i:]
	}

	if len(keep)+len(remaining) > cap(d.buf) {
		d.buf = make([]byte, len(keep)+len(remaining))
	}
	d.buf = d.buf[:len(keep)+len(remaining)]
	copy(d.buf, keep)
	copy(d.buf[len(keep):], remaining)

	if !d.open {
		return len(out), io.EOF
	}
	return len(out), d.err
}
