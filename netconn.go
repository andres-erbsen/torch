package torch

import (
	"fmt"
	"net"
	"time"
)

// SingleStreamConn uses one TOR connection carrying a single circuit carrying
// a single stream as a net.Conn. This enables direct access to TCP-level
// deadlines, but incurs the overhead of torconn and circuit creation.
type SingleStreamConn struct {
	tc     *TorConn
	circ   *Circuit
	stream *Stream
}

func (c *SingleStreamConn) Write(buf []byte) (int, error) {
	return c.stream.Write(buf)
}

func (c *SingleStreamConn) Read(buf []byte) (int, error) {
	return c.stream.Read(buf)
}

func (c *SingleStreamConn) Close() error {
	errS := c.stream.Close()
	errC := c.circ.Close()
	errT := c.tc.tlsConn.Close()
	if errS != nil {
		return errS
	}
	if errC != nil {
		return errC
	}
	return errT
}

func (c *SingleStreamConn) LocalAddr() net.Addr {
	// TODO: what should this be? Is there any way returning the real LocalAddr can be dangerous?
	return &addr{"", ""}
}

func (c *SingleStreamConn) RemoteAddr() net.Addr {
	return c.stream.RemoteAddr()
}

func (c *SingleStreamConn) SetDeadline(t time.Time) error {
	return c.tc.tlsConn.SetDeadline(t)
}

func (c *SingleStreamConn) SetReadDeadline(t time.Time) error {
	return c.tc.tlsConn.SetReadDeadline(t)
}

func (c *SingleStreamConn) SetWriteDeadline(t time.Time) error {
	return c.tc.tlsConn.SetWriteDeadline(t)
}

// MultiplexConn wraps a Stream to provide a net.Conn interface without
// interereing with other streams on the same circuit. However, this means that
// we cannot use TCP-level deadlines, and there currently is no deadline
// support (soft deadlines may be implemented in the future).
type MultiplexConn Stream

func (c *MultiplexConn) Write(buf []byte) (int, error) {
	return (*Stream)(c).Write(buf)
}

func (c *MultiplexConn) Read(buf []byte) (int, error) {
	return (*Stream)(c).Read(buf)
}

func (c *MultiplexConn) Close() error {
	return (*Stream)(c).Close()
}

func (c *MultiplexConn) LocalAddr() net.Addr {
	// TODO: what should this be? Is there any way returning the real LocalAddr can be dangerous?
	return &addr{"", ""}
}

func (c *MultiplexConn) RemoteAddr() net.Addr {
	return c.RemoteAddr()
}

func (c *MultiplexConn) SetDeadline(t time.Time) error {
	return fmt.Errorf("MultiplexConn does not support SetDeadline")
}

func (c *MultiplexConn) SetReadDeadline(t time.Time) error {
	return fmt.Errorf("MultiplexConn does not support SetReadDeadline")
}

func (c *MultiplexConn) SetWriteDeadline(t time.Time) error {
	return fmt.Errorf("MultiplexConn does not support SetWriteDeadline")
}
