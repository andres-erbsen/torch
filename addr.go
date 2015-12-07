package torch

import "net"

type addr struct{ network, addr string }

func (a *addr) Network() string { return a.network }
func (a *addr) String() string  { return a.addr }

var _ net.Addr = (*addr)(nil)
