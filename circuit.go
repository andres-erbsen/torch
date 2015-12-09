package torch

import (
	"bytes"
	"container/list"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/andres-erbsen/torch/ntor"
	"hash"
	"net"

	"golang.org/x/net/context"
	"golang.org/x/net/proxy"
)

const (
	circuitSendWindowMax = 1000
	circuitRecvWindowMax = 1000
	numRelayEarlyMax     = 8
)

type Circuit struct {
	torConn *TorConn
	id      []byte
	recv    chan cell // torConn sends incoming packets on recv

	requestSend             chan sendRelayCellRequest
	requestNewStream        chan newStreamRequest
	requestDeleteStream     chan deleteStreamRequest
	requestExtHandleControl chan extHandleControlRequest
	asyncErr                chan error
	requestInMainLoop       chan inMainLoopRequest

	// externalControlHandlers have exclusive acces to the Circuit while they
	// are executing.
	externalControlHandlers map[byte]externalControlHandler

	sendQueue list.List
	sendBusy  bool
	sendDone  chan struct{}

	requestSendRaw chan sendCellRequest
	raw            bool

	readRawDone  chan struct{}
	readRawOut   chan []byte // capacity 1, readRawBusy = 0 if empty
	readRawBusy  bool
	readRawQueue list.List

	// layers of encryption on this connection.
	// the layer terminated closest to us is stored first.
	layers []*onionLayer

	// streams are inside the innermost layer (the one terminated the furthest
	// away)
	streams      map[uint16]*Stream
	nextStreamID uint16

	relayEarlyRemaining int

	cancel  func()
	ctx     context.Context
	stopped chan struct{}

	errForClose error
}

type onionLayer struct {
	sendCipher, recvCipher cipher.Stream
	sendDigest, recvDigest hash.Hash

	recvWindow   int
	sendWindowCh chan struct{} // sendWindow = cap(sendWindowCh) - len(sendWindowCh)
}

type relayCell struct {
	streamID     uint16
	relayCommand byte
	payload      []byte
}

type sendCellRequest struct {
	cell
	ret chan error
}

type sendRelayCellRequest struct {
	relayCell
	ret chan error
}

type extHandleControlRequest struct {
	relayCommand byte
	handler      externalControlHandler
}

type externalControlHandler struct {
	h   func(relayCell) error
	ret chan error
}

type newStreamRequest struct {
	ctx               context.Context
	relayBeginCommand byte
	payload           []byte
	ret               chan *Stream
}

type deleteStreamRequest struct {
	id  uint16
	ret chan struct{}
}

type inMainLoopRequest struct {
	f   func() error
	ret chan error
}

func pickRelayEarlyRemaining() int {
	var b [4]byte
	rand.Read(b[:])
	r := binary.BigEndian.Uint32(b[:]) % 3 // in {0,1,2}
	return numRelayEarlyMax - int(r)
}

func makeCircuit(ctx context.Context, tc *TorConn, id []byte) *Circuit {
	ctx, cancel := context.WithCancel(ctx)
	circ := &Circuit{
		torConn: tc,
		id:      id,

		recv: make(chan cell),

		requestSend:             make(chan sendRelayCellRequest),
		requestNewStream:        make(chan newStreamRequest),
		requestDeleteStream:     make(chan deleteStreamRequest),
		requestExtHandleControl: make(chan extHandleControlRequest),
		requestInMainLoop:       make(chan inMainLoopRequest),
		asyncErr:                make(chan error),

		externalControlHandlers: make(map[byte]externalControlHandler),

		sendDone: make(chan struct{}),

		cancel:  cancel,
		ctx:     ctx,
		stopped: make(chan struct{}),

		relayEarlyRemaining: pickRelayEarlyRemaining(),

		streams:      make(map[uint16]*Stream),
		nextStreamID: 1,
	}
	return circ
}

func (circ *Circuit) Close() error {
	circ.cancel()
	<-circ.stopped
	if circ.errForClose != context.Canceled {
		return circ.errForClose
	} else {
		return nil
	}
}

func (circ *Circuit) run() {
	defer close(circ.stopped)
	for {
		select {
		case c := <-circ.recv: // raw or demux
			if err := circ.handleRecv(c); err != nil {
				circ.errForClose = err
				circ.cancel()
			}
		case rq := <-circ.requestNewStream: // demux only
			stream := makeStream(rq.ctx, circ, circ.nextStreamID)
			circ.streams[circ.nextStreamID] = stream
			circ.nextStreamID++
			rq.ret <- stream
		case rq := <-circ.requestDeleteStream: // demux only
			circ.handleDeleteStream(rq)
		case rq := <-circ.requestExtHandleControl: // demux only
			circ.externalControlHandlers[rq.relayCommand] = rq.handler
		case rq := <-circ.requestSend: // demux only
			circ.handleSend(rq)
		case rq := <-circ.requestSendRaw: // raw only
			circ.handleSendRaw(rq)
		case <-circ.readRawDone: // raw only
			circ.handleReadRawDone()
		case <-circ.sendDone: // raw or demux
			if front := circ.sendQueue.Front(); front != nil {
				go circ.blockingSend(circ.sendQueue.Remove(front).(sendCellRequest))
			} else {
				circ.sendBusy = false
			}
		case rq := <-circ.requestInMainLoop: // raw or demux
			rq.ret <- rq.f()
		case err := <-circ.asyncErr: // raw or demux
			if err != nil {
				circ.errForClose = fmt.Errorf("asyncerr: %s", err)
				circ.cancel()
			}
		case <-circ.ctx.Done(): // raw or demux
			if circ.errForClose == nil {
				circ.errForClose = circ.ctx.Err()
			}
			circ.sendQueue = list.List{}
			circ.closeAllStreams(fmt.Errorf("circuit shut down: %v", circ.errForClose))
			circ.torConn.deleteCircuit(circ.id)
			return
		}
	}
}

func (circ *Circuit) hijack() {
	circ.closeAllStreams(fmt.Errorf("circuit going raw: %s", circ.errForClose))
	circ.raw = true
	circ.readRawDone = make(chan struct{})
	circ.readRawOut = make(chan []byte)
	circ.requestSendRaw = make(chan sendCellRequest)
}

func (circ *Circuit) closeAllStreams(err error) {
	for _, stream := range circ.streams {
		go func(stream *Stream) { stream.asyncErr <- err }(stream)
	}
	for len(circ.streams) != 0 {
		circ.handleDeleteStream(<-circ.requestDeleteStream)
	}
}

func (circ *Circuit) handleDeleteStream(rq deleteStreamRequest) {
	delete(circ.streams, rq.id)
	rq.ret <- struct{}{}
}

func (circ *Circuit) handleReadRawDone() {
	if front := circ.readRawQueue.Front(); front != nil {
		circ.readRawOut <- circ.readRawQueue.Remove(front).([]byte)
	} else {
		circ.readRawBusy = false
	}
}

func (circ *Circuit) handleReadRaw(c cell) {
	if circ.readRawBusy {
		circ.readRawQueue.PushBack(c.payload)
	} else {
		circ.readRawOut <- c.payload
	}
}

func (circ *Circuit) handleRecv(c cell) error {
	switch c.command {
	case CELL_RELAY_EARLY:
		return fmt.Errorf("received RELAY_EARLY")
	case CELL_RELAY:
		for _, layer := range circ.layers {
			layer.recvCipher.XORKeyStream(c.payload, c.payload)
		}
		if circ.raw {
			circ.handleReadRaw(c)
		} else {
			return circ.handleRecvRelay(c)
		}

	case CELL_DESTROY:
		if len(c.payload) == 0 {
			return fmt.Errorf("received CELL_DESTROY with empty payload")
		}
		return fmt.Errorf("received CELL_DESTROY (%d)", c.payload[0])

	default:
		return fmt.Errorf("circuit %x: unknown cell (command=%d, payload=%x)\n", circ.id, c.command, c.payload)
	}
	return nil
}

func (circ *Circuit) handleRecvRelay(c cell) error {
	if len(c.payload) < 11 {
		return fmt.Errorf("truncated relay cell (length %d, expected >= 11)", len(c.payload))
	}
	layer, err := circ.checkDigest(c)
	if err != nil {
		return err
	}
	relayCommand := c.payload[0]
	streamID := binary.BigEndian.Uint16(c.payload[3:5])
	dataLength := binary.BigEndian.Uint16(c.payload[9:11])
	if 11+int(dataLength) > len(c.payload) {
		return fmt.Errorf("truncated relay cell (%d < %d)", dataLength, len(c.payload)-11)
	}
	data := c.payload[11:][:dataLength]

	if relayCommand == RELAY_DATA {
		//seqdebug: fmt.Printf(".")
		layer.recvWindow -= 1
		if layer.recvWindow <= 900 {
			layer.recvWindow += 100
			circ.handleSend(sendRelayCellRequest{relayCell{0, RELAY_SENDME, nil}, circ.asyncErr})
		}
	} else {
		//seqdebug: fmt.Printf(":")
	}

	switch {
	case streamID == 0 && relayCommand == RELAY_SENDME:
		for i := 0; i < 100; i++ {
			select {
			case <-circ.layers[len(circ.layers)-1].sendWindowCh:
			default:
				return fmt.Errorf("unexpected RELAY_SENDME")
			}
		}
	case streamID == 0 && circ.externalControlHandlers[relayCommand].h != nil:
		handler := circ.externalControlHandlers[relayCommand]
		handler.h(relayCell{streamID, relayCommand, data})
		handler.ret <- nil
		delete(circ.externalControlHandlers, relayCommand)
	case streamID != 0:
		if stream, known := circ.streams[streamID]; known {
			select {
			case stream.read <- relayCell{streamID, relayCommand, data}:
			case <-stream.ctx.Done():
				// ignore: the stream is already gone
			}
		} else {
			if relayCommand != RELAY_END {
				fmt.Printf("received relay packet for unknown stream %d with command %d data %x\n", streamID, relayCommand, data)
			}
		}
	default:
		return fmt.Errorf("unknown relay cell received: streamID=%x, dataLength=%x, payload[0]=%x", streamID, dataLength, c.payload[0])
	}
	return nil
}

func (circ *Circuit) checkDigest(c cell) (*onionLayer, error) {
	if c.payload[1] != 0 || c.payload[2] != 0 {
		return nil, fmt.Errorf("unrecognized relay cell (command=%d, payload=%x)", c.payload[0], c.payload[11:])
	}
	digest := [4]byte{c.payload[5], c.payload[6], c.payload[7], c.payload[8]} // copy
	c.payload[5], c.payload[6], c.payload[7], c.payload[8] = 0, 0, 0, 0
	layer := circ.layers[len(circ.layers)-1]
	layer.recvDigest.Write(c.payload)
	if !bytes.Equal(layer.recvDigest.Sum(nil)[:4], digest[:]) {
		return nil, fmt.Errorf("bad digest on a recognized cell")
	}
	copy(c.payload[5:9], digest[:])
	return layer, nil
}

// transactControl first sends (relayCOmmand, streamID, payload) and then runs
// h in the main loop on the first circuit with command=responseCommand that is
// received.
func (circ *Circuit) transactControl(relayCommand byte, streamID uint16, payload []byte, responseCommand byte, h func(relayCell) error) error {
	ch := make(chan error)
	select {
	case circ.requestExtHandleControl <- extHandleControlRequest{responseCommand, externalControlHandler{h, ch}}:
	case <-circ.ctx.Done():
		return fmt.Errorf("circuit shut down: %v", circ.errForClose)
	}
	if err := circ.relay(relayCommand, streamID, payload); err != nil {
		return err
	}
	select {
	case r := <-ch:
		return r
	case <-circ.ctx.Done():
		return fmt.Errorf("circuit shut down: %v", circ.errForClose)
	}
}

func (circ *Circuit) newStream(ctx context.Context, relayBeginCommand byte, payload []byte) (*Stream, error) {
	ch := make(chan *Stream)
	var stream *Stream
	select {
	case <-circ.stopped:
		return nil, circ.errForClose
	case circ.requestNewStream <- newStreamRequest{ctx, relayBeginCommand, payload, ch}:
		stream = <-ch
	}
	if err := circ.relay(relayBeginCommand, stream.id, payload); err != nil {
		return nil, err
	}
	return stream, nil
}

func (circ *Circuit) deleteStream(id uint16) {
	ch := make(chan struct{})
	select {
	case <-circ.stopped:
	case circ.requestDeleteStream <- deleteStreamRequest{id, ch}:
		<-ch
	}
}

func (circ *Circuit) inMainLoop(f func() error) error {
	ch := make(chan error)
	select {
	case <-circ.stopped:
		return fmt.Errorf("circuit is shut down: %s", circ.errForClose)
	case circ.requestInMainLoop <- inMainLoopRequest{f, ch}:
		return <-ch
	}
}

func (circ *Circuit) relay(relayCommand byte, streamID uint16, payload []byte) error {
	ret := make(chan error)
	select {
	case circ.requestSend <- sendRelayCellRequest{relayCell{streamID, relayCommand, payload}, ret}: // TODO: make an internal error feedback channel?
	case <-circ.ctx.Done():
		return fmt.Errorf("circuit is shutting down")
	}
	select {
	case err := <-ret:
		return err
	case <-circ.ctx.Done():
		return fmt.Errorf("circuit is shutting down")
	}
}

func (circ *Circuit) handleSend(rq sendRelayCellRequest) {
	if len(rq.payload) > RELAY_PAYLOAD_LEN {
		rq.ret <- fmt.Errorf("relay payload too long: %d > %d", len(rq.payload), RELAY_PAYLOAD_LEN)
		return
	}
	payload := make([]byte, PAYLOAD_LEN)
	payload[0] = rq.relayCommand
	binary.BigEndian.PutUint16(payload[3:5], rq.streamID)
	binary.BigEndian.PutUint16(payload[9:11], uint16(len(rq.payload)))
	copy(payload[11:], rq.payload)

	dstLayer := circ.layers[len(circ.layers)-1]
	if rq.relayCommand == RELAY_DATA {
		dstLayer.sendWindowCh <- struct{}{}
	}
	//seqdebug: fmt.Printf("(%d/%d)", rq.streamID, rq.relayCommand)

	dstLayer.sendDigest.Write(payload)
	copy(payload[5:9], dstLayer.sendDigest.Sum(nil)[:4])
	cellCommand := byte(CELL_RELAY)
	if rq.relayCommand == RELAY_EXTEND2 || rq.relayCommand == RELAY_EXTEND {
		// ALL extend commands are RELAY_EARLY
		circ.relayEarlyRemaining--
		cellCommand = CELL_RELAY_EARLY
	}
	circ.handleSendRaw(sendCellRequest{cell{circ.id, cellCommand, payload}, rq.ret})
}

// relayRaw encrypts and sends payload over the circuit in a RELAY cell. The
// payload slice IS MODIFIED.
func (circ *Circuit) handleSendRaw(rq sendCellRequest) {
	if len(rq.payload) != PAYLOAD_LEN {
		rq.ret <- fmt.Errorf("relay payload of incorrect length: %d != %d", len(rq.payload), PAYLOAD_LEN)
		return
	}
	if rq.cell.command == CELL_RELAY && circ.relayEarlyRemaining > 0 && len(circ.layers) > 1 {
		// some early relays are RELAY_EARLY too
		circ.relayEarlyRemaining--
		rq.cell.command = CELL_RELAY_EARLY
	}
	for _, layer := range circ.layers {
		layer.sendCipher.XORKeyStream(rq.payload, rq.payload)
	}
	if circ.sendBusy {
		circ.sendQueue.PushBack(rq)
	} else {
		go circ.blockingSend(rq)
		circ.sendBusy = true
	}
}

func (circ *Circuit) blockingSend(rq sendCellRequest) {
	rq.ret <- circ.torConn.writeCell(rq.cell)
	select {
	case circ.sendDone <- struct{}{}:
	case <-circ.ctx.Done():
	}
}

func (circ *Circuit) Extend(ip net.IP, port uint16, routerid, ntorPublic []byte) error {
	const (
		spec_ipv4 = iota
		spec_ipv6
		spec_id
	)
	nSpec := byte(2) // two next hop specifiers (IP and ID) before handshake
	if ip.To4() == nil {
		fmt.Errorf("an ipv4 address is required")
	}
	addr := make([]byte, 6)
	copy(addr[:4], ip.To4())
	binary.BigEndian.PutUint16(addr[4:], port)

	handshake, X, x := ntor.ClientHandshake(routerid[:], ntorPublic[:])
	payload := append([]byte{nSpec, spec_ipv4, byte(len(addr))}, addr...)
	payload = append(payload, append([]byte{spec_id, byte(len(routerid))}, routerid...)...)
	payload = append(payload, append([]byte{0, 2, 0, byte(len(handshake))}, handshake...)...)
	// 0,2 is the handshake method (uint16be); 0, len(handshake) is uint16be length
	return circ.transactControl(RELAY_EXTEND2, 0, payload, RELAY_EXTENDED2, func(c relayCell) error {
		return circ.addLayer(X, x, c.payload, routerid, ntorPublic)
	})
}

// Dial implements proxy.Dialer using DialTCP and DialDir based on the
// hostname, returning multiplexed connections.
func (circ *Circuit) Dial(network, addr string) (c net.Conn, err error) {
	ctx := context.TODO()
	var s *Stream
	if host, _, _ := net.SplitHostPort(addr); host == "tordir.localhost" {
		s, err = circ.DialDir(ctx)
	} else {
		s, err = circ.DialTCP(ctx, network, addr)
	}
	return (*MultiplexConn)(s), err
}

var _ proxy.Dialer = (*Circuit)(nil)

// DialTCP connects to a TCP server on the public Internet.
func (circ *Circuit) DialTCP(ctx context.Context, net, address string) (*Stream, error) {
	// acutally opts is uint32be, but only the lowest byte is used
	var opts byte
	switch net {
	case "tcp":
		opts |= 1
	case "tcp6":
		opts |= 2
	case "tcp4":
	default:
		return nil, fmt.Errorf("unsupported network")
	}

	// opts is a big-endian uint32
	payload := append([]byte(address), 0, 0, 0, 0, opts)
	stream, err := circ.newStream(ctx, RELAY_BEGIN, payload)
	if err != nil {
		return nil, err
	}
	stream.remoteAddr = &addr{net, address}
	return stream, nil
}

// DialDir connects to the directory port of the relay
func (circ *Circuit) DialDir(ctx context.Context) (*Stream, error) {
	stream, err := circ.newStream(ctx, RELAY_BEGIN_DIR, nil)
	if err != nil {
		return nil, err
	}
	stream.remoteAddr = &addr{"tordir", circ.torConn.tlsConn.RemoteAddr().String()}
	return stream, nil
}

// ListenRendezvousRaw executes the "client" part of the rendezvous protocol.
// Requires len(cookie) = 20. The returned function, accept, waits for the
// server to complete the rendezvous protocol and returns the 148-byte server
// handshake message and on success, this circuit will be connected to the
// rendezvous peer and the circuit will enter raw mode.
func (circ *Circuit) ListenRendezvousRaw(cookie []byte) (func() ([]byte, error), error) {
	acceptBarrier := make(chan error)
	var acceptCookie []byte

	err := circ.transactControl(RELAY_ESTABLISH_RENDEZVOUS, 0, cookie, RELAY_RENDEZVOUS_ESTABLISHED, func(c relayCell) error {
		circ.externalControlHandlers[RELAY_RENDEZVOUS2] = externalControlHandler{func(c relayCell) error {
			circ.hijack()
			acceptCookie = c.payload
			return nil
		}, acceptBarrier}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return func() ([]byte, error) {
		select {
		case err := <-acceptBarrier:
			if err != nil {
				return nil, err
			}
			return acceptCookie, nil
		case <-circ.stopped:
			return nil, circ.errForClose
		}
	}, nil
}

// DialRendezvousRaw executes the "server" part of the rendezvous protocol.
// Requires len(cookie) = 20, len(payload) = 148.  The Circuit should not be
// used for other purposes after this. On success, this circuit will be
// connected to the rendezvous peer and the circuit will enter raw mode.
func (circ *Circuit) DialRendezvousRaw(cookie, payload []byte) error {
	data := make([]byte, 168)
	copy(data[:20], cookie)
	copy(data[20:], payload)
	circ.inMainLoop(func() error { circ.hijack(); return nil })
	return circ.relay(RELAY_RENDEZVOUS1, 0, data)
}

// WriteRaw encrypts and sends payload over the circuit in a RELAY cell. The
// payload slice IS MODIFIED.
func (circ *Circuit) WriteRaw(payload []byte) error {
	ch := make(chan error)
	circ.requestSendRaw <- sendCellRequest{cell{circ.id, CELL_RELAY, payload}, ch}
	select {
	case err := <-ch:
		return err
	case <-circ.stopped:
		return circ.errForClose
	}
}

func (circ *Circuit) ReadRaw() ([]byte, error) {
	select {
	case bs := <-circ.readRawOut:
		return bs, nil
	case <-circ.stopped:
		return nil, circ.errForClose
	}
}
