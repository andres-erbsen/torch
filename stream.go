package torch

import (
	"container/list"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/net/context"
)

var ErrStreamClosed = fmt.Errorf("stream closed")

type Stream struct {
	id         uint16
	circuit    *Circuit
	remoteAddr net.Addr

	recvWindow  int
	writeWindow chan struct{}
	asyncErr    chan error

	read chan relayCell

	readDone  chan struct{}
	readOut   chan []byte // capacity 1, readBusy = 0 if empty, contains nil -> EOF
	readQueue list.List
	readBusy  bool

	asyncSends sync.WaitGroup

	cancel      func()
	ctx         context.Context
	stopped     chan struct{}
	errForClose error
}

type writeChunkRequest struct {
	bs  []byte
	ret chan error
}

func makeStream(ctx context.Context, circ *Circuit, id uint16) *Stream {
	ctx, cancel := context.WithCancel(ctx)
	stream := &Stream{
		id:      id,
		circuit: circ,
		read:    make(chan relayCell),

		recvWindow:  500,                      // tor-spec section 7.4
		writeWindow: make(chan struct{}, 500), // window value: cap(chan)-len(chan)
		asyncErr:    make(chan error),
		readDone:    make(chan struct{}, 1),
		readOut:     make(chan []byte, 1),

		cancel:  cancel,
		ctx:     ctx,
		stopped: make(chan struct{}),
	}
	go stream.run()
	return stream
}

func (stream *Stream) run() {
	defer close(stream.stopped)
	for {
		select {
		case <-stream.readDone:
			stream.handleReadDone()
		case rc := <-stream.read:
			switch rc.relayCommand {
			case RELAY_DATA:
				if len(rc.payload) != 0 {
					stream.readOutData(rc.payload)
				}
				stream.recvWindow -= 1
				stream.manageRecvWindow()
			case RELAY_END:
				stream.readOutData(nil)
			case RELAY_DROP:
			case RELAY_CONNECTED:
			// TODO: should DialTCP() block until this is received?
			case RELAY_SENDME:
				for i := 0; i < 50; i++ {
					select {
					case <-stream.writeWindow:
					default:
						break
					}
				}
			default:
				fmt.Printf("read command %d payload %x on stream %d\n",
					rc.relayCommand, rc.payload, stream.id)
			}
		case err := <-stream.asyncErr:
			if err != nil {
				stream.errForClose = err
				stream.cancel()
			}
		case <-stream.ctx.Done():
			if stream.errForClose == nil {
				stream.errForClose = stream.ctx.Err()
			}
			stream.asyncSends.Wait()
			stream.circuit.relay(RELAY_END, stream.id, []byte{REASON_DONE})
			stream.circuit.deleteStream(stream.id)
			return
		}
	}
}

func (stream *Stream) readOutData(payload []byte) {
	if stream.readBusy {
		stream.readQueue.PushBack(payload)
	} else {
		stream.readOut <- payload
		stream.readBusy = true
	}
}

func (stream *Stream) handleReadDone() {
	if front := stream.readQueue.Front(); front != nil {
		stream.readOut <- stream.readQueue.Remove(front).([]byte)
		stream.manageRecvWindow()
	} else {
		stream.readBusy = false
	}
}

func (stream *Stream) manageRecvWindow() {
	// MUST be called from main loop.
	if stream.recvWindow <= 450 && stream.readQueue.Len() < 9 {
		// tor-spec.txt 7.4: 9 cells in readQueue + 1 in readOut
		stream.recvWindow += 50
		stream.asyncSends.Add(1)
		go func() { // TODO: avoid allocating goroutines if possible
			defer stream.asyncSends.Done()
			select {
			case stream.circuit.requestSend <- sendRelayCellRequest{relayCell{stream.id, RELAY_SENDME, nil}, stream.asyncErr}:
			case <-stream.ctx.Done():
			}
		}()
	}
}

func (stream *Stream) writeChunk(b []byte) error {
	select {
	case stream.writeWindow <- struct{}{}:
	case <-stream.ctx.Done():
		return fmt.Errorf("closed")
	}
	return stream.circuit.relay(RELAY_DATA, stream.id, b)
}

func (stream *Stream) Write(b []byte) (int, error) {
	bytesWritten := 0
	for i := RELAY_PAYLOAD_LEN; i < len(b); i += RELAY_PAYLOAD_LEN {
		if err := stream.writeChunk(b[i-RELAY_PAYLOAD_LEN : i]); err != nil {
			return bytesWritten, err
		}
		bytesWritten += RELAY_PAYLOAD_LEN
	}
	if err := stream.writeChunk(b[bytesWritten:]); err != nil {
		return bytesWritten, err
	}
	return len(b), nil
}

func (stream *Stream) Read(out []byte) (int, error) {
	select {
	case <-stream.stopped:
		return 0, stream.errForClose
	case bs := <-stream.readOut:
		if bs == nil {
			stream.readOut <- bs
			return 0, io.EOF
		}
		n := copy(out, bs)
		if n == len(bs) {
			select {
			case stream.readDone <- struct{}{}:
			case <-stream.stopped:
			}
		} else {
			stream.readOut <- bs[n:]
		}
		return n, nil
	}
}

func (stream *Stream) Close() error {
	stream.cancel()
	<-stream.stopped
	if stream.errForClose != context.Canceled {
		return stream.errForClose
	} else {
		return nil
	}
}

func (stream *Stream) RemoteAddr() net.Addr {
	return stream.remoteAddr
}
