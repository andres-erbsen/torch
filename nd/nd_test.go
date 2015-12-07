package nd

import (
	"bytes"
	"crypto/rand"
	"github.com/andres-erbsen/torch"
	"io"
	"testing"
	"time"

	"golang.org/x/net/context"
)

func TestNetDogPlain(t *testing.T) {
	ctx, _ := context.WithTimeout(context.Background(), (30 * time.Second))

	const N = 10
	var needle [32]byte
	var plan [N]byte
	seed := make([]byte, 20)
	rand.Read(plan[:])
	rand.Read(seed)
	rand.Read(needle[:])
	dataSwap := make(chan string)

	ndct := func() {
		ndc, err := ND(ctx, &needle, seed)
		if err != nil {
			t.Fatal(err)
		}
		defer ndc.Close()

		circ := ndc.Circuit
		bit := ndc.Bit
		for i := 0; i < N; i++ {
			myData := make([]byte, torch.PAYLOAD_LEN)
			rand.Read(myData)
			copy(myData, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8})

			send := bit == (plan[i]&1 == 1)
			if send {
				dataSwap <- string(myData)
				if err := circ.WriteRaw([]byte(myData)); err != nil {
					t.Fatal(err)
				}
			} else {
				dataRef := <-dataSwap
				theirData, err := circ.ReadRaw()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal([]byte(dataRef), theirData) {
					t.Errorf("%x\n!= (at %v)\n%x\n", theirData, bit, []byte(dataRef))
				} else if testing.Verbose() {
					//t.Logf("%x\n== (at %v)\n%x\n", theirData, bit, []byte(dataRef))
				}
			}

		}
	}

	ch := make(chan struct{})
	go func() { ndct(); close(ch) }()
	ndct()
	<-ch
}

func TestNetDogEncrypted(t *testing.T) {
	ctx, _ := context.WithTimeout(context.Background(), (30 * time.Second))

	const N = 20
	var needle [32]byte
	var plan [N]byte
	seed := make([]byte, 20)
	rand.Read(plan[:])
	rand.Read(seed)
	rand.Read(needle[:])
	dataSwap := make(chan string)

	ndet := func() {
		ndc, err := ND(ctx, &needle, seed)
		if err != nil {
			t.Fatal(err)
		}
		defer ndc.Close()

		bit := ndc.Bit
		for i := 0; i < N; i++ {
			myData := make([]byte, FRAMESIZE)
			rand.Read(myData)
			copy(myData, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8})

			send := bit == (plan[i]&1 == 1)
			if send {
				dataSwap <- string(myData)
				if err := ndc.SendFrame([]byte(myData)); err != nil {
					t.Fatal(err)
				}
			} else {
				dataRef := <-dataSwap
				theirData := make([]byte, FRAMESIZE)
				if err := ndc.RecvFrame(theirData); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal([]byte(dataRef), theirData) {
					t.Errorf("%x\n!= (at %v)\n%x\n", theirData, bit, []byte(dataRef))
				} else if testing.Verbose() {
					//t.Logf("%x\n== (at %v)\n%x\n", theirData, bit, []byte(dataRef))
				}
			}

		}
	}

	ch := make(chan struct{})
	go func() { ndet(); close(ch) }()
	ndet()
	<-ch
}

func TestNetDogStream(t *testing.T) {
	ctx, _ := context.WithTimeout(context.Background(), (30 * time.Second))

	var msg1, msg2 [1450]byte
	rand.Read(msg1[:])
	rand.Read(msg2[:])

	var needle [32]byte
	seed := make([]byte, 20)
	rand.Read(seed)
	rand.Read(needle[:])

	ndst := func(sendMsg, recvMsg [1450]byte) {
		var recv bytes.Buffer

		conn, err := NDStream(ctx, &needle, seed)
		if err != nil {
			t.Fatal(err)
		}

		ch := make(chan struct{})
		go func() {
			defer close(ch)
			_, err := io.Copy(conn, bytes.NewReader(sendMsg[:]))
			if err != nil {
				t.Fatal(err)
			}
			err = conn.CloseWrite()
			if err != nil {
				t.Fatal(err)
			}
		}()
		_, err = io.Copy(&recv, conn)
		if err != nil {
			t.Fatal(err)
		}
		err = conn.Close()
		if err != nil {
			t.Fatal(err)
		}
		<-ch

		if !bytes.Equal(recv.Bytes(), recvMsg[:]) {
			t.Errorf("%x\n!=\n%x\n", recv.Bytes(), recvMsg[:])
		}
	}
	ch := make(chan struct{})
	go func() { ndst(msg1, msg2); close(ch) }()
	ndst(msg2, msg1)
	<-ch
}
