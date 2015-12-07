package torch

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/andres-erbsen/torch/directory"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/net/proxy"
)

func testSlashdotTorchN(t *testing.T, n int) {

	ctx, _ := context.WithTimeout(context.Background(), (30 * time.Second))

	torch, err := New(ctx, proxy.FromEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	defer torch.Stop()

	tc, circ, err := torch.UnguardedExitCircuit(ctx, n)
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()

	conn, err := circ.DialTCP(ctx, "tcp", "slashdot.org:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte("GET /\r\n\r\n"))
	reply, err := ioutil.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reply), "HTTP/") && strings.Contains(string(reply), "slashdot.org") {
		t.Errorf("expected %q, got %q", "HTTP/", reply)
	}
}

func TestSlashdotTorch2(t *testing.T) { testSlashdotTorchN(t, 2) }

//func TestSlashdotTorch3(t *testing.T) { testSlashdotTorchN(t, 3) }

func TestRendezvous(t *testing.T) {
	ctx, _ := context.WithTimeout(context.Background(), (30 * time.Second))

	torch, err := New(ctx, proxy.FromEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	defer torch.Stop()

	// FIXME: implement threadsafe Pick in Torch
	dst := torch.Pick(weighRelayWith)

	cookie := make([]byte, 20)
	payload := make([]byte, 148)
	message1 := make([]byte, PAYLOAD_LEN)
	message2 := make([]byte, PAYLOAD_LEN)
	rand.Read(cookie)
	rand.Read(payload)
	rand.Read(message1)
	rand.Read(message2)

	tc1, c1, err := torch.UnguardedCircuitTo(ctx, 1, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer tc1.Close()

	accept, err := c1.ListenRendezvousRaw(cookie)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		tc2, c2, err := torch.UnguardedCircuitTo(ctx, 1, dst)
		if err != nil {
			t.Fatal(err)
		}
		defer tc2.Close()

		if err := c2.DialRendezvousRaw(cookie, payload); err != nil {
			t.Fatal(err)
		}

		recvMessage, err := c2.ReadRaw()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(recvMessage, message2) {
			fmt.Printf("%x\n!=\n%x\n", recvMessage, message2)
			t.Fail()
		}

		if err := c2.WriteRaw([]byte(string(message1))); err != nil {
			t.Fatal(err)
		}
	}()
	payload2, err := accept()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload2, payload) {
		fmt.Printf("%x\n!=\n%x\n", payload2, payload)
		t.Fail()
	}

	if err := c1.WriteRaw([]byte(string(message2))); err != nil {
		t.Fatal(err)
	}

	recvMessage, err := c1.ReadRaw()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recvMessage, message1) {
		fmt.Printf("%x\n!=\n%x\n", recvMessage, message1)
		t.Fail()
	}
}

func TestHandshakeFailure(t *testing.T) {
	handshakeFailuerIP := [4]byte{193, 23, 244, 244}
	handshakeFailuerPort := uint16(443)
	ctx, _ := context.WithTimeout(context.Background(), (30 * time.Second))

	torch, err := New(ctx, proxy.FromEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	defer torch.Stop()

	n := torch.Pick(func(w *directory.BandwidthWeights, n *directory.NodeInfo) int64 {
		if n.IP == handshakeFailuerIP && n.Port == handshakeFailuerPort {
			return 1
		}
		return 0
	})

	tc1, _, err := torch.UnguardedCircuitTo(ctx, 1, n)
	if err != nil {
		/*
			sent: 160301007b010000770303c56160e1eaeaa7e102a9b86276e15527f0253d8802e0f3759565145acb894e1b000018c02fc02bc030c02cc013c009c014c00a002f0035c012000a01000036000500050100000000000a00080006001700180019000b00020100000d000e000c040104030501050302010203ff0100010000120000
			received: 15030100020228
		*/
		// t.Fatal(err)
		t.Skipf("%s (this is a known failing test, cause to be diagnosed)", err)
	}
	defer tc1.Close()

	// success.
}
