package nd

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/andres-erbsen/torch"
	"github.com/andres-erbsen/torch/config"
	"github.com/andres-erbsen/torch/directory"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/net/context"
	"golang.org/x/net/proxy"
)

type NetDog struct {
	dirConn   *torch.TorConn
	dirCirc   *torch.Circuit
	dirClient *http.Client
	routers   []*directory.ShortNodeInfo
}

func Prepare(ctx context.Context) (*NetDog, error) {
	dirConn, circ, err := torch.BuildDirectoryCircuit(ctx, config.BootstrapDirectories[:], proxy.FromEnvironment())
	if err != nil {
		return nil, err
	}

	c := &http.Client{
		Transport: &http.Transport{
			Dial:                  circ.Dial,
			MaxIdleConnsPerHost:   1,
			ResponseHeaderTimeout: 30 * time.Second,
		},
		Timeout: 90 * time.Second,
	}

	consensus, _, err := torch.DownloadConsensus(c, config.AuthorityFingerprints[:])
	if err != nil {
		return nil, err
	}

	return &NetDog{dirConn, circ, c, consensus.Routers}, nil
}

func (nd *NetDog) Close() error {
	nd.routers = nil
	nd.dirClient = nil
	return nd.dirConn.Close()
}

func Pick(routers []*directory.ShortNodeInfo, needle *[32]byte) *directory.ShortNodeInfo {
	var highestNotGreater *directory.ShortNodeInfo
	for _, ni := range routers {
		if bytes.Compare(ni.ID[:], needle[:]) <= 0 &&
			(highestNotGreater == nil || bytes.Compare(ni.ID[:], highestNotGreater.ID[:]) > 0) {
			highestNotGreater = ni
		}
	}
	if highestNotGreater != nil {
		return highestNotGreater
	}
	highestOverall := routers[0]
	for _, ni := range routers {
		if bytes.Compare(ni.ID[:], highestOverall.ID[:]) > 0 {
			highestOverall = ni
		}
	}
	return highestOverall
}

// connect requires len(cookie) = 20 and len(sendPayload) == 148. Nondeterminisitcally, EITHER
// the sendPayload is sent to the peer OR their sendPayload is returned here, not both.
func connect(ctx context.Context, c1, c2 *torch.Circuit, cookie []byte, sendPayload []byte) (*torch.Circuit, []byte, error) {
	if accept, err := c1.ListenRendezvousRaw(cookie); err == nil {
		c2.Close()

		recvPayload, err := accept()
		if err != nil {
			c1.Close()
			return nil, nil, err
		}

		return c1, recvPayload, nil
	}
	c1.Close()

	if err := c2.DialRendezvousRaw(cookie, sendPayload); err != nil {
		c2.Close()
		return nil, nil, err
	}
	return c2, nil, nil
}

func ND(ctx context.Context, needle *[32]byte, seed []byte) (*Conn, error) {
	nd, err := Prepare(ctx)
	if err != nil {
		return nil, err
	}
	defer nd.Close()

	mid_, err := torch.DownloadMicrodescriptors(nd.dirClient, []*directory.ShortNodeInfo{Pick(nd.routers, needle)})
	if err != nil {
		return nil, err
	}
	if len(mid_) != 1 {
		return nil, fmt.Errorf("!=1 md")
	}
	mid := mid_[0]

	tc, err := torch.DialOnionRouter(ctx, (net.IP)(mid.IP[:]).String()+":"+fmt.Sprint(mid.Port), mid.ID[:], proxy.FromEnvironment())
	if err != nil {
		return nil, err
	}

	c1, err := tc.CreateCircuit(ctx, mid.ID[:], mid.NTorOnionKey)
	if err != nil {
		return nil, err
	}
	c2, err := tc.CreateCircuit(ctx, mid.ID[:], mid.NTorOnionKey)
	if err != nil {
		return nil, err
	}
	return Handshake(ctx, c1, c2, seed)
}

func Handshake(ctx context.Context, c1, c2 *torch.Circuit, sharedSecret []byte) (*Conn, error) {
	// NOTE: one of the circuits is only needed after a couple of network round
	// trips, so it may be a good idea to pass in a <-chan *Circuit instead.
	kdf := hkdf.New(sha256.New, sharedSecret, nil, nil)
	var cookie [20]byte
	var authKeyAccept, authKeyDial, continueKey [32]byte
	if _, err := io.ReadFull(kdf, cookie[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(kdf, authKeyAccept[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(kdf, authKeyDial[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(kdf, continueKey[:]); err != nil {
		return nil, err
	}
	pk, sk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var theirPK [32]byte
	vouchDial := secretbox.Seal(nil, pk[:], &[24]byte{}, &authKeyDial)

	circ, theirVouchDial, err := connect(ctx, c1, c2, cookie[:], vouchDial[:])
	if err != nil {
		return nil, err
	}
	if theirVouchDial != nil {
		if len(theirVouchDial) < 32+box.Overhead {
			return nil, fmt.Errorf("rend payload too short: %d < %d", len(theirVouchDial), 32+box.Overhead)
		}
		theirPKbytes, ok := secretbox.Open(nil, theirVouchDial[:32+box.Overhead], &[24]byte{}, &authKeyDial)
		if !ok {
			return nil, fmt.Errorf("authentication failed")
		}
		copy(theirPK[:], theirPKbytes)
		err := circ.WriteRaw(secretbox.Seal(make([]byte, 0, torch.PAYLOAD_LEN), pk[:], &[24]byte{}, &authKeyAccept)[:torch.PAYLOAD_LEN])
		if err != nil {
			return nil, err
		}
	} else {
		theirVouchAccept, err := circ.ReadRaw()
		if err != nil {
			return nil, err
		}
		theirPKbytes, ok := secretbox.Open(nil, theirVouchAccept[:32+box.Overhead], &[24]byte{}, &authKeyAccept)
		if !ok {
			return nil, fmt.Errorf("authentication failed")
		}
		copy(theirPK[:], theirPKbytes)
	}
	var sharedDH [32]byte
	curve25519.ScalarMult(&sharedDH, sk, &theirPK)
	ret := &Conn{
		Circuit: circ,
		KDF:     hkdf.New(sha256.New, append(continueKey[:], sharedDH[:]...), nil, nil),
		Bit:     theirVouchDial != nil,
	}
	if ret.Bit {
		inc(&ret.writeNonce)
	} else {
		inc(&ret.readNonce)
	}
	if _, err := io.ReadFull(kdf, ret.key[:]); err != nil {
		return nil, err
	}
	return ret, nil
}

func NDStream(ctx context.Context, needle *[32]byte, seed []byte) (*Stream, error) {
	conn, err := ND(ctx, needle, seed)
	if err != nil {
		return nil, err
	}
	return &Stream{ndc: conn}, nil
}
