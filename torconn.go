package torch

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"reflect"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/net/proxy"

	"github.com/andres-erbsen/torch/directory"
)

// torConn implements the TOR link protocol. Only link protocol version 4 is
// supported.
type TorConn struct {
	// initialized by constructor, then immutable
	tlsConn          *tls.Conn
	linkProtoVersion uint16

	circuits             map[string]*Circuit
	requestDeleteCircuit chan deleteCircuitRequest
	requestNewCircuit    chan newCircuitRequest

	cancel      func()
	stopped     chan struct{}
	errForClose error
}

type deleteCircuitRequest struct {
	id  []byte
	ret chan<- struct{}
}

type newCircuitRequest struct {
	ctx context.Context
	ret chan<- *Circuit
}

func DialOnionRouter(ctx context.Context, address string, ID []byte, dialer proxy.Dialer) (*TorConn, error) {
	ctx, cancel := context.WithCancel(ctx)
	tcpConn, err := dialer.Dial("tcp", address) // FIXME: proxy.Dialer with a deadline
	if err != nil {
		return nil, fmt.Errorf("DialOnionRouter: %v", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		tcpConn.SetDeadline(deadline)
	}
	// spec paragraph 2: All implementations MUST support the SSLv3 ciphersuite
	// SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA. This is infortunately not present in
	// Go. Let's turn on SSL3 support anyway...
	tlsConn := tls.Client(tcpConn, &tls.Config{
		MinVersion:         tls.VersionSSL30,
		InsecureSkipVerify: true,
		Time: func() time.Time {
			return time.Time{}
		}})
	if _, err = tlsConn.Write(packCell(cell{[]byte{0, 0}, CELL_VERSIONS, []byte{0, 4}})); err != nil {
		return nil, fmt.Errorf("DialOnionRouter: tlsConn{%s}.Write: %v", address, err)
	}
	tc := &TorConn{
		tlsConn:          tlsConn,
		linkProtoVersion: 2, // will be overwritten by the handshake

		circuits:             make(map[string]*Circuit),
		requestNewCircuit:    make(chan newCircuitRequest),
		requestDeleteCircuit: make(chan deleteCircuitRequest),

		cancel:  cancel,
		stopped: make(chan struct{}),
	}
	tc.linkProtoVersion, err = tc.readVersionsCell()
	if err != nil {
		return nil, fmt.Errorf("DialOnionRouter: readVersionsCell{%s}.Write: %v", address, err)
	}
	if tc.linkProtoVersion == 0 {
		return nil, fmt.Errorf("no supported protocol versions in common")
	}
	if err = tc.authenticateResponder(ID); err != nil {
		return nil, fmt.Errorf("DialOnionRouter: tc.authenticateResponder{%s}.Write: %v", address, err)
	}
	if _, err = tlsConn.Write(netInfoCell(time.Time{}, nil, nil, tc.linkProtoVersion)); err != nil {
		return nil, fmt.Errorf("DialOnionRouter: tlsConn.Write(netInfoCell...) {%s}.Write: %v", address, err)
	}
	if _, _, err = tc.readAuthChallengeCell(); err != nil {
		return nil, fmt.Errorf("DialOnionRouter: tc.readAuthChallengeCell{%s}.Write: %v", address, err)
	}
	if err = tc.readNetInfoCell(); err != nil {
		return nil, fmt.Errorf("DialOnionRouter: tc.readNetInfoCell{%s}.Write: %v", address, err)
	}
	go tc.run(ctx)
	return tc, nil
}

func (tc *TorConn) authenticateResponder(expectedID []byte) error {
	// To authenticate the responder, the initiator MUST check the following:
	// * The CERTS cell contains exactly one CertType 1 "Link" certificate.
	// * The CERTS cell contains exactly one CertType 2 "ID" certificate.
	linkCert, idCert, _, err := tc.readCertsCell()
	if err != nil {
		return err
	}
	if linkCert == nil {
		return fmt.Errorf("missing link key certificate in CERTS cell")
	}
	if idCert == nil {
		return fmt.Errorf("missing id certificate in CERTS cell")
	}
	// * Both certificates have validAfter and validUntil dates that
	//   are not expired.
	now := time.Now()
	if now.Before(linkCert.NotBefore) || now.After(linkCert.NotAfter) {
		return fmt.Errorf("link certificate time constraints not satisfied")
	}
	if now.Before(idCert.NotBefore) || now.After(idCert.NotAfter) {
		return fmt.Errorf("id certificate time constraints not satisfied")
	}
	connCert := tc.tlsConn.ConnectionState().PeerCertificates[0]

	// * The certified key in the Link certificate matches the  link key that
	// was used to negotiate the TLS connection.
	if !reflect.DeepEqual(linkCert.PublicKey, connCert.PublicKey) {
		return fmt.Errorf("link key does not match TLS connection key")
	}
	// * The certified key in the ID certificate is a 1024-bit RSA key.
	if rsaKey, ok := idCert.PublicKey.(*rsa.PublicKey); !ok || rsaKey.N.BitLen() != 1024 || idCert.PublicKeyAlgorithm != x509.RSA {
		return fmt.Errorf("the certified key in the ID certificate is NOT a 1024-bit RSA key (algo %v type %T)", idCert.PublicKeyAlgorithm, idCert.PublicKey)
	}
	// * The certified key in the ID certificate was used to sign both
	// certificates.
	if err = idCert.CheckSignature(linkCert.SignatureAlgorithm, linkCert.RawTBSCertificate, linkCert.Signature); err != nil {
		return err
	}
	// * The ID certificate is correctly self-signed.
	// * The link certificate is correctly signed with the key in the ID
	// certificate
	if err = idCert.CheckSignature(idCert.SignatureAlgorithm, idCert.RawTBSCertificate, idCert.Signature); err != nil {
		return err
	}
	ID, err := directory.HashPublicKey(idCert.PublicKey)
	if !bytes.Equal(ID, expectedID) {
		return fmt.Errorf("expected sha1(pk) = %x, got %x", expectedID, ID)
	}
	return nil
}

// unusedCircID MUST be called from run()
func (tc *TorConn) unusedCircID() []byte {
	if tc.linkProtoVersion != 4 {
		panic("unusedCircID: reimplement for other protocols by tor-spec.txt section 4.1")
	}
	var d [4]byte
	for {
		rand.Read(d[:])
		d[0] |= (1 << 7) // protocol version 4: the node that initiated the connection sets the big-endian MSB to 1
		if _, used := tc.circuits[string(d[:])]; !used {
			return d[:]
		}
	}
}

type maybeCell struct {
	c   cell
	err error
}

func (tc *TorConn) recvLoop(ctx context.Context, ch chan<- maybeCell) {
	for {
		c, err := readCell(tc.tlsConn, tc.linkProtoVersion)
		if err != nil {
			c = cell{}
		}
		select {
		case ch <- maybeCell{c, err}:
		case <-ctx.Done():
			return
		}
	}
}

func (tc *TorConn) run(ctx context.Context) {
	defer close(tc.stopped)
	recvCh := make(chan maybeCell)
	go tc.recvLoop(ctx, recvCh)

	for {
		select {
		case mc := <-recvCh:
			if mc.err != nil {
				tc.errForClose = mc.err
				tc.cancel()
				continue
			}
			circuit, present := tc.circuits[string(mc.c.circid)]
			if !present {
				fmt.Printf("message for unknown circuit %v\n", mc.c.circid)
				continue
			}
			select {
			case circuit.recv <- mc.c:
			case <-circuit.ctx.Done():
				// circuit is shutting down
			case <-ctx.Done():
				// connection is shutting down
			}
		case rq := <-tc.requestNewCircuit:
			id := tc.unusedCircID()
			circ := makeCircuit(rq.ctx, tc, id)
			tc.circuits[string(id)] = circ
			rq.ret <- circ
		case rq := <-tc.requestDeleteCircuit:
			tc.handleDeleteCircuit(rq)
		case <-ctx.Done():
			if err := tc.tlsConn.Close(); tc.errForClose == nil {
				tc.errForClose = err
			}
			if err := ctx.Err(); tc.errForClose == nil {
				tc.errForClose = err
			}
			for _, circ := range tc.circuits {
				go func(circ *Circuit) { circ.asyncErr <- fmt.Errorf("torConn shut down: %s", tc.errForClose) }(circ)
			}
			for len(tc.circuits) != 0 {
				tc.handleDeleteCircuit(<-tc.requestDeleteCircuit)
			}
			return
		}
	}
}

func (tc *TorConn) handleDeleteCircuit(rq deleteCircuitRequest) {
	if _, ok := tc.circuits[string(rq.id)]; !ok {
		panic("delete of nonexistent circuit")
	}
	delete(tc.circuits, string(rq.id))
	rq.ret <- struct{}{}
}

func (tc *TorConn) deleteCircuit(id []byte) {
	ch := make(chan struct{})
	tc.requestDeleteCircuit <- deleteCircuitRequest{id, ch}
	select {
	case <-ch:
	case <-tc.stopped:
	}
}

func (tc *TorConn) Close() error {
	tc.cancel()
	<-tc.stopped
	if tc.errForClose != context.Canceled {
		return tc.errForClose
	} else {
		return nil
	}
}

func (tc *TorConn) newCircuit(ctx context.Context) (*Circuit, error) {
	ch := make(chan *Circuit)
	select {
	case tc.requestNewCircuit <- newCircuitRequest{ctx, ch}:
		return <-ch, nil
	case <-tc.stopped:
		return nil, fmt.Errorf("tor connection is shutting down: %s", tc.errForClose)
	}
}

func (tc *TorConn) CreateCircuit(ctx context.Context, routerid, ntorPublic []byte) (*Circuit, error) {
	circ, err := tc.newCircuit(ctx)
	if err != nil {
		return nil, err
	}
	return circ, circ.create(routerid, ntorPublic)
}

func (tc *TorConn) createCircuitInsecure(ctx context.Context) (*Circuit, error) {
	circ, err := tc.newCircuit(ctx)
	if err != nil {
		return nil, err
	}
	return circ, circ.create_fast()
}

func (tc *TorConn) writeCell(c cell) error {
	_, err := tc.tlsConn.Write(packCell(c))
	select {
	case <-tc.stopped:
		return fmt.Errorf("tor connection is shutting down: %s (write got %s)", tc.errForClose, err)
	default:
		return err
	}
}
