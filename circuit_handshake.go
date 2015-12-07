package torch

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"github.com/andres-erbsen/torch/ntor"
	"io"
)

func (circ *Circuit) create_fast() error {
	var x_y [HASH_LEN + HASH_LEN]byte
	var KH [HASH_LEN]byte
	x, y := x_y[:HASH_LEN], x_y[HASH_LEN:]
	if _, err := rand.Read(x); err != nil {
		return err
	}
	if err := circ.torConn.writeCell(cell{circ.id, CELL_CREATE_FAST, x}); err != nil {
		return err
	}
	serverHandshakeCell, ok := <-circ.recv
	if !ok {
		return fmt.Errorf("closed")
	}
	copy(y, serverHandshakeCell.payload)
	kdf := kdf_tor_new(x_y[:])
	if _, err := io.ReadFull(kdf, KH[:]); err != nil {
		return err
	}
	if !bytes.Equal(serverHandshakeCell.payload[len(y):][:HASH_LEN], KH[:]) {
		return fmt.Errorf("KH mismatch")
	}
	layer, err := circ.makeLayer(kdf)
	if err != nil {
		return err
	}
	circ.layers = []*onionLayer{layer}
	go circ.run()
	return nil
}

func (circ *Circuit) create(routerid, ntorPublic []byte) error {
	handshake, X, x := ntor.ClientHandshake(routerid[:], ntorPublic[:])
	cdata := append([]byte{0, 2, 0, byte(len(handshake))}, handshake...)
	if err := circ.torConn.writeCell(cell{circ.id, CELL_CREATE2, cdata}); err != nil { // atomic write
		return err
	}
	serverHandshakeCell, ok := <-circ.recv
	if !ok {
		return fmt.Errorf("closed")
	}

	if err := circ.addLayer(X, x, serverHandshakeCell.payload, routerid, ntorPublic); err != nil {
		return err
	}
	go circ.run()
	return nil

}

func (circ *Circuit) addLayer(X, x *[32]byte, serverHandshake, routerid, ntorPublic []byte) error {
	if len(serverHandshake) < 2 {
		return fmt.Errorf("server handshake cell too short")
	}
	handshakeLength := binary.BigEndian.Uint16(serverHandshake)
	if len(serverHandshake) < 2+int(handshakeLength) {
		return fmt.Errorf("server handshake cell too short")
	}
	ntorReply := serverHandshake[2:][:handshakeLength]
	kdf, err := ntor.ClientVerifyHandshake(routerid, ntorPublic, X, x, ntorReply)
	if err != nil {
		return err
	}
	layer, err := circ.makeLayer(kdf)
	if err != nil {
		return err
	}
	circ.layers = append(circ.layers, layer)
	return nil
}

func (circ *Circuit) makeLayer(kdf io.Reader) (*onionLayer, error) {
	buf := make([]byte, HASH_LEN+HASH_LEN+KEY_LEN+KEY_LEN)
	if _, err := io.ReadFull(kdf, buf); err != nil {
		return nil, err
	}
	sendDigest := sha1.New()
	if _, err := sendDigest.Write(buf[:HASH_LEN]); err != nil {
		return nil, err
	}
	recvDigest := sha1.New()
	if _, err := recvDigest.Write(buf[HASH_LEN:][:HASH_LEN]); err != nil {
		return nil, err
	}
	sendAES, err := aes.NewCipher(buf[HASH_LEN+HASH_LEN:][:KEY_LEN])
	if err != nil {
		return nil, err
	}
	recvAES, err := aes.NewCipher(buf[HASH_LEN+HASH_LEN+KEY_LEN:])
	if err != nil {
		return nil, err
	}
	return &onionLayer{
		sendCipher:   cipher.NewCTR(sendAES, make([]byte, 16)),
		recvCipher:   cipher.NewCTR(recvAES, make([]byte, 16)),
		sendDigest:   sendDigest,
		recvDigest:   recvDigest,
		recvWindow:   circuitRecvWindowMax,
		sendWindowCh: make(chan struct{}, circuitSendWindowMax),
	}, nil
}
