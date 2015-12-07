package torch

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

type cell struct {
	circid  []byte
	command byte
	payload []byte
}

func packCell(c cell) (ret []byte) {
	variableLength := c.command == 7 || c.command >= 128
	if !variableLength {
		if len(c.payload) > PAYLOAD_LEN {
			panic("packCell: len(payload) > PAYLOAD_LEN")
		}
		ret = make([]byte, 0, len(c.circid)+1+PAYLOAD_LEN)
	} else {
		ret = make([]byte, 0, len(c.circid)+1+2+len(c.payload))
	}
	ret = append(ret, c.circid...)
	ret = append(ret, c.command)
	if variableLength {
		ret = ret[:len(ret)+2]
		binary.BigEndian.PutUint16(ret[len(ret)-2:], uint16(len(c.payload)))
	}
	ret = append(ret, c.payload...)
	return ret[:cap(ret)]
}

func readCell(conn io.Reader, linkProtoVersion uint16) (c cell, err error) {
	for {
		c, err = readCellMaybePadding(conn, linkProtoVersion)
		if err != nil || c.command != CELL_PADDING && c.command != CELL_VPADDING {
			return
		}
	}
}

func readCellMaybePadding(conn io.Reader, linkProtoVersion uint16) (c cell, err error) {
	if linkProtoVersion < 4 {
		c.circid = make([]byte, 2)
	} else {
		c.circid = make([]byte, 4)
	}
	if _, err = io.ReadFull(conn, c.circid); err != nil {
		return
	}
	if err = binary.Read(conn, binary.BigEndian, &c.command); err != nil {
		return
	}
	payloadLength := uint16(PAYLOAD_LEN)
	if c.command == 7 || c.command >= 128 {
		if err = binary.Read(conn, binary.BigEndian, &payloadLength); err != nil {
			return
		}
	}
	c.payload = make([]byte, payloadLength)
	if _, err = io.ReadFull(conn, c.payload); err != nil {
		return
	}
	return
}

func (tc *TorConn) readVersionsCell() (canonicalVersion uint16, err error) {
	c, err := readCell(tc.tlsConn, 2)
	if err != nil {
		return
	}
	nVersions := len(c.payload) / 2
	for i := 0; i < nVersions; i++ {
		version := binary.BigEndian.Uint16(c.payload[2*i:])
		switch version {
		case 4:
			canonicalVersion = 4
		}
	}
	return
}

func (tc *TorConn) readCertsCell() (
	linkKeyCert, identityCert, authenticateCellCert *x509.Certificate,
	err error,
) {
	c, err := readCell(tc.tlsConn, tc.linkProtoVersion)
	if err != nil {
		return
	}
	payload := bytes.NewReader(c.payload)
	var nCerts byte
	if err = binary.Read(payload, binary.BigEndian, &nCerts); err != nil {
		return
	}
	for i := byte(0); i < nCerts; i++ {
		var certType byte
		if err = binary.Read(payload, binary.BigEndian, &certType); err != nil {
			return
		}
		var certLen int16
		if err = binary.Read(payload, binary.BigEndian, &certLen); err != nil {
			return
		}
		certCER := make([]byte, int(certLen))
		if _, err = io.ReadFull(payload, certCER); err != nil {
			return
		}
		cert, err := x509.ParseCertificate(certCER)
		if err != nil {
			return nil, nil, nil, err
		}
		switch certType {
		case 1: // Link key certificate certified by identity
			if linkKeyCert != nil {
				return nil, nil, nil, fmt.Errorf("multiple link key certificates")
			}
			linkKeyCert = cert
		case 2: // Identity certificate
			if identityCert != nil {
				return nil, nil, nil, fmt.Errorf("multiple identity certificates")
			}
			identityCert = cert
		case 3: // AUTHENTICATE cell link certificate
			if authenticateCellCert != nil {
				return nil, nil, nil, fmt.Errorf("multiple AUTHENTICATE cell certificates")
			}
			authenticateCellCert = cert
		}
	}
	return
}

func (tc *TorConn) readAuthChallengeCell() (
	challenge []byte,
	supportsRSASignSha256TLSSercret bool,
	err error,
) {
	c, err := readCell(tc.tlsConn, tc.linkProtoVersion)
	if err != nil {
		return
	}
	payload := bytes.NewReader(c.payload)
	challenge = make([]byte, 32)
	if _, err = io.ReadFull(payload, challenge); err != nil {
		return
	}
	var nMethods int16
	if err = binary.Read(payload, binary.BigEndian, &nMethods); err != nil {
		return
	}
	for i := int16(0); i < nMethods; i++ {
		var method int16
		if err = binary.Read(payload, binary.BigEndian, &method); err != nil {
			return
		}
		switch method {
		case 1:
			supportsRSASignSha256TLSSercret = true
		}
	}
	return
}

func netInfoCell(now time.Time, ourAddress net.Addr, theirAddress net.Addr, linkProtoVersion uint16) []byte {
	var circid []byte
	if linkProtoVersion < 4 {
		circid = make([]byte, 2)
	} else {
		circid = make([]byte, 4)
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(now.Unix()))
	if ourAddress != nil {
		panic("not implemented")
	} else {
		buf = append(buf, 0, 0)
	}
	if theirAddress != nil {
		panic("not implemented")
	} else {
		buf = append(buf, 0, 0)
	}
	return packCell(cell{circid, CELL_NETINFO, buf})
}

// XXX not implemented, just ignores the cell
func (tc *TorConn) readNetInfoCell() error {
	_, err := readCell(tc.tlsConn, tc.linkProtoVersion)
	if err != nil {
		return err
	}
	return nil
}

/*
func (tc *torConn) readCreated2Cell() ([]byte, error) {
	circid, command, payload, err := readCell(tc.tlsConn, tc.linkProtoVersion)
	if command != CELL_CREATED2 {
		return nil, fmt.Errorf("got circid %v command %v (expected CREATED2=%d)", circid, command, CELL_CREATED2)
	}

	if err != nil {
		return nil, err
	}
	defer ioutil.ReadAll(payload)
	var length uint16
	if err = binary.Read(payload, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	handshake := make([]byte, length)
	_, err = io.ReadFull(payload, handshake)
	return handshake, nil
}
*/
