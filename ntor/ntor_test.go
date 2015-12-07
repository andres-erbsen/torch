package ntor

import (
	"bytes"
	"crypto/rand"
	"golang.org/x/crypto/curve25519"
	"io"
	"testing"
)

func read32(r io.Reader) []byte {
	var ret [32]byte
	_, err := io.ReadFull(r, ret[:])
	if err != nil {
		panic(err)
	}
	return ret[:]
}

func keygen() (*[32]byte, *[32]byte) {
	var b, B [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	curve25519.ScalarBaseMult(&B, &b)
	return &B, &b
}

func TestKeyAgreement(t *testing.T) {
	ID := [20]byte{1, 2, 3, 4, 5, 6, 7, 7, 12, 241, 21}
	B, b := keygen()
	hs1, X, x := ClientHandshake(ID[:], B[:])
	hs2, k_s := ServerHandshake(b, hs1)
	k_c, err := ClientVerifyHandshake(ID[:], B[:], X, x, hs2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read32(k_s), read32(k_c)) {
		t.Fatal("keys do not agree")
	}
}

func TestWrongKey(t *testing.T) {
	ID := [20]byte{1, 2, 3, 4, 5, 6, 7, 7, 12, 241, 21}
	B, _ := keygen()
	_, b2 := keygen()
	hs1, X, x := ClientHandshake(ID[:], B[:])
	hs2, _ := ServerHandshake(b2, hs1)
	k_c, err := ClientVerifyHandshake(ID[:], B[:], X, x, hs2)
	if err == nil {
		t.Fatal(err)
	}
	if k_c != nil {
		t.Fatal()
	}
}
