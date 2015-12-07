package ntor

import (
	"io"
	"fmt"
	"crypto/sha256"
	"golang.org/x/crypto/hkdf"
	"crypto/subtle"
	"crypto/hmac"
	"crypto/rand"
	"golang.org/x/crypto/curve25519"
)

var (
	PROTOID = []byte("ntor-curve25519-sha256-1")
	T_mac     = []byte(string(PROTOID) + ":mac")
	T_key     = []byte(string(PROTOID) + ":key_extract")
	T_verify  = []byte(string(PROTOID) + ":verify")
	M_expand  = []byte(string(PROTOID) + ":key_expand")
)

const (
	H_LENGTH = 32
	ID_LENGTH = 20
	G_LENGTH  = 32
	CLIENT_HANDSHAKE_LENGTH = ID_LENGTH + G_LENGTH + G_LENGTH
)

func cat(slices ...[]byte) []byte {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	ret := make([]byte, length)
	i := 0
	for _, slice := range slices {
		copy(ret[i:], slice)
		i += len(slice)
	}
	return ret
}

func H(message, tweak []byte) []byte {
	w := hmac.New(sha256.New, tweak)
	if _, err := w.Write(message); err != nil {
		panic(err)
	}
	return w.Sum(nil)
}

func ClientHandshake(ID, B []byte) (client_handshake []byte, X_, x_ *[G_LENGTH]byte) {
	var X, x [G_LENGTH]byte
	if _, err := rand.Read(x[:]); err != nil {
		panic(err)
	}
	curve25519.ScalarBaseMult(&X, &x)
	return cat(ID, B, X[:]), &X, &x
}

// ServerHandshake computes a response to a client handshake with with public
// DH value X using the ntor-onion-key B and the corresponding secret key b.
func ServerHandshake(b *[G_LENGTH]byte, client_handshake []byte) (serverHandshake []byte, kdf io.Reader) {
	var ID [ID_LENGTH]byte
	var B, X, y, Y, g_to_xy, g_to_xb [G_LENGTH]byte
	copy(ID[:], client_handshake[:ID_LENGTH])
	copy(B[:], client_handshake[ID_LENGTH:][:G_LENGTH])
	copy(X[:], client_handshake[ID_LENGTH+G_LENGTH:])
	if _, err := rand.Read(y[:]); err != nil {
		panic(err)
	}
	curve25519.ScalarBaseMult(&Y, &y)
	curve25519.ScalarMult(&g_to_xy, &y, &X)
	curve25519.ScalarMult(&g_to_xb, b, &X)
	// TODO: "Both parties check that none of the EXP() operations produced the point at infinity"
	secret_input := cat(g_to_xy[:], g_to_xb[:], ID[:], B[:], X[:], Y[:], PROTOID)
	verify := H(secret_input, T_verify)
	auth_input := cat(verify, ID[:], B[:], Y[:], X[:], PROTOID, []byte("Server"))
	return cat(Y[:], H(auth_input, T_mac)), hkdf.New(sha256.New, secret_input, T_key, M_expand)
}

func ClientVerifyHandshake(ID, B_ []byte, X, x *[G_LENGTH]byte, serverHandshake []byte) (io.Reader, error) {
	if len(serverHandshake) < G_LENGTH + H_LENGTH {
		return nil, fmt.Errorf("server handshake too short: %d < %d", len(serverHandshake), G_LENGTH+H_LENGTH)
	}
	var B, Y, g_to_xy, g_to_xb [G_LENGTH]byte
	copy(Y[:], serverHandshake[:G_LENGTH])
	copy(B[:], B_)
	curve25519.ScalarMult(&g_to_xy, x, &Y)
	curve25519.ScalarMult(&g_to_xb, x, &B)
	// TODO: "Both parties check that none of the EXP() operations produced the point at infinity"
	secret_input := cat(g_to_xy[:], g_to_xb[:], ID, B[:], X[:], Y[:], PROTOID)
	verify := H(secret_input, T_verify)
	auth_input := cat(verify, ID, B[:], Y[:], X[:], PROTOID, []byte("Server"))
	if subtle.ConstantTimeCompare(H(auth_input, T_mac), serverHandshake[G_LENGTH:][:H_LENGTH]) != 1 {
		return nil, fmt.Errorf("authentication failed")
	}
	return hkdf.New(sha256.New, secret_input, T_key, M_expand), nil
}
