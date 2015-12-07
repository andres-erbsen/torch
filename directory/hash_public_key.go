package directory

import (
	"encoding/asn1"
	"crypto/sha1"
	"crypto/rsa"
	"math/big"
	"fmt"
)

func HashPublicKey(pub interface{}) ([]byte, error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		publicKeyBytes, err := asn1.Marshal(struct{*big.Int;int}{pub.N, pub.E})
		if err != nil {
			return nil, err
		}
		ret := sha1.Sum(publicKeyBytes)
		return ret[:], nil
	default:
		return nil, fmt.Errorf("unsupported public key type")
	}
}
