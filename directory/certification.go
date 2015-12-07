package directory

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"github.com/andres-erbsen/torch/directory/bufio"
	"io"
	"reflect"
	"strings"
	"time"
)

type cacheKey struct {
	idHashHex, signingHashHex string
}

type certification struct {
	notBefore, notAfter time.Time
	signingKey          *rsa.PublicKey
}

type AuthoritySet struct {
	now   func() time.Time
	cache map[cacheKey]*certification
}

func (c *AuthoritySet) NumAuthorities() int {
	s := make(map[string]struct{})
	for k := range c.cache {
		s[k.idHashHex] = struct{}{}
	}
	return len(s)
}

func (c *AuthoritySet) SigningKey(idHashHex, signingHashHex string) *rsa.PublicKey {
	r, ok := c.cache[cacheKey{idHashHex, signingHashHex}]
	if !ok {
		return nil
	}
	t := time.Now()
	if t.Before(r.notBefore) || t.After(r.notAfter) {
		return nil
	}
	return r.signingKey
}

// ReadCertifications updates signingKeys and identities whenever sufficient
// cross-certification is provided
func ReadCertifications(r io.Reader, allowedFingerprints []string) *AuthoritySet {
	ret := &AuthoritySet{cache: make(map[cacheKey]*certification)}
	ret.now = time.Now
	dr := bufio.NewDelimitedReader(io.MultiReader(bytes.NewReader([]byte{'\n'}), r), []byte("\ndir-key-certificate-version "))
	for dr.Next() {
		ParseCertification(dr, ret)
	}
outer:
	for k := range ret.cache {
		for _, allowed := range allowedFingerprints {
			if k.idHashHex == allowed {
				continue outer
			}
		}
		delete(ret.cache, k)
	}
	return ret
}

func ParseCertification(r io.Reader, cache *AuthoritySet) error {
	ret := new(certification)
	h := sha1.New()
	h.Write([]byte("dir-key-certificate-version "))
	hw := bufio.WriteUntil(h, []byte("\ndir-key-certification\n"))
	scanner := bufio.NewScanner(io.TeeReader(r, hw))
	if !scanner.Scan() || scanner.Text() != "3" {
		return fmt.Errorf("expected \"3\", got \"%s\"", scanner.Text())
	}
	scanner.Split(bufio.ScanUntilByte('\n', bufio.ScanByteDelimited(' ')))

	var idKey *rsa.PublicKey
	var idHashHex string
	var idSiganture, signingSignID []byte

	for scanner.Scan() {
		switch scanner.Text() {
		case "fingerprint":
			if idHashHex != "" {
				return fmt.Errorf("duplicate fingerprint")
			}
			scanner.Scan()
			idHashHex = strings.ToLower(scanner.Text())
		case "dir-key-published":
			scanner.Scan()
			dateStr := scanner.Text()
			scanner.Scan()
			timeStr := scanner.Text()
			ret.notBefore, _ = time.Parse("2006-01-02 15:04:05", dateStr+" "+timeStr)
		case "dir-key-expires":
			scanner.Scan()
			dateStr := scanner.Text()
			scanner.Scan()
			timeStr := scanner.Text()
			ret.notAfter, _ = time.Parse("2006-01-02 15:04:05", dateStr+" "+timeStr)
		case "dir-identity-key":
			idKey = new(rsa.PublicKey)
			scanner.Split(bufio.ScanPEM)
			scanner.Scan()
			if _, err := asn1.Unmarshal(scanner.Bytes(), idKey); err != nil {
				return err
			}
		case "dir-signing-key":
			ret.signingKey = new(rsa.PublicKey)
			scanner.Split(bufio.ScanPEM)
			scanner.Scan()
			if _, err := asn1.Unmarshal(scanner.Bytes(), ret.signingKey); err != nil {
				return err
			}
		case "dir-key-crosscert":
			scanner.Split(bufio.ScanPEM)
			scanner.Scan()
			signingSignID = append([]byte(nil), scanner.Bytes()...)
		case "dir-key-certification": // at end, exactly once
			scanner.Split(bufio.ScanPEM)
			scanner.Scan()
			idSiganture = append([]byte(nil), scanner.Bytes()...)
		}

		scanner.Split(bufio.ScanByteDelimited('\n'))
		if !scanner.Scan() {
			break
		}
		scanner.Split(bufio.ScanUntilByte('\n', bufio.ScanByteDelimited(' ')))
	}
	h.Write([]byte("\ndir-key-certification\n"))

	if idKey == nil {
		return fmt.Errorf("id key missing")
	}
	if ret.signingKey == nil {
		return fmt.Errorf("sig key missing")
	}

	idHash, err := HashPublicKey(idKey)
	if err != nil {
		return err
	}
	if fingerprintBytes, err := hex.DecodeString(idHashHex); err != nil {
		return err
	} else if !bytes.Equal(fingerprintBytes, idHash) {
		return fmt.Errorf("fingerprint does not match")
	}

	signingHash, err := HashPublicKey(ret.signingKey)
	if err != nil {
		return err
	}
	signingHashHex := hex.EncodeToString(signingHash)

	mapKey := cacheKey{idHashHex, signingHashHex}
	if reflect.DeepEqual(cache.cache[mapKey], ret) {
		return nil // no change regardless of whether signatures are valid or not
	}

	if err := rsa.VerifyPKCS1v15(idKey, 0, h.Sum(nil), idSiganture); err != nil {
		return fmt.Errorf("bad signature from id key: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(ret.signingKey, 0, idHash, signingSignID); err != nil {
		return fmt.Errorf("bad signature from signing key: %v", err)
	}

	cache.cache[mapKey] = ret
	return nil
}
