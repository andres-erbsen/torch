package directory

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"github.com/andres-erbsen/torch/directory/bufio"
	"io"
)

func ReadMicrodescriptors(r_ io.Reader, shortInfos []*ShortNodeInfo) ([]*NodeInfo, error) {
	h := sha256.New()
	r := bufio.NewDelimitedReader(io.MultiReader(bytes.NewReader([]byte{'\n'}), r_), []byte("onion-key\n"))

	byMDDigest := make(map[[32]byte]*ShortNodeInfo, len(shortInfos))
	for _, node := range shortInfos {
		byMDDigest[node.MicrodescriptorDigest] = node
	}
	nodes := make([]*NodeInfo, 0, len(shortInfos))
	scanner := bufio.NewScanner(nil)

	for r.Next() {
		node := new(NodeInfo)
		h.Reset()
		h.Write([]byte("onion-key\n"))
		scanner.Reset(io.TeeReader(r, h))

		scanner.Split(bufio.ScanPEM)
		scanner.Scan()
		if _, err := asn1.Unmarshal(scanner.Bytes(), &node.OnionKey); err != nil {
			continue
		}

		scanner.Split(bufio.ScanUntilByte('\n', bufio.ScanByteDelimited(' ')))
		for scanner.Scan() {
			switch scanner.Text() {
			case "ntor-onion-key":
				scanner.Scan()
				node.NTorOnionKey, _ = base64.StdEncoding.DecodeString(scanner.Text() + "=")
			case "a":
				scanner.Scan()
				node.Addresses = append(node.Addresses, scanner.Text())
			case "p":
				scanner.Scan()
				node.ExitPolicy4 = scanner.Text()
			case "p6":
				scanner.Scan()
				node.ExitPolicy6 = scanner.Text()
			case "family":
				for scanner.Scan() && len(scanner.Text()) > 0 {
					if scanner.Text()[0] == '$' {
						node.FamilyFingerprints = append(node.FamilyFingerprints, scanner.Text()[1:])
					} else {
						node.FamilyNicknames = append(node.FamilyNicknames, scanner.Text())
					}
				}
			}
			scanner.Split(bufio.ScanByteDelimited('\n'))
			scanner.Scan()
			scanner.Split(bufio.ScanUntilByte('\n', bufio.ScanByteDelimited(' ')))
		}

		var microdescriptorDigest [32]byte
		copy(microdescriptorDigest[:], h.Sum(nil))
		shortInfo, ok := byMDDigest[microdescriptorDigest]
		if !ok {
			continue
		}
		node.ShortNodeInfo = shortInfo
		nodes = append(nodes, node)
	}
	return nodes, scanner.Err()
}
