package directory

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/andres-erbsen/torch/directory/bufio"
	"io"
	"log"
	mathrand "math/rand"
	"strconv"
	"strings"
	"time"
)

// 212.112.245.170/tor/status-vote/current/consensus-microdesc/14C131+27B6B5+49015F+585769+805509+D586D1+E8A9C4+ED03BB+EFCBE7.z
// tor.noreply.org/tor/micro/d/MrvCj76HvmISlvtspAVTjzcp7p0NuCkUkUYg3Gs6Cig-xzZVjbCMiNkkTlWOWAcwqXWTTJYz9vDs37gam8kDiLA.z
func ReadMicrodescriptorConsensus(r io.Reader, authorities Authorities, nRequired int) (*Consensus, error) {
	h := sha256.New()
	hw := bufio.WriteUntil(h, []byte("\ndirectory-signature "))
	ret := &Consensus{Routers: make([]*ShortNodeInfo, 0, 1<<13)}
	scanner := bufio.NewScanner(io.TeeReader(r, hw))
	if !scanner.Scan() || scanner.Text() != "network-status-version 3 microdesc" {
		if scanner.Err != nil {
			return nil, scanner.Err()
		}
		return nil, fmt.Errorf("expected line: network-status-version 3 microdesc")
	}
	if !scanner.Scan() || scanner.Text() != "vote-status consensus" {
		if scanner.Err != nil {
			return nil, scanner.Err()
		}
		return nil, fmt.Errorf("expected line: vote-status consensus")
	}
	info := new(ShortNodeInfo)
	scanner.Split(bufio.ScanUntilByte('\n', bufio.ScanByteDelimited(' ')))
	for done := false; !done && scanner.Scan(); {
		switch scanner.Text() {
		case "valid-after":
			scanner.Scan()
			date := scanner.Text()
			scanner.Scan()
			ret.NotBefore, _ = time.Parse("2006-01-02 15:04:05", date+" "+scanner.Text())
		case "fresh-until":
			scanner.Scan()
			date := scanner.Text()
			scanner.Scan()
			ret.FreshUntil, _ = time.Parse("2006-01-02 15:04:05", date+" "+scanner.Text())
		case "valid-until":
			scanner.Scan()
			date := scanner.Text()
			scanner.Scan()
			ret.NotAfter, _ = time.Parse("2006-01-02 15:04:05", date+" "+scanner.Text())
		case "r": // SP nickname SP base64(ID) SP date SP time SP IP SP port SP dirport
			info = new(ShortNodeInfo)
			ret.Routers = append(ret.Routers, info)
			scanner.Scan()
			info.Nickname = scanner.Text()
			scanner.Scan()
			id, _ := base64.StdEncoding.DecodeString(scanner.Text() + "=")
			copy(info.ID[:], id)
			scanner.Scan()
			date := scanner.Text()
			scanner.Scan()
			info.Published, _ = time.Parse("2006-01-02 15:04:05", date+" "+scanner.Text())
			scanner.Scan()
			ParseDottedQuad(scanner.Text(), &info.IP)
			scanner.Scan()
			port, _ := strconv.Atoi(scanner.Text())
			info.Port = uint16(port)
			scanner.Scan()
			port, _ = strconv.Atoi(scanner.Text())
			info.DirectoryPort = uint16(port)
		case "m": // base64(sha256(microdescriptor))
			scanner.Scan()
			md, _ := base64.StdEncoding.DecodeString(scanner.Text() + "=")
			copy(info.MicrodescriptorDigest[:], md)
			// fmt.Printf("co %x\n", info.MicrodescriptorDigest)
		case "s": // flag [SP flag...]
			for scanner.Scan() && len(scanner.Bytes()) != 0 {
				switch scanner.Text() {
				case "Authority":
					info.Authority = true
				case "BadExit":
					info.BadExit = true
				case "Exit":
					info.Exit = true
				case "Fast":
					info.Fast = true
				case "Guard":
					info.Guard = true
				case "HSDir":
					info.HSDir = true
				case "Named":
					info.Named = true
				case "Running":
					info.Running = true
				case "Stable":
					info.Stable = true
				case "Unnamed":
					info.Unnamed = true
				case "V2Dir":
					info.V2Dir = true
				case "Valid":
					info.Valid = true
				}
			}
		case "v": // version...
			scanner.Scan() // skip "Tor"
			scanner.Scan()
			ParseDottedQuad(scanner.Text(), (*[4]byte)(&info.Version))
		case "w": // "Bandwidth=" INT [SP "Measured=" INT] [SP "Unmeasured=1"]
			for scanner.Scan() && len(scanner.Bytes()) != 0 {
				switch {
				case strings.HasPrefix(scanner.Text(), "Bandwidth="):
					bw, _ := strconv.Atoi(scanner.Text()[len("Bandwidth="):])
					info.RawBandwidth = int(bw)
				case scanner.Text() == "Unmeasured=1":
					info.UnmeasuredBandwidth, info.RawBandwidth = info.RawBandwidth, 0
				}
			}
		case "directory-footer":
			done = true
		default:
			//fmt.Printf("unknown token \"%s\"\n", scanner.Text())
		}

		scanner.Split(bufio.ScanByteDelimited('\n'))
		if !scanner.Scan() {
			break
		}
		scanner.Split(bufio.ScanUntilByte('\n', bufio.ScanByteDelimited(' ')))
	}
	var documentHash []byte
	getDocumentHash := func() []byte {
		if documentHash == nil {
			h.Write([]byte("\ndirectory-signature "))
			documentHash = h.Sum(nil)
		}
		return documentHash
	}

	agreeingAuthorities := make(map[string]struct{}, authorities.NumAuthorities())
	for scanner.Scan() {
		switch scanner.Text() {
		case "bandwidth-weights":
			for scanner.Scan() && len(scanner.Bytes()) != 0 {
				if len(scanner.Bytes()) < 4 || scanner.Bytes()[0] != 'W' || scanner.Bytes()[3] != '=' {
					continue
				}
				w_, _ := strconv.Atoi(scanner.Text()[len("Wxy="):])
				w := int64(w_)
				switch string(scanner.Bytes()[1:3]) {
				// TODO: figure out what the other values mean and probably reimplement this
				case "gg": // Weight for Guard-flagged nodes in the guard position
					ret.BandwidthWeights.ForGuard.Guard = w
				case "gd": // Weight for Guard+Exit-flagged nodes in the guard Position
					ret.BandwidthWeights.ForGuard.GuardExit = w
				case "mg": // Weight for Guard-flagged nodes in the middle Position
					ret.BandwidthWeights.ForRelay.Guard = w
				case "mm": // Weight for non-flagged nodes in the middle Position
					ret.BandwidthWeights.ForRelay.Relay = w
				case "me": // Weight for Exit-flagged nodes in the middle Position
					ret.BandwidthWeights.ForRelay.Exit = w
				case "md": // Weight for Guard+Exit flagged nodes in the middle Position
					ret.BandwidthWeights.ForRelay.GuardExit = w
				case "ee": // Weight for Exit-flagged nodes in the exit Position
					ret.BandwidthWeights.ForExit.Exit = w
				case "ed": // Weight for Guard+Exit-flagged nodes in the exit Position
					ret.BandwidthWeights.ForExit.GuardExit = w
				}
			}
		case "directory-signature": // [SP Algorithm] SP hex(id) SP hex(sha1(signing-key))
			scanner.Scan()
			algorithm := scanner.Text()
			scanner.Scan()
			idHex := strings.ToLower(scanner.Text())
			var sigKeyFprHex string
			if scanner.Scan() {
				sigKeyFprHex = strings.ToLower(scanner.Text())
			} else { // old format: hex(id) SP hex(sha1(signing-key))
				algorithm, idHex, sigKeyFprHex = "sha1", algorithm, idHex
			}
			sigKey := authorities.SigningKey(idHex, sigKeyFprHex)
			// PEM block containing signature
			scanner.Split(bufio.ScanPEM)
			scanner.Scan()
			if sigKey == nil {
				//log.Printf("unknown authority with hex id %q sig key hash %q", idHex, sigKeyFprHex)
				goto next_line
			}
			sig := scanner.Bytes()
			switch algorithm {
			case "sha256":
				if err := rsa.VerifyPKCS1v15(sigKey, 0, getDocumentHash(), sig); err == nil {
					agreeingAuthorities[idHex] = struct{}{}
				} else {
					log.Printf("bad signature: signer %s hash %x signature %x error %v\n", idHex, h.Sum(nil), sig, err)
				}
			}
		default:
			//fmt.Printf("unknown token %q\n", scanner.Text())
		}
	next_line:
		scanner.Split(bufio.ScanByteDelimited('\n'))
		if !scanner.Scan() {
			break
		}
		scanner.Split(bufio.ScanUntilByte('\n', bufio.ScanByteDelimited(' ')))
	}

	if len(agreeingAuthorities) < nRequired {
		if scanner.Err != nil {
			return nil, scanner.Err()
		}
		return ret, fmt.Errorf("too few valid authority signautures for consensus (got %d, need %d)", len(agreeingAuthorities), nRequired)
	}

	return ret, scanner.Err()
}

func ParseDottedQuad(addr string, out *[4]byte) {
	for i, o := 0, 0; i < len(addr) && o < 4; i++ {
		if addr[i] == '.' {
			o++
			continue
		}
		out[o] = out[o]*10 + (addr[i] - '0')
	}
}

func (c *Consensus) UpdateTime(rand *mathrand.Rand) time.Time {
	if rand == nil {
		rand = smallrand()
	}
	interval := c.FreshUntil.Sub(c.NotBefore)
	earliest := c.FreshUntil.Add(interval * 3 / 4)
	remaining := c.NotAfter.Sub(earliest)
	latest := earliest.Add(remaining * 7 / 8)
	delta := latest.Sub(earliest)
	return earliest.Add(time.Duration(float64(delta.Nanoseconds()) * rand.Float64()))
}
