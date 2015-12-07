package directory

import (
	"crypto/rsa"
	"time"
)

type Directory struct {
	Authorities Authorities
	Consensus   *Consensus
	Routers     []*NodeInfo
}

type Consensus struct { // microdescriptor consensus
	NotBefore, FreshUntil, NotAfter time.Time
	BandwidthWeights                BandwidthWeights
	Routers                         []*ShortNodeInfo
}

type Authorities interface {
	NumAuthorities() int
	// hex(sha1(idKey)), hex(sha1(signingKey)) -> signingKey
	SigningKey(string, string) *rsa.PublicKey
}

type NodeInfo struct {
	*ShortNodeInfo

	NTorOnionKey []byte
	OnionKey     rsa.PublicKey

	ExitPolicy4, ExitPolicy6 string
	Addresses                []string
	FamilyFingerprints       []string // []hex(sha1(idKey)), lowerCase
	FamilyNicknames          []string // in addition to FamilyFingerprints, NOT corresponding
}

type ShortNodeInfo struct {
	MinimalNodeInfo

	Nickname              string
	MicrodescriptorDigest [32]byte // sha256(microdescriptor)
	Published             time.Time
	DirectoryPort         uint16
	Version               Version
	RawBandwidth          int // kilobytes per second
	UnmeasuredBandwidth   int

	Authority, BadExit, Exit, Fast, Guard, HSDir, Named, Running, Stable, Unnamed, V2Dir, Valid bool
}

type MinimalNodeInfo struct {
	ID   [20]byte // hashPublicKey(signingKey)
	IP   [4]byte
	Port uint16
}

// PositionWeights represents weights for choosing a node that will serve in a
// particular position (guard / relay / exit / directory).
type PositionWeights struct {
	Guard, Relay, Exit, GuardExit int64
}

type BandwidthWeights struct {
	ForGuard, ForRelay, ForExit PositionWeights
}

type Version [4]byte
