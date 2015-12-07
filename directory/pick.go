package directory

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	mathrand "math/rand"
	"sort"
)

// WeightedSample takes a slice of weights as input and returns the index of
// the weighed random choice. The slice is modified. Weights must be > 0.
func WeightedSample(weights []int64, rand *mathrand.Rand) int {
	if len(weights) < 2 {
		return 0
	}
	for i := 1; i < len(weights); i++ {
		weights[i] += weights[i-1]
	}
	x := rand.Int63n(weights[len(weights)-1])
	return sort.Search(len(weights), func(i int) bool { return weights[i] > x })
}

func Pick(weigh func(*NodeInfo) int64, routers []*NodeInfo, rand *mathrand.Rand) *NodeInfo {
	if rand == nil {
		rand = smallrand()
	}
	choices := make([]*NodeInfo, 0, len(routers))
	weights := make([]int64, 0, len(routers))
	for _, node := range routers {
		if w := weigh(node); w > 0 {
			choices = append(choices, node)
			weights = append(weights, w)
		}
	}
	return choices[WeightedSample(weights, rand)]
}

func smallrand() *mathrand.Rand {
	var seedBytes [8]byte
	if _, err := cryptorand.Read(seedBytes[:]); err != nil {
		panic(err)
	}
	return mathrand.New(mathrand.NewSource(int64(binary.LittleEndian.Uint64(seedBytes[:]) >> 1)))
}

func (w *PositionWeights) Weigh(n *NodeInfo) int64 {
	if n.Guard && n.Exit {
		return w.GuardExit
	}
	if n.Guard {
		return w.Guard
	}
	if n.Exit {
		return w.Exit
	}
	return w.Relay
}

func (w *BandwidthWeights) WeighBootstrap(n *NodeInfo) int64 {
	if !n.V2Dir || !n.Stable || !n.Running {
		return 0
	}
	return w.ForRelay.Weigh(n)
}
