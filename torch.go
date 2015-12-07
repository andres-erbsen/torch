package torch

import (
	"compress/zlib"
	"encoding/base64"
	"fmt"
	"github.com/andres-erbsen/torch/config"
	"github.com/andres-erbsen/torch/directory"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/net/proxy"
)

// var cacheDirDefault = filepath.Join(os.Getenv("HOME"), ".cache", "torch")

type Torch struct {
	dialer proxy.Dialer

	sync.RWMutex
	cachedDir *directory.Directory

	cancel func()
	ctx    context.Context
}

// New initializes a new TOR client, loading the consensus information. When
// New returns, the resulting TOR client is in a good state for selecting and
// establishing circuits.
func New(ctx context.Context, dialer proxy.Dialer) (*Torch, error) {
	tc, circ, err := BuildDirectoryCircuit(ctx, config.BootstrapDirectories[:], proxy.FromEnvironment())
	if err != nil {
		return nil, err
	}
	defer tc.Close()

	c := &http.Client{
		Transport: &http.Transport{
			Dial:                  circ.Dial,
			MaxIdleConnsPerHost:   1,
			ResponseHeaderTimeout: 10 * time.Second,
		},
		Timeout: 1000 * time.Second,
	}

	consensus, authorities, err := DownloadConsensus(c, config.AuthorityFingerprints[:])
	if err != nil {
		return nil, err
	}

	mds, err := DownloadMicrodescriptors(c, consensus.Routers)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	t := &Torch{
		dialer: dialer,
		cachedDir: &directory.Directory{
			Routers:     mds,
			Consensus:   consensus,
			Authorities: authorities},

		cancel: cancel,
		ctx:    ctx,
	}
	go t.cron()
	return t, nil
}

func BuildDirectoryCircuit(ctx context.Context, dirs []*directory.MinimalNodeInfo, dialer proxy.Dialer) (tc *TorConn, circ *Circuit, err error) {
	for _, dir := range dirs {
		tc, err = DialOnionRouter(ctx, net.IP(dir.IP[:]).String()+":"+strconv.Itoa(int(dir.Port)), dir.ID[:], dialer)
		if err != nil {
			continue
		}
		circ, err = tc.createCircuitInsecure(context.Background())
		if err != nil {
			tc.Close()
			continue
		}
		return
	}
	return nil, nil, fmt.Errorf("could not create directory circuit: %s", err)
}

func DownloadConsensus(dirClient *http.Client, authorityFingerprints []string) (*directory.Consensus, directory.Authorities, error) {
	// ~/.tor-browser-en/INSTALL/Browser/TorBrowser/Data/Tor/cached-microdesc-consensus
	// ~/.tor/cached-microdesc-consensus
	// /var/lib/tor/cached-microdesc-consensus
	authorities, err := func() (directory.Authorities, error) {
		resp, err := dirClient.Get("http://tordir.localhost/tor/keys/all.z")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		r, err := zlib.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return directory.ReadCertifications(r, authorityFingerprints), nil
	}()
	if err != nil {
		return nil, nil, err
	}

	if authorities.NumAuthorities() < config.AuthoritiesRequired {
		return nil, nil, fmt.Errorf("failed to download authority keys: got %d out of required %d", authorities.NumAuthorities(), config.AuthoritiesRequired)
	}

	resp, err := dirClient.Get("http://tordir.localhost/tor/status-vote/current/consensus-microdesc.z")
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	r, err := zlib.NewReader(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	defer r.Close()

	consensus, err := directory.ReadMicrodescriptorConsensus(r, authorities, config.AuthoritiesRequired)
	if err != nil {
		return nil, nil, err
	}
	return consensus, authorities, resp.Body.Close()
}

func DownloadMicrodescriptors(dirClient *http.Client, snis []*directory.ShortNodeInfo) ([]*directory.NodeInfo, error) {
	nBatches := (len(snis) + 91) / 92
	collect := make(chan error, nBatches)
	mds := make([]*directory.NodeInfo, len(snis))
	for i := 0; i < nBatches; i++ {
		go func(i int) {
			start := 92 * i
			pastend := start + 92
			if len(snis) < pastend {
				pastend = len(snis)
			}

			fprs := make([]string, 0, 92)
			for j := start; j < pastend; j++ {
				fprs = append(fprs, strings.TrimRight(base64.StdEncoding.EncodeToString(snis[j].MicrodescriptorDigest[:]), "="))
			}
			resp, err := dirClient.Get("http://tordir.localhost/tor/micro/d/" + strings.Join(fprs, "-") + ".z")
			if err != nil {
				collect <- err
				return
			}
			defer resp.Body.Close()

			r, err := zlib.NewReader(resp.Body)
			if err != nil {
				collect <- err
				return
			}
			defer r.Close()

			mdBatch, err := directory.ReadMicrodescriptors(r, snis[start:pastend])
			if err != nil {
				collect <- err
				return
			}

			copy(mds[start:pastend], mdBatch)
			collect <- nil
		}(i)
	}
	var retErr error
	for i := 0; i < nBatches; i++ {
		err := <-collect
		if err != nil && retErr == nil {
			retErr = err
		}
	}
	return mds, retErr
}

func niAddr(ni *directory.NodeInfo) string {
	return fmt.Sprintf("%d.%d.%d.%d:%d", ni.IP[0], ni.IP[1], ni.IP[2], ni.IP[3], ni.Port)
}

func (t *Torch) Pick(weighWith func(w *directory.BandwidthWeights, n *directory.NodeInfo) int64) *directory.NodeInfo {
	t.RLock()
	defer t.RUnlock()

	weigh := func(n *directory.NodeInfo) int64 {
		return weighWith(&t.cachedDir.Consensus.BandwidthWeights, n)
	}

	return directory.Pick(weigh, t.cachedDir.Routers, nil)
}

func weighRelayWith(w *directory.BandwidthWeights, n *directory.NodeInfo) int64 {
	return w.ForRelay.Weigh(n)
}

func weighExitWith(w *directory.BandwidthWeights, n *directory.NodeInfo) int64 {
	return w.ForExit.Weigh(n)
}

func (t *Torch) UnguardedCircuitTo(ctx context.Context, n int, dst *directory.NodeInfo) (*TorConn, *Circuit, error) {
	if n < 1 {
		return nil, nil, fmt.Errorf("cannot build circuit of %d nodes", n)
	}
	if n >= 6 {
		return nil, nil, fmt.Errorf("requested circuit too long")
	}

	// entry
	var n1 *directory.NodeInfo
	if n == 1 {
		n1 = dst
	} else {
		n1 = t.Pick(weighRelayWith)
	}
	tc, err := DialOnionRouter(ctx, niAddr(n1), n1.ID[:], t.dialer)
	if err != nil {
		return nil, nil, err
	}
	circ, err := tc.CreateCircuit(ctx, n1.ID[:], n1.NTorOnionKey)
	if err != nil {
		return nil, nil, err
	}

	if n == 1 {
		return tc, circ, err
	}

	// routers
	for i := 2; i < n; i++ {
		ni := t.Pick(weighRelayWith)
		if err := circ.Extend(net.IP(ni.IP[:]), ni.Port, ni.ID[:], ni.NTorOnionKey); err != nil {
			return nil, nil, err
		}
	}

	if err := circ.Extend(net.IP(dst.IP[:]), dst.Port, dst.ID[:], dst.NTorOnionKey); err != nil {
		return nil, nil, err
	}

	return tc, circ, nil
}

func (t *Torch) UnguardedExitCircuit(ctx context.Context, n int) (*TorConn, *Circuit, error) {
	return t.UnguardedCircuitTo(ctx, n, t.Pick(weighExitWith))
}

func (t *Torch) Stop() error {
	t.cancel()
	return nil
}

func (t *Torch) cron() {
	// cron does NOT enjoy exclusive access to instance variables, a RWMutex is
	// used.

	for {
		select {
		case <-time.After(t.cachedDir.Consensus.UpdateTime(nil).Sub(time.Now())):
			panic("time to update consensus (not implemented)")
		case <-t.ctx.Done():
			return
		}
	}
}
