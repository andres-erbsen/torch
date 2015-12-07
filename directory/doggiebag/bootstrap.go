package doggiebag

import (
	"bytes"
	"github.com/andres-erbsen/torch/config"
	"github.com/andres-erbsen/torch/directory"
)

func Bootstrap() *directory.Directory {
	keysD := MustAsset("keys")
	dir := new(directory.Directory)
	dir.Authorities = directory.ReadCertifications(bytes.NewReader(keysD), config.AuthorityFingerprints[:])
	consensusD := MustAsset("consensus-microdesc")
	var err error
	dir.Consensus, err = directory.ReadMicrodescriptorConsensus(bytes.NewReader(consensusD), dir.Authorities, config.AuthoritiesRequired)
	if err != nil {
		panic(err)
	}

	microsD := MustAsset("microdescriptors")
	dir.Routers, err = directory.ReadMicrodescriptors(bytes.NewReader(microsD), dir.Consensus.Routers)
	if err != nil {
		panic(err)
	}

	return dir
}
