package torch

import (
	"fmt"
	"io"
	"math/rand"
	"testing"
)

// expand computes 100 bytes of keystream in increments cumulatively indicated in idxs
// idxs MUST contain literal 100
func expand(seed string, idxs []int) string {
	var out [100]byte
	kdf := kdf_tor_new([]byte(seed))
	done := 0
	for _, i := range idxs {
		if i >= done && i <= 100 {
			_, err := io.ReadFull(kdf, out[done:i])
			if err != nil {
				panic(err)
			}
			done = i
		}
	}
	return fmt.Sprintf("%x", out)
}

var known = [...]struct{ in, out string }{
	{"", "5ba93c9db0cff93f52b521d7420e43f6eda2784fbf8b4530d8d246dd74ac53a13471bba17941dff7c4ea21bb365bbeeaf5f2c654883e56d11e43c44e9842926af7ca0a8cca12604f945414f07b01e13da42c6cf1de3abfdea9b95f34687cbbe92b9a7383"},
	{"Tor", "776c6214fc647aaa5f683c737ee66ec44f03d0372e1cce69227950f236ddf1e329a7ce7c227903303f525a8c6662426e8034870642a6dabbd41b5d97ec9bf2312ea729992f48f8ea2d0ba83f45dfda1a80bdc8b80de01b23e3e0ffae099b3e4ccf28dc28"},
	{"AN ALARMING ITEM TO FIND ON A MONTHLY AUTO-DEBIT NOTICE", "a340b5d126086c3ab29c2af4179196dbf95e1c72431419d3314844bf8f6afb6098db952b95581fb6c33625709d6f4400b8e7ace18a70579fad83c0982ef73f89395bcc39493ad53a685854daf2ba9b78733b805d9a6824c907ee1dba5ac27a1e466d4d10"},
}

func TestKDFTOR(t *testing.T) {
	for _, kat := range known {
		for i := 0; i < 100; i++ {
			p := rand.Perm(101)
			out := expand(kat.in, p)
			if out != kat.out {
				t.Errorf("KDF_TOR(\"%s\", %v) produced bad output:\n%s\n!=\n%s", kat.in, p, out, kat.out)
			}
		}
	}
}
