package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"github.com/andres-erbsen/torch/nd"
	"io"
	"os"

	"golang.org/x/net/context"
)

type hex32byte [32]byte

func (h *hex32byte) String() string     { return fmt.Sprintf("%x", *h) }
func (h *hex32byte) Set(s string) error { _, err := fmt.Sscanf("%x", s, h[:]); return err }

func main() {
	var id [32]byte
	flag.Var((*hex32byte)(&id), "rend", "hex ID of the OR through which the connection is created. If zero, computed from seed.")
	flag.Parse()

	if flag.NArg() != 1 || len(flag.Arg(0)) == 0 {
		os.Stderr.Write([]byte("USAGE: please specify a shared seed as the first argument\n"))
		flag.Usage()
		os.Exit(3)
	}
	seed := flag.Arg(0)

	if id == [32]byte{} {
		id = sha256.Sum256(append([]byte("ND_EXPAND_SEED_R"), []byte(seed)...))
	}

	conn, err := nd.NDStream(context.Background(), &id, []byte(seed))
	if err != nil {
		os.Stderr.Write([]byte(err.Error() + "\n"))
		os.Exit(3)
	}

	ch := make(chan struct{})
	go func() {
		defer close(ch)
		_, err := io.Copy(conn, os.Stdin)
		if err != nil {
			os.Stderr.Write([]byte(err.Error() + "\n"))
			os.Exit(2)
		}
		if err := conn.CloseWrite(); err != nil {
			os.Stderr.Write([]byte(err.Error() + "\n"))
			os.Exit(12)
		}
	}()
	_, err = io.Copy(os.Stdout, conn)
	if err != nil {
		os.Stderr.Write([]byte(err.Error() + "\n"))
		os.Exit(1)
	}
	if err := conn.Close(); err != nil {
		os.Stderr.Write([]byte(err.Error() + "\n"))
		os.Exit(11)
	}
	<-ch
}
