// falcon1024_crossverify.go - Cross-verify go-qrllib Falcon-1024 against the
// PQClean falcon-1024 "clean" implementation, which is the Falcon round-3
// reference code (integer-emulated floating point, sign_dyn) behind the NIST
// API that go-qrllib follows.
//
// Both sides draw every random byte from the same SHAKE256 stream: the C
// harness (falcon1024_crossverify_ref.c) defines randombytes() over PQClean's
// own SHAKE256 with the same label. Key generation consumes 48 bytes, each
// signing call a 40-byte nonce and then a 48-byte sampler seed, and the
// messages are drawn from the stream as well. So beyond mutual verification,
// the check requires byte-identical public keys, private keys, signed messages
// and detached signatures from the two implementations. This is what the
// bit-exactness of go-qrllib's floating-point sampler guarantees, and it holds
// only if that sampler rounds exactly as the reference does, on every target.
//
// Usage:
//
//	go run falcon1024_crossverify.go generate /tmp/falcon1024_go.bin
//	go run falcon1024_crossverify.go check    /tmp/falcon1024_ref.bin
//
// "generate" writes go-qrllib's keys and signatures for the C harness to
// regenerate and compare; "check" regenerates the C harness's output from its
// stream, compares, and opens and verifies it with go-qrllib.
package main

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/theQRL/go-qrllib/crypto/falcon1024"
)

const (
	entries  = 8
	labelGo  = "go-qrllib Falcon-1024 cross-verification: go-qrllib generates"
	labelRef = "go-qrllib Falcon-1024 cross-verification: PQClean generates"
)

// entry is one key pair with a signed message and a detached signature of a
// message drawn from the stream. The file format is, per entry, the five
// fields in this order, each prefixed with its big-endian 32-bit length.
type entry struct {
	pk, sk, msg, sm, sig []byte
}

func stream(label string) io.Reader {
	s := sha3.NewSHAKE256()
	_, _ = s.Write([]byte(label))
	return s
}

func generate(label string) ([]entry, error) {
	rnd := stream(label)
	out := make([]entry, 0, entries)
	for i := range entries {
		pub, priv, err := falcon1024.GenerateKey(rnd)
		if err != nil {
			return nil, fmt.Errorf("entry %d: GenerateKey: %w", i, err)
		}
		msg := make([]byte, 33*(i+1))
		if _, err := io.ReadFull(rnd, msg); err != nil {
			return nil, err
		}
		sm, err := falcon1024.Sign(rnd, priv, msg)
		if err != nil {
			return nil, fmt.Errorf("entry %d: Sign: %w", i, err)
		}
		sig, err := falcon1024.SignDetached(rnd, priv, msg)
		if err != nil {
			return nil, fmt.Errorf("entry %d: SignDetached: %w", i, err)
		}
		if opened, err := falcon1024.Open(pub, sm); err != nil || !bytes.Equal(opened, msg) {
			return nil, fmt.Errorf("entry %d: self-check of the signed message failed", i)
		}
		if !falcon1024.Verify(pub, msg, sig) {
			return nil, fmt.Errorf("entry %d: self-check of the detached signature failed", i)
		}
		out = append(out, entry{pub.Bytes(), priv.Bytes(), msg, sm, sig})
	}
	return out, nil
}

func writeEntries(path string, es []entry) error {
	var buf bytes.Buffer
	for _, e := range es {
		for _, field := range [][]byte{e.pk, e.sk, e.msg, e.sm, e.sig} {
			var n [4]byte
			binary.BigEndian.PutUint32(n[:], uint32(len(field)))
			buf.Write(n[:])
			buf.Write(field)
		}
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func readEntries(path string) ([]entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var es []entry
	next := func() ([]byte, error) {
		if len(data) < 4 {
			return nil, errors.New("truncated file")
		}
		n := int(binary.BigEndian.Uint32(data))
		data = data[4:]
		if len(data) < n {
			return nil, errors.New("truncated file")
		}
		field := data[:n]
		data = data[n:]
		return field, nil
	}
	for len(data) > 0 {
		var e entry
		var err error
		for _, field := range []*[]byte{&e.pk, &e.sk, &e.msg, &e.sm, &e.sig} {
			if *field, err = next(); err != nil {
				return nil, err
			}
		}
		es = append(es, e)
	}
	if len(es) != entries {
		return nil, fmt.Errorf("file holds %d entries, want %d", len(es), entries)
	}
	return es, nil
}

// check regenerates the C harness's entries from its stream, requires them to
// be byte-identical, and opens and verifies the C outputs with go-qrllib.
func check(path string) error {
	theirs, err := readEntries(path)
	if err != nil {
		return err
	}
	ours, err := generate(labelRef)
	if err != nil {
		return err
	}
	for i := range entries {
		a, b := ours[i], theirs[i]
		for _, f := range []struct {
			name string
			x, y []byte
		}{
			{"public key", a.pk, b.pk}, {"private key", a.sk, b.sk}, {"message", a.msg, b.msg},
			{"signed message", a.sm, b.sm}, {"detached signature", a.sig, b.sig},
		} {
			if !bytes.Equal(f.x, f.y) {
				return fmt.Errorf("entry %d: %s differs from PQClean's (%d vs %d bytes)", i, f.name, len(f.x), len(f.y))
			}
		}

		pub, err := falcon1024.NewPublicKey(b.pk)
		if err != nil {
			return fmt.Errorf("entry %d: NewPublicKey: %w", i, err)
		}
		if _, err := falcon1024.NewPrivateKey(b.sk); err != nil {
			return fmt.Errorf("entry %d: NewPrivateKey: %w", i, err)
		}
		opened, err := falcon1024.Open(pub, b.sm)
		if err != nil || !bytes.Equal(opened, b.msg) {
			return fmt.Errorf("entry %d: Open rejected PQClean's signed message", i)
		}
		if !falcon1024.Verify(pub, b.msg, b.sig) {
			return fmt.Errorf("entry %d: Verify rejected PQClean's detached signature", i)
		}
		tampered := bytes.Clone(b.msg)
		tampered[0] ^= 1
		if falcon1024.Verify(pub, tampered, b.sig) {
			return fmt.Errorf("entry %d: Verify accepted PQClean's signature for a different message", i)
		}
	}
	return nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: falcon1024_crossverify (generate|check) <file>")
		os.Exit(2)
	}
	mode, path := os.Args[1], os.Args[2]
	switch mode {
	case "generate":
		es, err := generate(labelGo)
		if err == nil {
			err = writeEntries(path, es)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("go-qrllib Falcon-1024: wrote %d entries to %s\n", entries, path)
		fmt.Printf("  per entry: pk %d, sk %d bytes; signed message and detached signature from the shared stream\n",
			falcon1024.PublicKeySize, falcon1024.PrivateKeySize)
	case "check":
		if err := check(path); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("go-qrllib Falcon-1024 <-> PQClean falcon-1024: %d entries PASSED\n", entries)
		fmt.Println("  - same stream -> identical public key, private key, signed message and detached signature")
		fmt.Println("  - PQClean signed message opens under go-qrllib")
		fmt.Println("  - PQClean detached signature verifies under go-qrllib, and not for a different message")
	default:
		fmt.Fprintln(os.Stderr, "usage: falcon1024_crossverify (generate|check) <file>")
		os.Exit(2)
	}
}
