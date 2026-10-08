package falcon1024_test

import (
	"bytes"
	"fmt"
	"log"

	"github.com/theQRL/go-qrllib/crypto/falcon1024"
)

func Example() {
	pub, priv, err := falcon1024.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("hello, world")

	// The signed message carries msg together with its signature.
	signedMessage, err := priv.Sign(nil, msg)
	if err != nil {
		log.Fatal(err)
	}

	opened, err := falcon1024.Open(pub, signedMessage)
	if err != nil {
		log.Fatal("invalid signature")
	}
	fmt.Println(bytes.Equal(opened, msg))
	// Output: true
}

func Example_detached() {
	pub, priv, err := falcon1024.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("hello, world")

	// A detached signature is kept apart from the message it signs.
	sig, err := priv.SignDetached(nil, msg)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(falcon1024.Verify(pub, msg, sig))
	// Output: true
}
