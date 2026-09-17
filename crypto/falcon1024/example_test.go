package falcon1024_test

import (
	"log"

	"github.com/theQRL/go-qrllib/crypto/falcon1024"
)

func Example() {
	pub, priv, err := falcon1024.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("hello, world")

	sig, err := priv.Sign(nil, msg)
	if err != nil {
		log.Fatal(err)
	}

	if ok := falcon1024.Verify(pub, msg, sig); !ok {
		log.Fatal("invalid signature")
	}
}
