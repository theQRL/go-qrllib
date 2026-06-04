package mlkem1024_test

import (
	"bytes"
	"log"

	"github.com/theQRL/go-qrllib/crypto/mlkem1024"
)

func Example() {
	bobDK, err := mlkem1024.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	// Bob shares his encapsulation key with Alice.
	bobEKBytes := bobDK.EncapsulationKey().Bytes()

	// Alice encapsulates a shared key to Bob's encapsulation key.
	bobEK, err := mlkem1024.NewEncapsulationKey(bobEKBytes)
	if err != nil {
		log.Fatal(err)
	}
	aliceSharedKey, ciphertext, err := bobEK.Encapsulate()
	if err != nil {
		log.Fatal(err)
	}

	// Bob decapsulates Alice's ciphertext to recover the same shared key.
	bobSharedKey, err := bobDK.Decapsulate(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	if !bytes.Equal(aliceSharedKey, bobSharedKey) {
		log.Fatal("shared keys differ")
	}
}
