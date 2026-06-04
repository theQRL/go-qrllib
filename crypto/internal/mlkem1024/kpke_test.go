package mlkem1024

import "testing"

func TestPKERoundTrip(t *testing.T) {
	var d, m, r [32]byte
	for i := range d {
		d[i] = byte(i)
		m[i] = byte(7*i + 3)
		r[i] = byte(255 - 3*i)
	}

	var dk DecapsulationKey
	pkeKeyGen(&dk, &d)

	var ciphertext [CiphertextSize]byte
	pkeEncrypt(&ciphertext, &dk.encryptionKey, &m, &r)

	var got [32]byte
	pkeDecrypt(&got, &dk, &ciphertext)

	if got != m {
		t.Fatalf("decrypted message = %x, want %x", got, m)
	}
}
