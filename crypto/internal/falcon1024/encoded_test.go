package falcon1024

import (
	"bytes"
	"testing"
)

func TestTestingOnlyNewPrivateKeyFromEncoded(t *testing.T) {
	if _, err := TestingOnlyNewPrivateKeyFromEncoded(make([]byte, encodedPrivateKeySize)); err == nil {
		t.Fatal("TestingOnlyNewPrivateKeyFromEncoded accepted malformed key")
	}

	// test_falcon.c publishes component private-key polynomials, not a
	// serialized secret key. Use those reference polynomials to check that
	// private-key reconstruction produces the reference public key.
	// Source: https://falcon-sign.info/impl/test_falcon.c.html
	f := mustDecodeSmallPolynomialHex(t, ntruSmallF1024Hex)
	g := mustDecodeSmallPolynomialHex(t, ntruSmallG1024Hex)
	ntruF := mustDecodeSmallPolynomialHex(t, ntruF1024Hex)

	sk := make([]byte, encodedPrivateKeySize)
	if err := skEncode(sk, f, g, ntruF); err != nil {
		t.Fatal(err)
	}

	priv, err := TestingOnlyNewPrivateKeyFromEncoded(sk)
	if err != nil {
		t.Fatal(err)
	}
	if want := referencePublicKeyBytes(t); !bytes.Equal(priv.PublicKey().Bytes(), want) {
		t.Fatal("private key reconstructed unexpected public key")
	}
}
