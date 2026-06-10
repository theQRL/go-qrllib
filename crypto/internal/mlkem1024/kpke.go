package mlkem1024

import "crypto/sha3"

// K-PKE (FIPS 203, Section 5): the IND-CPA-secure public-key encryption
// scheme that ML-KEM wraps with the FO transform.

func pkeKeyGen(dk *DecapsulationKey, d *[32]byte) {
	var gInput [33]byte
	copy(gInput[:32], d[:])
	gInput[32] = k
	G := sha3.Sum512(gInput[:])
	rho, sigma := G[:32], (*[32]byte)(G[32:])
	copy(dk.rho[:], rho)
	copy(dk.encoded[k*encodingSize12:], rho)

	// Wipe key-generation secrets on return: gInput holds the seed d and
	// G holds sigma (the CBD sampling seed).
	defer func() {
		wipe(gInput[:])
		wipe(G[:])
	}()

	A := &dk.a
	for i := range k {
		for j := range k {
			sampleNTT(&A[i*k+j], &dk.rho, byte(j), byte(i))
		}
	}

	var counter byte
	s := &dk.s
	for i := range s {
		samplePolyCBD(&s[i], sigma, counter)
		ntt(&s[i])
		counter++
	}

	t := &dk.t
	for i := range t {
		var acc ringElement
		nttMulAdd4(&acc,
			&A[i*k], &s[0],
			&A[i*k+1], &s[1],
			&A[i*k+2], &s[2],
			&A[i*k+3], &s[3],
		)

		var e ringElement
		samplePolyCBD(&e, sigma, counter)
		ntt(&e)
		counter++
		polyAddAssign(&acc, &e)
		wipeRing(&e) // noise secret; no longer needed

		t[i] = acc
		byteEncode12((*[encodingSize12]byte)(dk.encoded[i*encodingSize12:(i+1)*encodingSize12]), &t[i])
	}
}

func pkeEncrypt(dst *[CiphertextSize]byte, ek *encryptionKey, m, r *[32]byte) {
	var counter byte
	var y [k]ringElement
	for i := range y {
		samplePolyCBD(&y[i], r, counter)
		ntt(&y[i])
		counter++
	}

	off := 0
	for i := range k {
		var acc ringElement
		// ek.a is stored row-major as A[row*k+column]. K-PKE.Encrypt needs
		// A^T * y, so this walks one column of A for each output polynomial.
		nttMulAdd4(&acc,
			&ek.a[i], &y[0],
			&ek.a[k+i], &y[1],
			&ek.a[2*k+i], &y[2],
			&ek.a[3*k+i], &y[3],
		)
		inverseNTT(&acc)

		var e1 ringElement
		samplePolyCBD(&e1, r, counter)
		counter++
		polyAddAssign(&acc, &e1)
		wipeRing(&e1) // noise secret; acc (= u_i) is public ciphertext

		ringCompressAndEncode11((*[encodingSize11]byte)(dst[off:off+encodingSize11]), &acc)
		off += encodingSize11
	}

	var e2 ringElement
	samplePolyCBD(&e2, r, counter)

	var mu ringElement
	ringDecodeAndDecompress1(&mu, m)

	var v ringElement
	nttMulAdd4(&v,
		&ek.t[0], &y[0],
		&ek.t[1], &y[1],
		&ek.t[2], &y[2],
		&ek.t[3], &y[3],
	)
	inverseNTT(&v)
	polyAddAssign(&v, &e2)
	polyAddAssign(&v, &mu)

	ringCompressAndEncode5((*[encodingSize5]byte)(dst[off:off+encodingSize5]), &v)

	// Wipe encryption secrets: y is the encryption randomness vector,
	// e2/mu derive from the message randomness, and full-precision v
	// carries mu before compression rounding. The u_i accumulators are
	// not wiped — they are the public ciphertext content.
	for i := range y {
		wipeRing(&y[i])
	}
	wipeRing(&e2)
	wipeRing(&mu)
	wipeRing(&v)
}

func pkeDecrypt(dst *[32]byte, dk *DecapsulationKey, c *[CiphertextSize]byte) {
	var u [k]ringElement
	off := 0
	for i := range k {
		ringDecodeAndDecompress11(&u[i], (*[encodingSize11]byte)(c[off:off+encodingSize11]))
		off += encodingSize11
		ntt(&u[i])
	}

	var v ringElement
	ringDecodeAndDecompress5(&v, (*[encodingSize5]byte)(c[off:off+encodingSize5]))

	var acc ringElement
	nttMulAdd4(&acc,
		&dk.s[0], &u[0],
		&dk.s[1], &u[1],
		&dk.s[2], &u[2],
		&dk.s[3], &u[3],
	)
	inverseNTT(&acc)

	polySubAssign(&v, &acc)
	ringCompressAndEncode1(dst, &v)

	// Wipe decryption secrets: acc is s^T·u (secret-key-dependent) and v
	// holds the noisy plaintext polynomial after the subtraction. The
	// decoded u is public ciphertext content and is left as is. dst (the
	// decrypted message) is the caller's responsibility — decapsulate
	// wipes it after the FO re-encryption check.
	wipeRing(&acc)
	wipeRing(&v)
}
