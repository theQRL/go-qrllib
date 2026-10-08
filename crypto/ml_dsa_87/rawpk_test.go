package ml_dsa_87

// rawPK wraps packed public-key bytes WITHOUT validation.
//
// It exists so tests can drive the FIPS 204 primitive on arbitrary inputs —
// mutated, mauled, or all-zero keys — which ParsePublicKey would rightly
// refuse. This is the only way to construct an unvalidated PublicKey, and it
// is deliberately confined to this package's tests.
func rawPK(b [CRYPTO_PUBLIC_KEY_BYTES]uint8) *PublicKey {
	return &PublicKey{packed: b, valid: true}
}
