package dilithium

const (
	CryptoPublicKeyBytes = SeedBytes + K*PolyT1PackedBytes
	CryptoSecretKeyBytes = 3*SeedBytes + L*PolyETAPackedBytes + K*PolyETAPackedBytes + K*PolyT0PackedBytes
	// CryptoBytes is the signature size in bytes
	CryptoBytes = SeedBytes + L*PolyZPackedBytes + PolyVecHPackedBytes

	Shake128Rate        = 168
	Shake256Rate        = 136
	Stream128BlockBytes = Shake128Rate
	Stream256BlockBytes = Shake256Rate

	PolyUniformNBlocks       = (768 + Stream128BlockBytes - 1) / Stream128BlockBytes
	PolyUniformETANBlocks    = (136 + Stream256BlockBytes - 1) / Stream256BlockBytes
	PolyUniformGamma1NBlocks = (PolyZPackedBytes + Stream256BlockBytes - 1) / Stream256BlockBytes

	SeedBytes = 32
	CRHBytes  = 64 // hash of public key
	N         = 256
	Q         = 8380417
	QInv      = 58728449 // -q^(-1) mod 2^32
	D         = 13

	K      = 8
	L      = 7
	ETA    = 2
	TAU    = 60
	BETA   = 120
	GAMMA1 = 1 << 19
	GAMMA2 = (Q - 1) / 32
	OMEGA  = 75

	// Polynomial sizes
	PolyT1PackedBytes   = 320
	PolyT0PackedBytes   = 416
	PolyETAPackedBytes  = 96
	PolyZPackedBytes    = 640
	PolyVecHPackedBytes = OMEGA + K
	PolyW1PackedBytes   = 128
)
