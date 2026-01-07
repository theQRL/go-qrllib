package dilithium

// Dilithium parameter set constants for security level 5 (≈256-bit post-quantum).
//
// # Rejection Sampling Bounds
//
// The signing algorithm uses rejection sampling to produce signatures that don't
// leak secret key information. The loop at label "rej:" continues until all
// conditions are satisfied:
//
//  1. ||z||∞ < GAMMA1 - BETA: Response vector z must have bounded coefficients.
//     Probability of rejection: ≈ exp(-π * L * N * BETA² / GAMMA1²) ≈ 30%
//
//  2. ||w0 - cs2||∞ < GAMMA2 - BETA: Low bits must remain bounded after
//     subtracting c*s2. Probability of rejection: ≈ 5%
//
//  3. ||ct0||∞ < GAMMA2: Challenge times t0 must be bounded.
//     Probability of rejection: < 1%
//
//  4. Number of hints ≤ OMEGA: At most OMEGA coefficients can differ.
//     Probability of rejection: ≈ 1%
//
// Combined, the expected number of iterations is approximately 4-7.
// The loop is probabilistically bounded and terminates with overwhelming
// probability after a small number of iterations.
//
// # Parameter Relationships
//
//   - BETA = TAU * ETA = 60 * 2 = 120 (bound on c*s norm contribution)
//   - GAMMA1 = 2^19 (masking range for y, ensures z doesn't leak s1)
//   - GAMMA2 = (Q-1)/32 (decomposition parameter for hints)
//   - OMEGA = 75 (maximum allowed hints, related to signature size)
const (
	CRYPTO_PUBLIC_KEY_BYTES = SEED_BYTES + K*POLY_T1_PACKED_BYTES
	CRYPTO_SECRET_KEY_BYTES = 3*SEED_BYTES + L*POLY_ETA_PACKED_BYTES + K*POLY_ETA_PACKED_BYTES + K*POLY_T0_PACKED_BYTES
	// CRYPTO_BYTES is the signature size in bytes
	CRYPTO_BYTES = SEED_BYTES + L*POLY_Z_PACKED_BYTES + POLY_VEC_H_PACKED_BYTES

	SHAKE128_RATE         = 168
	SHAKE256_RATE         = 136
	STREAM128_BLOCK_BYTES = SHAKE128_RATE
	STREAM256_BLOCK_BYTES = SHAKE256_RATE

	POLY_UNIFORM_N_BLOCKS        = (768 + STREAM128_BLOCK_BYTES - 1) / STREAM128_BLOCK_BYTES
	POLY_UNIFORM_ETA_N_BLOCKS    = (136 + STREAM256_BLOCK_BYTES - 1) / STREAM256_BLOCK_BYTES
	POLY_UNIFORM_GAMMA1_N_BLOCKS = (POLY_Z_PACKED_BYTES + STREAM256_BLOCK_BYTES - 1) / STREAM256_BLOCK_BYTES

	SEED_BYTES = 32
	CRH_BYTES  = 64 // hash of public key
	N          = 256
	Q          = 8380417
	Q_INV      = 58728449 // -q^(-1) mod 2^32
	D          = 13

	// Matrix/vector dimensions: A is K×L, s1 is L×1, s2 is K×1
	K = 8 // number of rows in matrix A
	L = 7 // number of columns in matrix A

	// ETA bounds the secret key coefficients: s1, s2 ∈ [-ETA, ETA]^N
	ETA = 2

	// TAU is the number of ±1 coefficients in challenge polynomial c
	TAU = 60

	// BETA = TAU * ETA bounds ||c*s||∞ for norm checks in rejection sampling
	BETA = 120

	// GAMMA1 = 2^19 is the range for masking vector y ∈ [-GAMMA1+1, GAMMA1]^N
	// Larger GAMMA1 means fewer rejections but larger signatures
	GAMMA1 = 1 << 19

	// GAMMA2 = (Q-1)/32 is the decomposition parameter for high/low bit splitting
	GAMMA2 = (Q - 1) / 32

	// OMEGA is the maximum number of hints allowed in a valid signature
	// Signatures with more than OMEGA hints are rejected
	OMEGA = 75

	// Polynomial sizes
	POLY_T1_PACKED_BYTES    = 320
	POLY_T0_PACKED_BYTES    = 416
	POLY_ETA_PACKED_BYTES   = 96
	POLY_Z_PACKED_BYTES     = 640
	POLY_VEC_H_PACKED_BYTES = OMEGA + K
	POLY_W1_PACKED_BYTES    = 128
)
