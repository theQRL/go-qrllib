package falcon1024

import "errors"

const headerSize = 1

type compressedBitReader struct {
	src     []byte
	pos     int
	current byte
	bits    int
}

func (r *compressedBitReader) readBit() (uint32, bool) {
	if r.bits == 0 {
		if r.pos >= len(r.src) {
			return 0, false
		}
		r.current = r.src[r.pos]
		r.pos++
		r.bits = 8
	}

	r.bits--
	return uint32(r.current>>r.bits) & 1, true
}

func (r *compressedBitReader) readBits(bitCount int) (uint32, bool) {
	var v uint32
	for range bitCount {
		bit, ok := r.readBit()
		if !ok {
			return 0, false
		}
		v = (v << 1) | bit
	}
	return v, true
}

func (r *compressedBitReader) trailingBits() byte {
	if r.bits == 0 {
		return 0
	}
	return r.current & byte((1<<r.bits)-1)
}

var (
	errInvalidSignatureEncoding        = errors.New("falcon-1024: invalid signature encoding")
	errCompressedSignatureTooLarge     = errors.New("falcon-1024: compressed signature too large")
	errCompressedCoefficientOutOfRange = errors.New("falcon-1024: compressed coefficient out of range")
)

const maxCompressedCoefficient = 2047

// compressedDecode maps to the Falcon reference comp_decode. Each coefficient
// is encoded as sign bit || low 7 magnitude bits || unary high magnitude bits.
func compressedDecode(src []byte) (smallPolynomial, int, error) {
	var p smallPolynomial
	r := compressedBitReader{src: src}

	for i := range p {
		b, ok := r.readBits(8)
		if !ok {
			return smallPolynomial{}, 0, errInvalidSignatureEncoding
		}

		negative := b&0x80 != 0
		magnitude := int32(b & 0x7f)

		for {
			bit, ok := r.readBit()
			if !ok {
				return smallPolynomial{}, 0, errInvalidSignatureEncoding
			}
			if bit == 1 {
				break
			}

			magnitude += 128
			if magnitude > maxCompressedCoefficient {
				return smallPolynomial{}, 0, errInvalidSignatureEncoding
			}
		}

		if negative {
			if magnitude == 0 {
				return smallPolynomial{}, 0, errInvalidSignatureEncoding
			}
			magnitude = -magnitude
		}

		p[i] = magnitude
	}

	if r.trailingBits() != 0 {
		return smallPolynomial{}, 0, errInvalidSignatureEncoding
	}

	return p, r.pos, nil
}

// compressedEncode maps to the Falcon reference comp_encode.
func compressedEncode(dst []byte, s smallPolynomial) (int, error) {
	var acc uint32
	accBits := 0
	written := 0

	for _, x := range s {
		if x < -maxCompressedCoefficient || x > maxCompressedCoefficient {
			return 0, errCompressedCoefficientOutOfRange
		}
	}

	for _, x := range s {
		t := x
		sign := uint32(0)
		if t < 0 {
			t = -t
			sign = 0x80
		}

		low := sign | (uint32(t) & 0x7F)
		high := uint32(t) >> 7

		acc = (acc << 8) | low
		accBits += 8

		acc = (acc << (high + 1)) | 1
		accBits += int(high) + 1

		for accBits >= 8 {
			accBits -= 8
			if written >= len(dst) {
				return 0, errCompressedSignatureTooLarge
			}
			dst[written] = byte(acc >> accBits)
			written++
		}
	}

	if accBits > 0 {
		if written >= len(dst) {
			return 0, errCompressedSignatureTooLarge
		}
		dst[written] = byte(acc << (8 - accBits))
		written++
	}

	return written, nil
}

const (
	privateKeyHeader byte = 0x50 + logN
	fgBits                = 5
	ntruFBits             = 8
)

func skEncode(dst []byte, f, g, ntruF smallPolynomial) error {
	if len(dst) != PrivateKeySize {
		return errors.New("falcon-1024: invalid private key length")
	}

	dst[0] = privateKeyHeader
	offset := headerSize

	written, err := trimI8Encode(dst[offset:], f, fgBits)
	if err != nil {
		return err
	}
	offset += written

	written, err = trimI8Encode(dst[offset:], g, fgBits)
	if err != nil {
		return err
	}
	offset += written

	written, err = trimI8Encode(dst[offset:], ntruF, ntruFBits)
	if err != nil {
		return err
	}
	offset += written

	if offset != PrivateKeySize {
		return errors.New("falcon-1024: invalid private key encoding")
	}

	return nil
}

func skDecode(src []byte) (f, g, ntruF smallPolynomial, err error) {
	if len(src) != PrivateKeySize {
		return smallPolynomial{}, smallPolynomial{}, smallPolynomial{},
			errors.New("falcon-1024: invalid private key length")
	}
	if src[0] != privateKeyHeader {
		return smallPolynomial{}, smallPolynomial{}, smallPolynomial{},
			errors.New("falcon-1024: invalid private key")
	}

	offset := headerSize
	var consumed int

	f, consumed, err = trimI8Decode(src[offset:], fgBits)
	if err != nil {
		return smallPolynomial{}, smallPolynomial{}, smallPolynomial{}, err
	}
	offset += consumed

	g, consumed, err = trimI8Decode(src[offset:], fgBits)
	if err != nil {
		return smallPolynomial{}, smallPolynomial{}, smallPolynomial{}, err
	}
	offset += consumed

	ntruF, consumed, err = trimI8Decode(src[offset:], ntruFBits)
	if err != nil {
		return smallPolynomial{}, smallPolynomial{}, smallPolynomial{}, err
	}
	offset += consumed

	if offset != PrivateKeySize {
		return smallPolynomial{}, smallPolynomial{}, smallPolynomial{},
			errors.New("falcon-1024: invalid private key")
	}

	return f, g, ntruF, nil
}

const publicKeyHeader byte = 0x00 + logN

func pkEncode(dst []byte, h ringElement) error {
	if len(dst) != PublicKeySize {
		return errors.New("falcon-1024: invalid public key length")
	}

	dst[0] = publicKeyHeader
	polyByteEncode(dst[headerSize:], h)

	return nil
}

func pkDecode(src []byte) (h ringElement, err error) {
	if len(src) != PublicKeySize {
		return ringElement{}, errors.New("falcon-1024: invalid public key length")
	}
	if src[0] != publicKeyHeader {
		return ringElement{}, errors.New("falcon-1024: invalid public key")
	}

	return polyByteDecode(src[headerSize:])
}

const (
	// signatureHeader is the signature header byte of the reference NIST API
	// (nist.c): 0x20 + logn.
	signatureHeader byte = 0x20 + logN

	signedMessageLengthSize = 2
	signedMessagePrefixSize = signedMessageLengthSize + nonceSize

	// maxCompressedSignatureSize is the room the reference crypto_sign gives
	// comp_encode: CRYPTO_BYTES less the length prefix, the nonce and the
	// signature header byte.
	maxCompressedSignatureSize = MaxSignedMessageOverhead - signedMessagePrefixSize - headerSize
)

var errInvalidSignedMessage = errors.New("falcon-1024: invalid signed message")

// signedMessageEncode builds the reference crypto_sign output: a two-byte
// big-endian signature length, the nonce, the message and the signature
// (header byte then compressed s2). Like the reference, it fails rather than
// retries when the compressed polynomial does not fit.
func signedMessageEncode(nonce [nonceSize]byte, message []byte, s2 smallPolynomial) ([]byte, error) {
	var sig [headerSize + maxCompressedSignatureSize]byte
	sig[0] = signatureHeader
	written, err := compressedEncode(sig[headerSize:], s2)
	if err != nil {
		return nil, err
	}
	sigLen := headerSize + written

	sm := make([]byte, signedMessagePrefixSize+len(message)+sigLen)
	sm[0] = byte(sigLen >> 8)
	sm[1] = byte(sigLen)
	copy(sm[signedMessageLengthSize:], nonce[:])
	copy(sm[signedMessagePrefixSize:], message)
	copy(sm[signedMessagePrefixSize+len(message):], sig[:sigLen])
	return sm, nil
}

// signedMessageDecode parses a signed message with the checks of the
// reference crypto_sign_open. The returned nonce and message alias sm.
func signedMessageDecode(sm []byte) (nonce, message []byte, s2 smallPolynomial, err error) {
	if len(sm) < signedMessagePrefixSize {
		return nil, nil, smallPolynomial{}, errInvalidSignedMessage
	}

	sigLen := int(sm[0])<<8 | int(sm[1])
	if sigLen > len(sm)-signedMessagePrefixSize {
		return nil, nil, smallPolynomial{}, errInvalidSignedMessage
	}
	msgLen := len(sm) - signedMessagePrefixSize - sigLen

	nonce = sm[signedMessageLengthSize:signedMessagePrefixSize]
	message = sm[signedMessagePrefixSize : signedMessagePrefixSize+msgLen]
	sig := sm[signedMessagePrefixSize+msgLen:]

	if sigLen < headerSize || sig[0] != signatureHeader {
		return nil, nil, smallPolynomial{}, errInvalidSignedMessage
	}

	s2, consumed, err := compressedDecode(sig[headerSize:])
	if err != nil {
		return nil, nil, smallPolynomial{}, err
	}
	if consumed != sigLen-headerSize {
		return nil, nil, smallPolynomial{}, errInvalidSignedMessage
	}

	return nonce, message, s2, nil
}

const (
	// detachedSignatureHeader is the header byte of the compressed signature
	// format of the reference library API (falcon.h): 0x30 + logn.
	detachedSignatureHeader byte = 0x30 + logN

	detachedSignaturePrefixSize = headerSize + nonceSize

	// maxDetachedCompressedSize is the room FALCON_SIG_COMPRESSED_MAXSIZE
	// leaves for the compressed polynomial.
	maxDetachedCompressedSize = MaxSignatureSize - detachedSignaturePrefixSize
)

// detachedSignatureEncode builds a compressed-format signature as the
// reference library's signing functions do for FALCON_SIG_COMPRESSED: the
// header byte, the nonce and the compressed polynomial, nothing more.
func detachedSignatureEncode(nonce [nonceSize]byte, s2 smallPolynomial) ([]byte, error) {
	var sig [MaxSignatureSize]byte
	sig[0] = detachedSignatureHeader
	copy(sig[headerSize:detachedSignaturePrefixSize], nonce[:])
	written, err := compressedEncode(sig[detachedSignaturePrefixSize:], s2)
	if err != nil {
		return nil, err
	}

	out := make([]byte, detachedSignaturePrefixSize+written)
	copy(out, sig[:])
	return out, nil
}

// detachedSignatureDecode parses a compressed-format signature with the
// checks of the reference falcon_verify: the header byte, at least the nonce,
// and a compressed polynomial that consumes exactly the remaining bytes. The
// returned nonce aliases sig.
func detachedSignatureDecode(sig []byte) (nonce []byte, s2 smallPolynomial, err error) {
	if len(sig) < detachedSignaturePrefixSize || sig[0] != detachedSignatureHeader {
		return nil, smallPolynomial{}, errInvalidSignatureEncoding
	}

	s2, consumed, err := compressedDecode(sig[detachedSignaturePrefixSize:])
	if err != nil {
		return nil, smallPolynomial{}, err
	}
	if consumed != len(sig)-detachedSignaturePrefixSize {
		return nil, smallPolynomial{}, errInvalidSignatureEncoding
	}

	return sig[headerSize:detachedSignaturePrefixSize], s2, nil
}

// trimI8Len returns the number of bytes a trim_i8 encoding of n bits-wide
// coefficients occupies.
func trimI8Len(bits int) int { return (n*bits + 7) >> 3 }

func trimI8Encode(dst []byte, p smallPolynomial, bits int) (int, error) {
	if bits != fgBits && bits != ntruFBits {
		return 0, errors.New("falcon-1024: invalid trim_i8 bit width")
	}

	bound := int32(1<<(bits-1)) - 1
	for _, x := range p {
		if x < -bound || x > bound {
			return 0, errors.New("falcon-1024: trim_i8 coefficient out of range")
		}
	}

	outLen := trimI8Len(bits)
	if len(dst) < outLen {
		return 0, errors.New("falcon-1024: short trim_i8 output buffer")
	}

	if bits == 8 {
		for i, x := range p {
			dst[i] = byte(int8(x))
		}
		return outLen, nil
	}

	var acc uint32
	accBits := 0
	written := 0

	mask := uint32((1 << bits) - 1)
	for _, x := range p {
		acc = (acc << bits) | (uint32(x) & mask)
		accBits += bits

		for accBits >= 8 {
			accBits -= 8
			dst[written] = byte(acc >> accBits)
			written++
		}
	}

	if accBits > 0 {
		dst[written] = byte(acc << (8 - accBits))
		written++
	}

	return written, nil
}

func trimI8Decode(src []byte, bits int) (smallPolynomial, int, error) {
	if bits != fgBits && bits != ntruFBits {
		return smallPolynomial{}, 0, errors.New("falcon-1024: invalid trim_i8 bit width")
	}

	inLen := trimI8Len(bits)
	if len(src) < inLen {
		return smallPolynomial{}, 0, errors.New("falcon-1024: short trim_i8 input")
	}

	var p smallPolynomial

	if bits == 8 {
		for i := range p {
			x := int8(src[i])
			if x == -128 {
				return smallPolynomial{}, 0, errors.New("falcon-1024: invalid trim_i8 encoding")
			}
			p[i] = int32(x)
		}
		return p, inLen, nil
	}

	mask := uint32((1 << bits) - 1)
	signBit := int32(1 << (bits - 1))
	fullRange := int32(1 << bits)

	var acc uint32
	accBits := 0
	consumed := 0

	for i := range p {
		for accBits < bits {
			acc = (acc << 8) | uint32(src[consumed])
			consumed++
			accBits += 8
		}

		accBits -= bits
		x := int32((acc >> accBits) & mask)

		if x >= signBit {
			if x == signBit {
				return smallPolynomial{}, 0, errors.New("falcon-1024: invalid trim_i8 encoding")
			}
			x -= fullRange
		}

		p[i] = x

		if accBits == 0 {
			acc = 0
		} else {
			acc &= (1 << accBits) - 1
		}
	}

	if acc != 0 {
		return smallPolynomial{}, 0, errors.New("falcon-1024: invalid trim_i8 encoding")
	}

	return p, inLen, nil
}
