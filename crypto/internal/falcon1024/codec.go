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
	if len(dst) != encodedPrivateKeySize {
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

	if offset != encodedPrivateKeySize {
		return errors.New("falcon-1024: invalid private key encoding")
	}

	return nil
}

func skDecode(src []byte) (f, g, ntruF smallPolynomial, err error) {
	if len(src) != encodedPrivateKeySize {
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

	if offset != encodedPrivateKeySize {
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
	signatureHeader     byte = 0x30 + logN
	signaturePrefixSize      = headerSize + nonceSize
)

func sigEncode(dst []byte, nonce [nonceSize]byte, s2 smallPolynomial) error {
	if len(dst) != SignatureSize {
		return errors.New("falcon-1024: invalid signature length")
	}

	dst[0] = signatureHeader
	copy(dst[headerSize:signaturePrefixSize], nonce[:])

	written, err := compressedEncode(dst[signaturePrefixSize:], s2)
	if err != nil {
		return err
	}
	clear(dst[signaturePrefixSize+written:])

	return nil
}

func sigDecode(src []byte) (nonce [nonceSize]byte, s2 smallPolynomial, err error) {
	if len(src) != SignatureSize {
		return nonce, smallPolynomial{}, errors.New("falcon-1024: invalid signature length")
	}
	if src[0] != signatureHeader {
		return nonce, smallPolynomial{}, errors.New("falcon-1024: invalid signature")
	}

	copy(nonce[:], src[headerSize:signaturePrefixSize])

	s2, consumed, err := compressedDecode(src[signaturePrefixSize:])
	if err != nil {
		return nonce, smallPolynomial{}, err
	}

	for _, b := range src[signaturePrefixSize+consumed:] {
		if b != 0 {
			return nonce, smallPolynomial{}, errors.New("falcon-1024: invalid signature")
		}
	}

	return nonce, s2, nil
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
