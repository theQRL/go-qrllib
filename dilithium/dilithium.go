package dilithium

type Dilithium struct {
	pk [PKSizePacked]uint8
	sk [SKSizePacked]uint8
}

func New() *Dilithium {
	var sk [SKSizePacked]uint8
	var pk [PKSizePacked]uint8
	cryptoSignKeypair(nil, &pk, &sk)
	return &Dilithium{pk, sk}
}

func NewFromKeys(pk *[PKSizePacked]uint8, sk *[SKSizePacked]uint8) *Dilithium {
	return &Dilithium{*pk, *sk}
}

func (d *Dilithium) GetPK() [PKSizePacked]uint8 {
	return d.pk
}

func (d *Dilithium) GetSK() [SKSizePacked]uint8 {
	return d.sk
}

// Seal the message, returns signature attached with message.
func (d *Dilithium) Seal(message []uint8) []uint8 {
	return cryptoSign(message, &d.sk)
}

// Sign the message, and return a detached signature. Detached signatures are
// variable sized, but never larger than SIG_SIZE_PACKED.
func (d *Dilithium) Sign(message []uint8) []uint8 {
	var sig [SigSizePacked]byte
	return cryptoSignDetached(&sig, message, &d.sk)
}

// Open the sealed message m. Returns the original message sealed with signature.
// In case the signature is invalid, nil is returned.
func Open(signatureMessage []uint8, pk *[PKSizePacked]uint8) []uint8 {
	return cryptoSignOpen(signatureMessage, pk)
}

func Verify(message []uint8, signature []uint8, pk *[PKSizePacked]uint8) bool {
	return cryptoVerifyDetached(signature, message, pk)
}

// ExtractMessage extracts message from Signature attached with message.
func ExtractMessage(signatureMessage []uint8) []uint8 {
	return signatureMessage[SigSizePacked:]
}

// ExtractSignature extracts signature from Signature attached with message.
func ExtractSignature(signatureMessage []uint8) []uint8 {
	return signatureMessage[:SigSizePacked]
}
