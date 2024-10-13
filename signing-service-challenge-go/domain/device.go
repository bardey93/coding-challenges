package domain

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"sync"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
)

// SignatureDevice contains all relevant fields for creating signatures
type SignatureDevice struct {
	ID        []byte                    `json:"id"`
	Label     string                    `json:"label"`
	Algorithm crypto.SignatureAlgorithm `json:"signature_algorithm"`
	Signer    crypto.Signer

	signatureCounter int
	mu               sync.Mutex
}

// NewSignatureDevice initializes a SignatureDevice with the provided data a generated key pair for the given signature algorithm
func NewSignatureDevice(id []byte, label string, algorithm crypto.SignatureAlgorithm) (SignatureDevice, error) {
	signer, err := crypto.NewSigner(algorithm)
	if err != nil {
		return SignatureDevice{}, fmt.Errorf("NewSigantureDevice | %w", err)
	}
	return SignatureDevice{
		ID:        id,
		Label:     label,
		Algorithm: algorithm,
		Signer:    signer,
	}, nil
}

// Sign creates a digital signature for the provided data. The provided dataToBeSigned will be prepended by the
// signature counter and suffixed by the last signature, each divided witha '_' character
func (sd *SignatureDevice) Sign(dataToBeSigned []byte, lastSignature []byte) ([]byte, error) {
	sd.mu.Lock() // prevent sigCounter from being corrupted
	defer sd.mu.Unlock()
	secDataToBeSigned := prepareSecDataToBeSigned(dataToBeSigned, lastSignature, sd.signatureCounter, sd.ID)

	rawSig, err := sd.Signer.Sign(secDataToBeSigned)
	if err != nil {
		return nil, fmt.Errorf("SignatureDevice Sign | id: %s | err: %w", sd.ID, err)
	}
	encodedSig := make([]byte, base64.StdEncoding.EncodedLen(len(rawSig)))
	base64.StdEncoding.Encode(encodedSig, rawSig)

	sd.signatureCounter++
	// mux unlocks here
	return encodedSig, nil
}

func prepareSecDataToBeSigned(dataToBeSigned []byte, lastSignature []byte, signatureCounter int, id []byte) []byte {
	if lastSignature == nil {
		lastSignature = make([]byte, base64.StdEncoding.EncodedLen(len(id)))
		base64.StdEncoding.Encode(lastSignature, id)
	}
	sigCounter := []byte(strconv.Itoa(signatureCounter))

	// allocate for efficiency
	lenSecData := len(dataToBeSigned) + len(lastSignature) + len(sigCounter) + 2
	secDataToBeSigned := make([]byte, lenSecData)

	secDataToBeSigned = append(secDataToBeSigned, sigCounter...)
	secDataToBeSigned = append(secDataToBeSigned, []byte("_")...)
	secDataToBeSigned = append(secDataToBeSigned, dataToBeSigned...)
	secDataToBeSigned = append(secDataToBeSigned, []byte("_")...)
	secDataToBeSigned = append(secDataToBeSigned, lastSignature...)

	return secDataToBeSigned
}
