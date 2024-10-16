package domain

import (
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
	"github.com/google/uuid"
)

// SignatureDevice contains all relevant fields for creating signatures
type SignatureDevice struct {
	ID        uuid.UUID                 `json:"id"`
	Label     string                    `json:"label"`
	Algorithm crypto.SignatureAlgorithm `json:"signature_algorithm"`

	signer           crypto.Signer
	signatureCounter int
	mu               sync.Mutex
	lastSignature    string
}

// NewSignatureDevice initializes a SignatureDevice with the provided data a generated key pair for the given signature algorithm
func NewSignatureDevice(id uuid.UUID, label string, algorithm crypto.SignatureAlgorithm) (*SignatureDevice, error) {
	if id == uuid.Nil {
		return nil, fmt.Errorf("NewSignatureDevice | invalid uuid")
	}

	signer, err := crypto.NewSigner(algorithm)
	if err != nil {
		return nil, fmt.Errorf("NewSigantureDevice | %w", err)
	}
	// init lastSignautre for first signing

	uid := []byte(id.String())
	lastSignature := base64.StdEncoding.EncodeToString(uid)

	return &SignatureDevice{
		ID:        id,
		Label:     label,
		Algorithm: algorithm,
		signer:    signer,

		lastSignature: lastSignature,
	}, nil
}

// Sign creates a digital signature for the provided data. The provided dataToBeSigned will be prepended by the
// signature counter and suffixed by the last signature, each divided witha '_' character
func (sd *SignatureDevice) Sign(dataToBeSigned string) (string, string, error) {
	sd.mu.Lock() // prevent sigCounter from being corrupted
	defer sd.mu.Unlock()
	secDataToBeSigned := prepareSecDataToBeSigned(dataToBeSigned, sd.lastSignature, sd.signatureCounter)

	rawSig, err := sd.signer.Sign([]byte(secDataToBeSigned))
	if err != nil {
		return "", "", fmt.Errorf("SignatureDevice Sign | id: %s | err: %w", sd.ID, err)
	}
	encodedSignature := base64.StdEncoding.EncodeToString(rawSig)
	sd.lastSignature = encodedSignature

	sd.signatureCounter++
	// mux unlocks here
	return encodedSignature, secDataToBeSigned, nil
}

func prepareSecDataToBeSigned(dataToBeSigned string, lastSignature string, signatureCounter int) string {
	return fmt.Sprintf("%d_%s_%s", signatureCounter, dataToBeSigned, lastSignature)
}
