package domain

import (
	"encoding/base64"
	"fmt"
	"strconv"
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
	lastSignature    []byte
}

// NewSignatureDevice initializes a SignatureDevice with the provided data a generated key pair for the given signature algorithm
func NewSignatureDevice(id uuid.UUID, label string, algorithm crypto.SignatureAlgorithm) (*SignatureDevice, error) {
	signer, err := crypto.NewSigner(algorithm)
	if err != nil {
		return nil, fmt.Errorf("NewSigantureDevice | %w", err)
	}
	// init lastSignautre for first signing
	lastSignature := make([]byte, base64.StdEncoding.EncodedLen(len(id)))
	uid := []byte(id.String())

	base64.StdEncoding.Encode(lastSignature, uid)
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
func (sd *SignatureDevice) Sign(dataToBeSigned []byte) (string, string, error) {
	sd.mu.Lock() // prevent sigCounter from being corrupted
	defer sd.mu.Unlock()
	secDataToBeSigned := prepareSecDataToBeSigned(dataToBeSigned, sd.lastSignature, sd.signatureCounter)

	rawSig, err := sd.signer.Sign(secDataToBeSigned)
	if err != nil {
		return "", "", fmt.Errorf("SignatureDevice Sign | id: %s | err: %w", sd.ID, err)
	}
	encodedSig := make([]byte, base64.StdEncoding.EncodedLen(len(rawSig)))
	base64.StdEncoding.Encode(encodedSig, rawSig)

	sd.signatureCounter++
	sd.lastSignature = encodedSig
	// mux unlocks here
	return string(encodedSig), string(secDataToBeSigned), nil
}

func prepareSecDataToBeSigned(dataToBeSigned []byte, lastSignature []byte, signatureCounter int) []byte {
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
