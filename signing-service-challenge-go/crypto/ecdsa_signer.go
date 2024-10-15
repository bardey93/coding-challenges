package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// ECDSASigner holds the keys and signs data with ECDSA
type ECDSASigner struct {
	key *ECCKeyPair
}

// NewECDSASigner gnereates an ECDSASigner with a key pair
func NewECDSASigner() (ECDSASigner, error) {
	g := ECCGenerator{}
	key, err := g.Generate()
	if err != nil {
		return ECDSASigner{}, fmt.Errorf("NewECDSASigner | %w", err)
	}
	return ECDSASigner{
		key: key,
	}, nil
}

// Sign produces a digital signature for the provided payload
func (s ECDSASigner) Sign(dataTobeSigned []byte) ([]byte, error) {
	hash := sha256.Sum256(dataTobeSigned)
	signature, err := ecdsa.SignASN1(rand.Reader, s.key.Private, hash[:])
	if err != nil {
		return nil, fmt.Errorf("ECDSASigner.SignASN1 | %w", err)
	}
	return signature, nil
}
