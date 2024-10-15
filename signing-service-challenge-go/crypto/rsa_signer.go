package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

// RSASigner holds the keys and signs data with RSA
type RSASigner struct {
	key *RSAKeyPair
}

// NewRSASigner gnereates an RSASigner with a key pair
func NewRSASigner() (RSASigner, error) {
	g := RSAGenerator{}
	key, err := g.Generate()
	if err != nil {
		return RSASigner{}, fmt.Errorf("NewRSASigner | %w", err)
	}
	return RSASigner{
		key: key,
	}, nil
}

// Sign produces a digital signature for the provided payload with RSA PKCS1v15
func (s RSASigner) Sign(dataTobeSigned []byte) ([]byte, error) {
	hash := sha256.Sum256(dataTobeSigned)
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.key.Private, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("RSASigner.SignPKCS1v15 | %w", err)
	}
	return signature, nil
}
