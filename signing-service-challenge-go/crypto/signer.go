package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

type SignatureAlgorithm string

const SignatureRSA SignatureAlgorithm = "RSA"
const SignautreECDSA SignatureAlgorithm = "ECDSA"

// Signer defines a contract for different types of signing implementations.
type Signer interface {
	Sign(dataToBeSigned []byte) ([]byte, error)
}

// NewSigner returns an implementation of Signer based on the provided algorithm
func NewSigner(algorithm SignatureAlgorithm) (Signer, error) {
	switch algorithm {
	case SignatureRSA:
		return NewRSASigner()
	case SignautreECDSA:
		return NewECDSASigner()
	}
	return nil, fmt.Errorf("invalid signature algorithm provided")
}

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
