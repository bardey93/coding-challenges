package crypto

import (
	"fmt"
)

type SignatureAlgorithm string

const SignatureRSA SignatureAlgorithm = "RSA"
const SignautreECDSA SignatureAlgorithm = "ECDSA"

// IsSupportedAlgorithm checks whether agiven algorithm is supported by the signing suite.
func IsSupportedAlgorithm(algorithm string) bool {
	sigAlg := SignatureAlgorithm(algorithm)
	switch sigAlg {
	case SignatureRSA:
		return true
	case SignautreECDSA:
		return true
	}
	return false
}

// Signer defines a contract for different types of signing implementations.
type Signer interface {
	Sign(dataToBeSigned []byte) ([]byte, error)
	Verify(dataToBeSigned []byte, signature []byte) bool
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
