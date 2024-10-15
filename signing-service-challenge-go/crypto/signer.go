package crypto

import (
	"fmt"
)

type SignatureAlgorithm string

const SignatureRSA SignatureAlgorithm = "RSA"
const SignautreECDSA SignatureAlgorithm = "ECDSA"

func IsSupportedAlgorithm(algorithm string) bool {
	sigAlg := SignatureAlgorithm(algorithm)
	switch sigAlg {
	case SignatureRSA:
	case SignautreECDSA:
		return true
	}
	return false
}

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
