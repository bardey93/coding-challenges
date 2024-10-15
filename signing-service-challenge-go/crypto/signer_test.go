package crypto

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSupportedAlgorithm(t *testing.T) {
	testData := map[string]bool{
		"RSA":   true,
		"ECDSA": true,
		"AES":   false,
		"":      false,
	}
	for algorithm, expected := range testData {
		result := IsSupportedAlgorithm(algorithm)
		assert.Equal(t, expected, result, fmt.Sprintf("algorithm: %s", algorithm))
	}

}

func TestNewSigner(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		s, err := NewSigner(SignatureRSA)
		assert.Nil(t, err)
		assert.NotNil(t, s)
	})
	t.Run("ECDSA", func(t *testing.T) {
		s, err := NewSigner(SignautreECDSA)
		assert.Nil(t, err)
		assert.NotNil(t, s)
	})
	t.Run("invalid param", func(t *testing.T) {
		s, err := NewSigner("")
		assert.NotNil(t, err, "expect error on invalid singature algorithm")
		assert.Nil(t, s, "do not expect a returned value for invalid signature algorithm")
	})
}
