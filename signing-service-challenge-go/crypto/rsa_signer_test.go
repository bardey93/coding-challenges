package crypto

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRSASigner(t *testing.T) {
	rsaSigner, err := NewRSASigner()
	assert.Nil(t, err)
	assert.NotEqual(t, RSASigner{}, rsaSigner)
}

func TestRSASign(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		payload := []byte("toBeSigned")
		signer, err := NewRSASigner()
		assert.Nil(t, err)

		signature, err := signer.Sign(payload)
		assert.Nil(t, err)
		assert.NotNil(t, 0, len(signature))

	})
	t.Run("empty", func(t *testing.T) {
		payload := []byte("toBeSigned")
		signer, err := NewRSASigner()
		assert.Nil(t, err)

		signature, err := signer.Sign(payload)
		assert.Nil(t, err)
		assert.NotNil(t, signature)
	})
	t.Run("default", func(t *testing.T) {
		payload := []byte("toBeSigned")
		signer, err := NewRSASigner()
		assert.Nil(t, err)

		signature, err := signer.Sign(payload)
		assert.Nil(t, err)

		hash := sha256.Sum256(payload)
		err = rsa.VerifyPKCS1v15(signer.key.Public, crypto.SHA256, hash[:], signature)
		assert.Nil(t, err)
	})
}
