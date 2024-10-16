package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewECDSASigner(t *testing.T) {
	ecdsaSigner, err := NewECDSASigner()
	assert.Nil(t, err)
	assert.NotEqual(t, ECDSASigner{}, ecdsaSigner)
}

func TestECDSASign(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		payload := []byte("toBeSigned")
		signer, err := NewECDSASigner()
		assert.Nil(t, err)

		signature, err := signer.Sign(payload)
		assert.Nil(t, err)
		assert.NotNil(t, 0, len(signature))

	})
	t.Run("empty", func(t *testing.T) {
		payload := []byte("toBeSigned")
		signer, err := NewECDSASigner()
		assert.Nil(t, err)

		signature, err := signer.Sign(payload)
		assert.Nil(t, err)
		assert.NotNil(t, signature)
	})
	t.Run("default sign and verify", func(t *testing.T) {
		payload := []byte("toBeSigned")
		signer, err := NewECDSASigner()
		assert.Nil(t, err)

		signature, err := signer.Sign(payload)
		assert.Nil(t, err)

		verified := signer.Verify(payload, signature)
		assert.True(t, verified)
	})
}
