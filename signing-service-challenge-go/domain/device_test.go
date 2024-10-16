package domain

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"testing"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSignatureDevice(t *testing.T) {
	t.Run("no id", func(t *testing.T) {
		sd, err := NewSignatureDevice(uuid.Nil, "", crypto.SignatureRSA)
		require.Nil(t, sd)
		assert.NotNil(t, err)
	})
	t.Run("no algorithm", func(t *testing.T) {
		sd, err := NewSignatureDevice(uuid.New(), "", "")
		require.Nil(t, sd)
		assert.NotNil(t, err)
	})
	t.Run("default", func(t *testing.T) {
		id := uuid.New()
		label := "myDev"
		algorithm := crypto.SignatureRSA
		base64ID := base64.StdEncoding.EncodeToString([]byte(id.String()))

		sd, err := NewSignatureDevice(id, label, algorithm)
		require.Nil(t, err)
		require.NotNil(t, sd)

		assert.Equal(t, id, sd.ID)
		assert.Equal(t, label, sd.Label)
		assert.Equal(t, algorithm, sd.Algorithm)
		assert.Equal(t, 0, sd.signatureCounter)
		assert.Equal(t, base64ID, sd.lastSignature)
	})
}

func TestSign(t *testing.T) {
	dataToBeSigned := "data"
	t.Run("ecdsa sign", func(t *testing.T) {
		sd, err := NewSignatureDevice(uuid.New(), "myDev", crypto.SignautreECDSA)
		require.Nil(t, err)
		require.NotNil(t, sd)

		base64ID := base64.StdEncoding.EncodeToString([]byte(sd.ID.String()))
		expectedSecData := fmt.Sprintf("0_data_%s", base64ID)

		signature, secData, err := sd.Sign(dataToBeSigned)
		require.Nil(t, err)
		assert.Equal(t, expectedSecData, secData)

		rawSig, err := base64.StdEncoding.DecodeString(signature)
		require.Nil(t, err)

		verified := sd.signer.Verify([]byte(expectedSecData), rawSig)
		assert.True(t, verified)

		assert.Equal(t, signature, sd.lastSignature)
	})
	t.Run("rsa sign", func(t *testing.T) {
		sd, err := NewSignatureDevice(uuid.New(), "myDev", crypto.SignatureRSA)
		require.Nil(t, err)
		require.NotNil(t, sd)

		base64ID := base64.StdEncoding.EncodeToString([]byte(sd.ID.String()))
		expectedSecData := fmt.Sprintf("0_data_%s", base64ID)

		signature, secData, err := sd.Sign(dataToBeSigned)
		require.Nil(t, err)
		assert.Equal(t, expectedSecData, secData)

		rawSig, err := base64.StdEncoding.DecodeString(signature)
		require.Nil(t, err)

		verified := sd.signer.Verify([]byte(expectedSecData), rawSig)
		assert.True(t, verified)

		assert.Equal(t, signature, sd.lastSignature)
	})

}

func TestPrepareSecDataToBeSigned(t *testing.T) {
	t.Run("no input", func(t *testing.T) {
		expected := "0__"
		res := prepareSecDataToBeSigned("", "", 0)
		assert.Equal(t, 3, len(res))
		strRes := string(res)
		assert.Equal(t, expected, strRes)
	})
	t.Run("default", func(t *testing.T) {
		dataToBeSigned := "data"
		lastSignature := "no-a-real-base64-string"
		counter := -17
		expected := strconv.Itoa(counter) + "_" + dataToBeSigned + "_" + lastSignature
		res := prepareSecDataToBeSigned(dataToBeSigned, lastSignature, counter)
		assert.Equal(t, expected, res)
	})
}
