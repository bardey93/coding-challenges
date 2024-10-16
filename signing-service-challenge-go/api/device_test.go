package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/persistence"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSignatureDevices(t *testing.T) {
	s := NewServer(":8080")
	s.Storer = getStorerWithData(t)

	r := httptest.NewRequest("GET", "http://localhost:8080/api/v0/devices", nil)
	w := httptest.NewRecorder()
	s.GetSignatureDevices(w, r)

	resp := w.Result()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestPostSignatureDevice(t *testing.T) {
	s := NewServer(":8080")

	r := httptest.NewRequest("POST", "http://localhost:8080/api/v0/devices/create?id=38da2fb6-c293-4a63-a349-835330f0aca7&label=myDev&algorithm=RSA", nil)
	w := httptest.NewRecorder()
	s.PostSignatureDevice(w, r)

	resp := w.Result()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestPostSignature(t *testing.T) {
	s := NewServer(":8080")
	s.Storer = getStorerWithData(t)
	payload := SignatureRequest{
		ID:   "38da2fb6-c293-4a63-a349-835330f0aca7",
		Data: "data",
	}
	raw, err := json.Marshal(payload)
	require.Nil(t, err)

	r := httptest.NewRequest("POST", "http://localhost:8080/api/v0/devices/sign", bytes.NewBuffer(raw))
	w := httptest.NewRecorder()
	s.PostSignature(w, r)

	resp := w.Result()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
func getDeviceMap(t *testing.T) map[string]*domain.SignatureDevice {
	uuid1, err := uuid.Parse("38da2fb6-c293-4a63-a349-835330f0aca7")
	require.Nil(t, err, "uuid1 parse")
	dev1, err := domain.NewSignatureDevice(uuid1, "Dev1", crypto.SignatureRSA)
	require.Nil(t, err, "dev1")

	uuid2, err := uuid.Parse("1727d3e0-e1ae-410c-97d2-70da0ae0abc4")
	require.Nil(t, err, "uuid2 parse")
	dev2, err := domain.NewSignatureDevice(uuid2, "Dev2", crypto.SignautreECDSA)
	require.Nil(t, err, "dev2")

	uuid3, err := uuid.Parse("ff50085e-463d-4b83-a4e6-94e9eae3dbaf")
	require.Nil(t, err, "uuid3 parse")
	dev3, err := domain.NewSignatureDevice(uuid3, "Dev3", crypto.SignatureRSA)
	require.Nil(t, err, "dev3")

	uuid4, err := uuid.Parse("e2a31dd8-1356-4c73-980a-69fd86af0dc9")
	require.Nil(t, err, "uuid4 parse")
	dev4, err := domain.NewSignatureDevice(uuid4, "", crypto.SignautreECDSA)
	require.Nil(t, err, "dev4")

	deviceMap := map[string]*domain.SignatureDevice{
		uuid1.String(): dev1,
		uuid2.String(): dev2,
		uuid3.String(): dev3,
		uuid4.String(): dev4,
	}
	return deviceMap
}

func getStorerWithData(t *testing.T) persistence.InMemoryStorer {
	deviceMap := getDeviceMap(t)

	return persistence.InMemoryStorer{
		Devices: deviceMap,
	}
}
