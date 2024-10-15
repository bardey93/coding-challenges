package persistence

import (
	"testing"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateSignatureDevice(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		s := getEmptyStorer()
		sd, err := s.CreateSignatureDevice(nil)
		assert.NotNil(t, err, "storing nil expects error")
		assert.Nil(t, sd, "nil return value expected on error")
	})
	t.Run("empty", func(t *testing.T) {
		s := getEmptyStorer()
		sd, err := s.CreateSignatureDevice(&domain.SignatureDevice{})
		assert.NotNil(t, err, "storing nil expects error")
		assert.Nil(t, sd, "nil return value expected on error")
	})
	t.Run("new", func(t *testing.T) {
		s := getEmptyStorer()
		devices := getDeviceMap(t)
		for _, dev := range devices {
			sd, err := s.CreateSignatureDevice(dev)
			assert.Nil(t, err)
			dev := s.Devices[dev.ID.String()]
			assert.Equal(t, dev.ID, sd.ID, "device shoudld be stored with its id")
		}
	})
	t.Run("collision", func(t *testing.T) {
		s := getStorerWithData(t)
		devices := s.Devices
		for _, dev := range devices {
			sd, err := s.CreateSignatureDevice(dev)
			assert.Nil(t, err)
			assert.Equal(t, dev, sd, "expected devices to be equal")
		}
	})
}

func TestReadSignatureDevices(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		s := getEmptyStorer()

		gotDevices, err := s.ReadSignatureDevices()
		assert.Nil(t, err)
		assert.Equal(t, 0, len(gotDevices))
	})
	t.Run("read all", func(t *testing.T) {
		s := getStorerWithData(t)
		devices := s.Devices

		gotDevices, err := s.ReadSignatureDevices()
		assert.Nil(t, err)
		for _, gotDev := range gotDevices {
			device := devices[gotDev.ID.String()]
			assert.Equal(t, device, gotDev, "devices not equal")
		}
	})
}

func TestReadSignatureDevice(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		s := getEmptyStorer()

		dev, err := s.ReadSignatureDevice(uuid.NewString())
		assert.Nil(t, err)
		assert.Nil(t, dev, "no device expected")
	})

	t.Run("empty string", func(t *testing.T) {
		s := getStorerWithData(t)
		dev, err := s.ReadSignatureDevice("")
		assert.NotNil(t, err, "expect error for invalid id")
		assert.Nil(t, dev, "expect no device for invalid id")
	})
	t.Run("retrieve device", func(t *testing.T) {
		s := getStorerWithData(t)
		devices := s.Devices

		for id, device := range devices {
			gotDev, err := s.ReadSignatureDevice(id)
			assert.Nil(t, err)
			assert.Equal(t, device, gotDev, "devices not equal")
		}
	})

}

func getEmptyStorer() InMemoryStorer {
	return InMemoryStorer{
		Devices: map[string]*domain.SignatureDevice{},
	}
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

func getStorerWithData(t *testing.T) InMemoryStorer {
	deviceMap := getDeviceMap(t)

	return InMemoryStorer{
		Devices: deviceMap,
	}
}
