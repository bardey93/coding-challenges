package persistence

import (
	"fmt"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
	"github.com/google/uuid"
)

type InMemoryStorer struct {
	Devices map[string]*domain.SignatureDevice
}

// CreateSignatureDevice stores a domain.SignatureDevice in the memory store. Expects a valid UUID. If the id already exists, the entry is updated.
func (s InMemoryStorer) CreateSignatureDevice(device *domain.SignatureDevice) (*domain.SignatureDevice, error) {
	if device == nil {
		return nil, fmt.Errorf("CreateSignatureDevice | device is nil")
	}
	if device.ID == uuid.Nil {
		return nil, fmt.Errorf("CreateSignatureDevice | no id")
	}
	s.Devices[string(device.ID.String())] = device
	return device, nil
}

func (s InMemoryStorer) ReadSignatureDevices() ([]*domain.SignatureDevice, error) {
	devices := make([]*domain.SignatureDevice, len(s.Devices))

	i := 0
	for _, dev := range s.Devices {
		devices[i] = dev
		i++
	}
	return devices, nil
}

func (s InMemoryStorer) ReadSignatureDevice(id string) (*domain.SignatureDevice, error) {
	_, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("ReadSignatureDevice | invalid uuid")
	}
	return s.Devices[id], nil
}
