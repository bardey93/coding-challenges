package persistence

import "github.com/fiskaly/coding-challenges/signing-service-challenge/domain"

type InMemoryStorer struct {
	Devices map[string]*domain.SignatureDevice
}

func (s InMemoryStorer) CreateSignatureDevice(device *domain.SignatureDevice) (*domain.SignatureDevice, error) {
	s.Devices[string(device.ID.String())] = device
	return nil, nil
}

func (s InMemoryStorer) ReadSignatureDevices() ([]*domain.SignatureDevice, error) {
	devices := make([]*domain.SignatureDevice, len(s.Devices))
	for _, dev := range s.Devices {
		devices = append(devices, dev)
	}
	return devices, nil
}

func (s InMemoryStorer) ReadSignatureDevice(id string) (*domain.SignatureDevice, error) {
	return s.Devices[id], nil
}
