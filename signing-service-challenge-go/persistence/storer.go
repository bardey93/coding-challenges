package persistence

import "github.com/fiskaly/coding-challenges/signing-service-challenge/domain"

type Storer interface {
	CreateSignatureDevice(device *domain.SignatureDevice) (*domain.SignatureDevice, error)
	ReadSignatureDevices() ([]*domain.SignatureDevice, error)
	ReadSignatureDevice(id string) (*domain.SignatureDevice, error)
}
