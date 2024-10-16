package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
	"github.com/google/uuid"
)

// GetSignatureDevices lists all stored SignatureDevices
func (s *Server) GetSignatureDevices(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		WriteErrorResponse(response, http.StatusMethodNotAllowed, []string{
			http.StatusText(http.StatusMethodNotAllowed),
		})
		return
	}

	devices, err := s.storer.ReadSignatureDevices()
	if err != nil {
		log.Printf("GetSignatureDevices read devices | %s", err)
		WriteErrorResponse(response, http.StatusInternalServerError, []string{http.StatusText(http.StatusInternalServerError)})
	}

	WriteAPIResponse(response, http.StatusOK, devices)
}

// PostSignatureDevie creates a new signature device and stores it with the storer
func (s *Server) PostSignatureDevice(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		WriteErrorResponse(response, http.StatusMethodNotAllowed, []string{
			http.StatusText(http.StatusMethodNotAllowed),
		})
		return
	}

	// handle inputs
	id := request.URL.Query().Get("id")
	label := request.URL.Query().Get("label")
	algorithm := request.URL.Query().Get("algorithm")
	if !crypto.IsSupportedAlgorithm(algorithm) {
		log.Printf("PostSignatureDevice unsupported algorithm: %s", algorithm)
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			http.StatusText(http.StatusBadRequest),
		})
		return
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		log.Printf("PostSignatureDevice invalid | err: %s", err)
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			http.StatusText(http.StatusBadRequest),
		})
		return
	}

	sd, err := domain.NewSignatureDevice(uid, label, crypto.SignatureAlgorithm(algorithm))
	if err != nil {
		log.Printf("PostSignatureDevice New Signaturedevice: %s | err: %s", sd.ID, err)
		WriteErrorResponse(response, http.StatusInternalServerError, []string{
			http.StatusText(http.StatusInternalServerError),
		})
		return
	}

	sd, err = s.storer.CreateSignatureDevice(sd)
	if err != nil {
		log.Printf("PostSignatureDevice store signatureDevice | err: %s", err)
		WriteErrorResponse(response, http.StatusInternalServerError, []string{
			http.StatusText(http.StatusInternalServerError),
		})
		return
	}

	WriteAPIResponse(response, http.StatusOK, sd)
}

func (s *Server) PostSignature(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		WriteErrorResponse(response, http.StatusMethodNotAllowed, []string{
			http.StatusText(http.StatusMethodNotAllowed),
		})
		return
	}

	payload := SignatureRequest{}
	err := json.NewDecoder(request.Body).Decode(&payload)
	if err != nil {
		log.Printf("PostSignautre decode | err: %s", err)
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			http.StatusText(http.StatusBadRequest),
		})
		return
	}

	sd, err := s.storer.ReadSignatureDevice(payload.ID)
	if err != nil {
		log.Printf("PostSignature read device | err: %s", err)
		WriteErrorResponse(response, http.StatusInternalServerError, []string{
			http.StatusText(http.StatusInternalServerError),
		})
		return
	}

	signature, signedData, err := sd.Sign(payload.Data)
	if err != nil {
		log.Printf("PostSignature sign | err: %s", err)
		WriteErrorResponse(response, http.StatusInternalServerError, []string{
			http.StatusText(http.StatusInternalServerError),
		})
		return
	}
	resp := SignatureResponse{
		SignedData: signedData,
		Signature:  signature,
	}

	WriteAPIResponse(response, http.StatusOK, resp)
}
