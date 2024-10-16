package api

import (
	"encoding/json"
	"net/http"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/persistence"
)

// Response is the generic API response container.
type Response struct {
	Data interface{} `json:"data"`
}

// SignatureRequest struct is the request payload for signature handlers
type SignatureRequest struct {
	ID   string `json:"id"`
	Data string `json:"data"`
}

// SignatureResponse is the response struct for the signature handler
type SignatureResponse struct {
	SignedData string `json:"signed_data"`
	Signature  string `json:"signature"`
}

// ErrorResponse is the generic error API response container.
type ErrorResponse struct {
	Errors []string `json:"errors"`
}

// Server manages HTTP requests and dispatches them to the appropriate services.
type Server struct {
	listenAddress string
	Storer        persistence.Storer
}

// NewServer is a factory to instantiate a new Server.
func NewServer(listenAddress string) *Server {
	return &Server{
		listenAddress: listenAddress,
		Storer: persistence.InMemoryStorer{
			Devices: map[string]*domain.SignatureDevice{},
		},
		// TODO: add services / further dependencies here ...
	}
}

// Run registers all HandlerFuncs for the existing HTTP routes and starts the Server.
func (s *Server) Run() error {
	mux := http.NewServeMux()

	mux.Handle("/api/v0/health", http.HandlerFunc(s.Health))

	mux.Handle("/api/v0/devices", http.HandlerFunc(s.GetSignatureDevices))
	mux.Handle("/api/v0/devices/create", http.HandlerFunc(s.PostSignatureDevice))
	mux.Handle("/api/v0/devices/sign", http.HandlerFunc(s.PostSignature))

	return http.ListenAndServe(s.listenAddress, mux)
}

// WriteInternalError writes a default internal error message as an HTTP response.
func WriteInternalError(w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
}

// WriteErrorResponse takes an HTTP status code and a slice of errors
// and writes those as an HTTP error response in a structured format.
func WriteErrorResponse(w http.ResponseWriter, code int, errors []string) {
	w.WriteHeader(code)

	errorResponse := ErrorResponse{
		Errors: errors,
	}

	bytes, err := json.Marshal(errorResponse)
	if err != nil {
		WriteInternalError(w)
	}

	w.Write(bytes)
}

// WriteAPIResponse takes an HTTP status code and a generic data struct
// and writes those as an HTTP response in a structured format.
func WriteAPIResponse(w http.ResponseWriter, code int, data interface{}) {
	w.WriteHeader(code)

	response := Response{
		Data: data,
	}

	bytes, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		WriteInternalError(w)
	}

	w.Write(bytes)
}
