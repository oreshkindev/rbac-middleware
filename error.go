package rbac

import (
	"encoding/json"
	"net/http"
)

// Renderer интерфейс для объектов, которые могут быть отрендерены в HTTP-ответ
type Renderer interface {
	Render(w http.ResponseWriter, r *http.Request) error
}

// SetStatus устанавливает HTTP-статус для ответа
func SetStatus(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
}

type ErrResponse struct {
	HTTPStatusCode int    `json:"code"`            // http response status code
	Status         string `json:"status"`          // user-level status message
	Error          string `json:"error,omitempty"` // application-level error message, for debugging
}

func (err *ErrResponse) Render(w http.ResponseWriter, r *http.Request) error {
	SetStatus(w, err.HTTPStatusCode)
	return json.NewEncoder(w).Encode(err)
}

func ErrInvalidRequest(err error) Renderer {
	return &ErrResponse{
		HTTPStatusCode: http.StatusBadRequest,
		Status:         "Invalid request",
		Error:          err.Error(),
	}
}

func ErrUnauthorized(err error) Renderer {
	return &ErrResponse{
		HTTPStatusCode: http.StatusUnauthorized,
		Status:         "Unauthorized",
		Error:          err.Error(),
	}
}
