package rbac

import (
	"net/http"

	"github.com/go-chi/render"
)

type ErrResponse struct {
	HTTPStatusCode int    `json:"code"`            // http response status code
	Err            error  `json:"-"`               // low-level runtime error
	Status         string `json:"status"`          // user-level status message
	Error          string `json:"error,omitempty"` // application-level error message, for debugging
}

func (err *ErrResponse) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, err.HTTPStatusCode)
	return nil
}

func ErrInvalidRequest(err error) render.Renderer {
	return &ErrResponse{
		HTTPStatusCode: 400,
		Err:            err,
		Status:         "Invalid request",
		Error:          err.Error(),
	}
}

func ErrUnauthorized(err error) render.Renderer {
	return &ErrResponse{
		HTTPStatusCode: 401,
		Err:            err,
		Status:         "Unauthorized",
		Error:          err.Error(),
	}
}
