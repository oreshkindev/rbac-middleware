package rbac

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/render"
	"github.com/golang-jwt/jwt/v5"
)

type (
	Access string
)

const (
	version = "v0.0.1"
)

// Guard is a middleware function that checks the access level of a user
// based on the provided access levels.
//
// Parameters:
// - access: a slice of Access levels that represent the allowed access levels.
//
// Returns:
// - A function that takes a http.Handler as input and returns a http.Handler.
func Guard(access []Access) func(http.Handler) http.Handler {
	// Return a function that takes a http.Handler as input and returns a http.Handler.
	return func(next http.Handler) http.Handler {
		// Return a http.HandlerFunc that takes a http.ResponseWriter and a *http.Request as input.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Declare variables to store the token string and role.
			var (
				tokenString string
				role        string

				err error
			)

			// Get the token string from the request headers.
			if tokenString, err = GetBearer(r); err != nil {
				// If there is an error, render an unauthorized error response.
				render.Render(w, r, ErrUnauthorized(err))
				return
			}

			// Get the role from the token string.
			if role, err = GetRole(tokenString); err != nil {
				// If there is an error, render an unauthorized error response.
				render.Render(w, r, ErrUnauthorized(err))
				return
			}

			// Check if the role has permission based on the access levels.
			hasPermission := false
			for _, ac := range access {
				if role == string(ac) {
					hasPermission = true
					break
				}
			}
			if hasPermission {
				// If the role has permission, serve the next http.Handler.
				next.ServeHTTP(w, r)
				return
			}

			// If the role does not have permission, render an invalid request error response.
			render.Render(w, r, ErrInvalidRequest(fmt.Errorf("Permission rule for %s is not allowed", role)))
		})
	}
}

// HashToken generates a JWT token string for the provided subject with the specified timeout using the provided secret key.
//
// subject: the subject to be included in the token claims.
// timeout: the duration for which the token is valid.
// Returns the generated JWT token string and an error if any.
func HashToken[T any](subject T, timeout time.Duration) (string, error) {
	// Create a new token with the HMAC SHA256 signing method and the provided subject and expiration claims.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		// Subject claim represents the subject of the token.
		"sub": subject,
		// Expiration claim represents the expiration time of the token.
		"exp": time.Now().Add(timeout * time.Minute).Unix(),
	})

	// Sign the token using the provided secret key and return the signed token string.
	return token.SignedString([]byte(os.Getenv("SECRET_KEY")))
}

// GetRole retrieves the role from the subject claim of a JWT token.
//
// Parameters:
// - tokenString: the JWT token string.
//
// Returns:
// - string: the role extracted from the token subject claim.
// - error: an error if the token is invalid or if the role claim is missing or invalid.
func GetRole(tokenString string) (string, error) {
	// Parse the JWT token using the provided secret key.
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			// Return an error if the signing method is unexpected.
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		// Return the secret key as the key for verifying the token signature.
		return []byte(os.Getenv("SECRET_KEY")), nil
	})
	if err != nil {
		// Return an error if the token parsing fails.
		return "", err
	}

	// Convert the parsed token claims to a MapClaims type.
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		// Return an error if the claims are not of type MapClaims.
		return "", fmt.Errorf("Claims are not of type MapClaims")
	}

	// Get the subject claim from the parsed token claims.
	subject, ok := claims["sub"].(map[string]interface{})
	if !ok {
		// Return an error if the subject claim is missing or invalid.
		return "", fmt.Errorf("Subject claim is missing or invalid")
	}

	// Get the role claim from the subject claim.
	role, ok := subject["role"].(string)
	if !ok {
		// Return an error if the role claim is missing or invalid.
		return "", fmt.Errorf("Role claim is missing or invalid")
	}

	// Return the extracted role from the token subject claim.
	return role, nil
}

// GetBearer retrieves the bearer token from the request headers.
// It checks if the "Authorization" header is present and if it starts with "Bearer ".
// If the header is missing or invalid, it returns an error. Otherwise, it extracts and returns the bearer token.
//
// Parameters:
// - r: the http.Request object from which to extract the bearer token.
//
// Returns:
// - string: the bearer token extracted from the request headers.
// - error: an error if the header is missing or invalid.
func GetBearer(r *http.Request) (string, error) {

	// Get the value of the "Authorization" header
	headers := r.Header.Get("Authorization")
	if headers == "" {
		return "", fmt.Errorf("Header 'Authorization' required")
	}

	// Check if the header starts with "Bearer "
	if !strings.HasPrefix(headers, "Bearer ") {
		return "", fmt.Errorf("Missing or invalid token prefix: %s", headers)
	}

	// Extract the bearer token from the header
	return headers[len("Bearer "):], nil
}
