package rbac

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/render"
	"github.com/golang-jwt/jwt/v5"
)

var (
	secretKey     []byte
	secretKeyOnce sync.Once
	roleKey       = "role" // Default role key
)

func SetRoleKey(key string) {
	roleKey = key
}

func getSecretKey() ([]byte, error) {
	var err error
	secretKeyOnce.Do(func() {
		key := os.Getenv("SECRET_KEY")
		if key == "" {
			err = fmt.Errorf("SECRET_KEY environment variable is not set")
			return
		}
		secretKey = []byte(key)
	})
	return secretKey, err
}

func Guard[T comparable](access []T) func(http.Handler) http.Handler {
	accessMap := make(map[T]struct{})
	for _, a := range access {
		accessMap[a] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString, err := GetBearer(r)
			if err != nil {
				render.Render(w, r, ErrUnauthorized(err))
				return
			}

			role, err := GetRole[T](tokenString)
			if err != nil {
				render.Render(w, r, ErrUnauthorized(err))
				return
			}

			if _, ok := accessMap[role]; ok {
				next.ServeHTTP(w, r)
				return
			}

			render.Render(w, r, ErrForbidden(fmt.Errorf("permission denied for role: %v", role)))
		})
	}
}

func HashToken[T any](subject T, timeout time.Duration) (string, error) {
	secretKey, err := getSecretKey()
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": subject,
		"exp": time.Now().Add(timeout).Unix(),
	})

	return token.SignedString(secretKey)
}

func GetRole[T any](tokenString string) (T, error) {
	var zeroValue T

	secretKey, err := getSecretKey()
	if err != nil {
		return zeroValue, err
	}

	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})
	if err != nil {
		return zeroValue, err
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return zeroValue, fmt.Errorf("claims are not of type MapClaims")
	}

	subject, ok := claims["sub"].(map[string]interface{})
	if !ok {
		return zeroValue, fmt.Errorf("subject claim is missing or invalid")
	}

	role, ok := subject[roleKey]
	if !ok {
		return zeroValue, fmt.Errorf("role claim is missing or invalid")
	}

	typedRole, ok := role.(T)
	if !ok {
		return zeroValue, fmt.Errorf("role claim is not of the expected type")
	}

	return typedRole, nil
}

func GetBearer(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", fmt.Errorf("header 'Authorization' required")
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return "", fmt.Errorf("invalid token prefix: %s", auth)
	}

	return auth[len(prefix):], nil
}
