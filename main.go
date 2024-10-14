package rbac

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type (
	ContextKey string
	Access     interface{}
)

const (
	PermissionKey ContextKey = "permission"
)

func Middleware(allowedPermissions ...Access) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString, err := GetBearer(r)
			if err != nil {
				errResponse := ErrUnauthorized(err)
				errResponse.Render(w, r)
				return
			}

			claims, err := Validate(tokenString)
			if err != nil {
				errResponse := ErrUnauthorized(err)
				errResponse.Render(w, r)
				return
			}

			permission, ok := claims["permission"]
			switch {
			case !ok:
				errResponse := ErrUnauthorized(fmt.Errorf("Invalid permission claim"))
				errResponse.Render(w, r)
			case !hasPermission(permission, allowedPermissions):
				errResponse := ErrInvalidRequest(fmt.Errorf("Permission denied for %v", permission))
				errResponse.Render(w, r)
			default:
				ctx := context.WithValue(r.Context(), PermissionKey, permission)
				next.ServeHTTP(w, r.WithContext(ctx))
			}
		})
	}
}

func Hash(subject map[string]interface{}, timeout time.Duration) (string, error) {
	secretKey := os.Getenv("SECRET_KEY")
	if secretKey == "" {
		return "", fmt.Errorf("Secret key not set in environment")
	}

	claims := jwt.MapClaims{
		"exp": time.Now().Add(timeout * time.Minute).Unix(),
	}
	for k, v := range subject {
		claims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

func Validate(tokenString string) (jwt.MapClaims, error) {
	secretKey := os.Getenv("SECRET_KEY")
	if secretKey == "" {
		return nil, fmt.Errorf("Secret key not set in environment")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("Invalid token: token has expired")
		}
		return nil, fmt.Errorf("Invalid token: %v", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("Invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("Invalid claims")
	}

	return claims, nil
}

func GetBearer(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		return "", fmt.Errorf("Missing or invalid token prefix")
	}
	return strings.TrimPrefix(auth, "Bearer "), nil
}

func hasPermission(userPermission interface{}, allowedPermissions []Access) bool {
	userPermStr := toString(userPermission)
	for _, permission := range allowedPermissions {
		if userPermStr == toString(permission) {
			return true
		}
	}
	return false
}

func toString(v interface{}) string {
	switch val := v.(type) {
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case string:
		return val
	default:
		return fmt.Sprintf("%v", val)
	}
}
