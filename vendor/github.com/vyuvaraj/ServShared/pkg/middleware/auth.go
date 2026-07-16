package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ContextKey is the type for context keys to avoid collisions.
type ContextKey string

const (
	// ClaimsContextKey is the context key for authenticated claims.
	ClaimsContextKey ContextKey = "servverse-claims"
)

// Claims defines standard JWT claims for the Servverse ecosystem.
type Claims struct {
	Username string   `json:"username,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
	TenantID string   `json:"tenant_id,omitempty"`
	jwt.RegisteredClaims
}

// GetClaims extracts claims from request context (set by AuthMiddleware).
func GetClaims(r *http.Request) *Claims {
	if c, ok := r.Context().Value(ClaimsContextKey).(*Claims); ok {
		return c
	}
	return nil
}

type AuthValidator struct {
	jwtSecret     []byte
	jwksURL       string
	oidcIssuer    string
	jwkKeys       map[string]*rsa.PublicKey
	jwkKeysMu     sync.RWMutex
	jwksLastFetch time.Time
}

func NewAuthValidator(secret string, jwksURL string, oidcIssuer string) *AuthValidator {
	return &AuthValidator{
		jwtSecret: []byte(secret),
		jwksURL:   jwksURL,
		oidcIssuer: oidcIssuer,
		jwkKeys:   make(map[string]*rsa.PublicKey),
	}
}

// ValidateToken validates a JWT string and returns its claims.
func (v *AuthValidator) ValidateToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if v.jwksURL != "" {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			kid, _ := t.Header["kid"].(string)
			if kid == "" {
				return nil, errors.New("missing kid header")
			}
			return v.getRSAPublicKey(kid)
		}

		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return v.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		if v.oidcIssuer != "" && claims.Issuer != v.oidcIssuer {
			return nil, errors.New("invalid issuer")
		}
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// ExtractTokenFromHeader parses Authorization Bearer header.
func ExtractTokenFromHeader(headerVal string) (string, error) {
	if headerVal == "" {
		return "", errors.New("authorization header is missing")
	}
	parts := strings.Split(headerVal, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", errors.New("authorization header format must be Bearer <token>")
	}
	return parts[1], nil
}

func (v *AuthValidator) getRSAPublicKey(kid string) (*rsa.PublicKey, error) {
	v.jwkKeysMu.RLock()
	key, exists := v.jwkKeys[kid]
	v.jwkKeysMu.RUnlock()

	if exists && time.Since(v.jwksLastFetch) < 1*time.Hour {
		return key, nil
	}

	if err := v.fetchJWKS(); err != nil {
		if exists {
			return key, nil
		}
		return nil, err
	}

	v.jwkKeysMu.RLock()
	key, exists = v.jwkKeys[kid]
	v.jwkKeysMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("key id %s not found in JWKS", kid)
	}
	return key, nil
}

type jwkKey struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Alg string   `json:"alg"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

type jwkKeySet struct {
	Keys []jwkKey `json:"keys"`
}

func (v *AuthValidator) fetchJWKS() error {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(v.jwksURL)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks jwkKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	v.jwkKeysMu.Lock()
	defer v.jwkKeysMu.Unlock()

	for _, k := range jwks.Keys {
		if k.Kty == "RSA" {
			pubKey, err := parseRSAPublicKey(k.N, k.E)
			if err == nil {
				v.jwkKeys[k.Kid] = pubKey
			}
		}
	}
	v.jwksLastFetch = time.Now()
	return nil
}

func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)
	var eVal uint64
	for _, b := range eBytes {
		eVal = (eVal << 8) | uint64(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: int(eVal),
	}, nil
}

// AuthMiddleware returns an HTTP middleware that enforces JWT auth.
func AuthMiddleware(next http.Handler) http.Handler {
	secret := os.Getenv("SERV_JWT_SECRET")
	jwksURL := os.Getenv("SERV_JWKS_URL")
	if secret == "" && jwksURL == "" {
		return next // dev mode — no auth enforced
	}

	validator := NewAuthValidator(secret, jwksURL, "")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/healthz" || path == "/readyz" || path == "/health" ||
			strings.HasPrefix(path, "/api/auth/login") ||
			strings.HasPrefix(path, "/api/auth/register") ||
			strings.HasPrefix(path, "/api/auth/jwks") ||
			strings.HasPrefix(path, "/.well-known/jwks.json") ||
			strings.HasPrefix(path, "/api/auth/reset-password/") ||
			strings.HasPrefix(path, "/api/auth/magic-link/") ||
			strings.HasPrefix(path, "/api/auth/passkey/login/") ||
			strings.HasPrefix(path, "/oauth/token") ||
			strings.HasPrefix(path, "/api/v1/oauth/token") {
			next.ServeHTTP(w, r)
			return
		}

		token, err := ExtractTokenFromHeader(r.Header.Get("Authorization"))
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized: " + err.Error(), "code": "ERR_MISSING_AUTH"})
			return
		}

		claims, err := validator.ValidateToken(token)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized: " + err.Error(), "code": "ERR_INVALID_TOKEN"})
			return
		}

		ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
