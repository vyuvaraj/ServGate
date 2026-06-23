package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type GatewayConfig struct {
	Addr      string  `json:"addr"`
	AuthToken string  `json:"auth_token"`
	TlsCert   string  `json:"tls_cert"`
	TlsKey    string  `json:"tls_key"`
	Routes    []Route `json:"routes"`
	Signature string  `json:"signature,omitempty"`
}

type ConfigProvider interface {
	Load() (*GatewayConfig, error)
	Save(cfg *GatewayConfig) error
}

type LocalFileProvider struct {
	Path string
}

func NewLocalFileProvider(path string) *LocalFileProvider {
	return &LocalFileProvider{Path: path}
}

func (p *LocalFileProvider) Load() (*GatewayConfig, error) {
	file, err := os.Open(p.Path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cfg GatewayConfig
	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		return nil, err
	}

	if secret := os.Getenv("SERV_JWT_SECRET"); secret != "" {
		if err := verifyConfigSignature(&cfg, []byte(secret)); err != nil {
			return nil, fmt.Errorf("config signature verification failed: %w", err)
		}
	}

	return &cfg, nil
}

func (p *LocalFileProvider) Save(cfg *GatewayConfig) error {
	if secret := os.Getenv("SERV_JWT_SECRET"); secret != "" {
		if err := signConfig(cfg, []byte(secret)); err != nil {
			return fmt.Errorf("failed to sign config: %w", err)
		}
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p.Path, data, 0644)
}

type S3ConfigProvider struct {
	Endpoint  string
	Bucket    string
	Key       string
	AccessKey string
	SecretKey string
	AuthToken string
}

func NewS3ConfigProvider() *S3ConfigProvider {
	endpoint := os.Getenv("SERV_CONFIG_S3_ENDPOINT")
	bucket := os.Getenv("SERV_CONFIG_S3_BUCKET")
	key := os.Getenv("SERV_CONFIG_S3_KEY")
	accessKey := os.Getenv("SERV_CONFIG_S3_ACCESS_KEY")
	secretKey := os.Getenv("SERV_CONFIG_S3_SECRET_KEY")
	authToken := os.Getenv("SERV_CONFIG_S3_AUTH_TOKEN")

	if endpoint == "" || bucket == "" || authToken == "" {
		if raw := os.Getenv("SERVVERSE_DISCOVERY"); raw != "" {
			var manifest struct {
				Store     string `json:"store"`
				AuthToken string `json:"auth_token"`
			}
			if json.Unmarshal([]byte(raw), &manifest) == nil {
				if endpoint == "" && manifest.Store != "" {
					endpoint = manifest.Store
				}
				if authToken == "" && manifest.AuthToken != "" {
					authToken = manifest.AuthToken
				}
			} else {
				if data, err := os.ReadFile(raw); err == nil {
					if json.Unmarshal(data, &manifest) == nil {
						if endpoint == "" && manifest.Store != "" {
							endpoint = manifest.Store
						}
						if authToken == "" && manifest.AuthToken != "" {
							authToken = manifest.AuthToken
						}
					}
				}
			}
		}
	}

	if endpoint == "" {
		endpoint = "http://localhost:8081" // fallback to ServStore default
	}
	if bucket == "" {
		bucket = "serv-config"
	}
	if key == "" {
		key = "gate-config.json"
	}
	if authToken == "" {
		authToken = "gateway-secret-token" // default secret token
	}

	return &S3ConfigProvider{
		Endpoint:  strings.TrimSuffix(endpoint, "/"),
		Bucket:    bucket,
		Key:       key,
		AccessKey: accessKey,
		SecretKey: secretKey,
		AuthToken: authToken,
	}
}

func (p *S3ConfigProvider) ensureBucketExists() {
	url := fmt.Sprintf("%s/%s", p.Endpoint, p.Bucket)
	req, err := http.NewRequest("PUT", url, nil)
	if err != nil {
		return
	}
	if p.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+p.AuthToken)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

func (p *S3ConfigProvider) Load() (*GatewayConfig, error) {
	url := fmt.Sprintf("%s/%s/%s", p.Endpoint, p.Bucket, p.Key)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if p.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+p.AuthToken)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, os.ErrNotExist
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch config from S3 (%d): %s", resp.StatusCode, string(body))
	}

	var cfg GatewayConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, err
	}

	if secret := os.Getenv("SERV_JWT_SECRET"); secret != "" {
		if err := verifyConfigSignature(&cfg, []byte(secret)); err != nil {
			return nil, fmt.Errorf("config signature verification failed: %w", err)
		}
	}

	return &cfg, nil
}

func (p *S3ConfigProvider) Save(cfg *GatewayConfig) error {
	if secret := os.Getenv("SERV_JWT_SECRET"); secret != "" {
		if err := signConfig(cfg, []byte(secret)); err != nil {
			return fmt.Errorf("failed to sign config: %w", err)
		}
	}

	p.ensureBucketExists()

	url := fmt.Sprintf("%s/%s/%s", p.Endpoint, p.Bucket, p.Key)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	if p.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+p.AuthToken)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to save config to S3 (%d): %s", resp.StatusCode, string(body))
	}

	return nil
}

func signConfig(cfg *GatewayConfig, secret []byte) error {
	routesData, err := json.Marshal(cfg.Routes)
	if err != nil {
		return err
	}
	h := sha256.New()
	h.Write(routesData)
	computedHash := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	claims := map[string]interface{}{
		"config_hash": computedHash,
		"exp":         time.Now().Add(24 * time.Hour).Unix(),
		"iss":         "servconsole",
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return err
	}

	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return err
	}

	headerEnc := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimsEnc := base64.RawURLEncoding.EncodeToString(claimsBytes)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(headerEnc + "." + claimsEnc))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	cfg.Signature = headerEnc + "." + claimsEnc + "." + sig
	return nil
}

func verifyConfigSignature(cfg *GatewayConfig, secret []byte) error {
	if cfg.Signature == "" {
		return fmt.Errorf("missing configuration signature")
	}

	parts := strings.Split(cfg.Signature, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid signature format")
	}

	headerPart, payloadPart, signaturePart := parts[0], parts[1], parts[2]

	// Validate signature
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(headerPart + "." + payloadPart))
	expectedMac := mac.Sum(nil)

	sigBytes, err := decodeBase64Url(signaturePart)
	if err != nil || !hmac.Equal(sigBytes, expectedMac) {
		return fmt.Errorf("invalid signature")
	}

	payloadBytes, err := decodeBase64Url(payloadPart)
	if err != nil {
		return fmt.Errorf("failed to decode signature claims")
	}

	var claims struct {
		ConfigHash string `json:"config_hash"`
		Exp        int64  `json:"exp"`
		Issuer     string `json:"iss"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return fmt.Errorf("invalid signature claims JSON")
	}

	if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
		return fmt.Errorf("signature has expired")
	}

	if claims.Issuer != "servconsole" {
		return fmt.Errorf("invalid signature issuer: %s", claims.Issuer)
	}

	routesData, err := json.Marshal(cfg.Routes)
	if err != nil {
		return fmt.Errorf("failed to serialize routes for verification")
	}
	h := sha256.New()
	h.Write(routesData)
	computedHash := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	if claims.ConfigHash != computedHash {
		return fmt.Errorf("signature hash mismatch (possible configuration tampering)")
	}

	return nil
}

func decodeBase64Url(s string) ([]byte, error) {
	if l := len(s) % 4; l > 0 {
		s += strings.Repeat("=", 4-l)
	}
	return base64.URLEncoding.DecodeString(s)
}
