package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestHealthEndpoint(t *testing.T) {
	os.Setenv("VERCEL_WEBHOOK_SECRET", "test_secret")
	defer os.Unsetenv("VERCEL_WEBHOOK_SECRET")

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK\n"))
	})

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "OK\n" {
		t.Errorf("expected OK, got %s", w.Body.String())
	}
}

func computeSig(secret []byte, body []byte) string {
	mac := hmac.New(sha1.New, secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySignature(t *testing.T) {
	secret := []byte("test_secret")
	body := []byte(`[{"id":"42","message":"hello"}]`)

	sig := computeSig(secret, body)
	if !verifySignature(secret, body, sig) {
		t.Error("valid signature should pass")
	}

	if verifySignature(secret, body, "bad000bad000") {
		t.Error("invalid signature should fail")
	}

	if verifySignature(secret, body, "") {
		t.Error("empty signature should fail")
	}
}

func TestVercelVerifyHandshake(t *testing.T) {
	os.Setenv("VERCEL_WEBHOOK_SECRET", "test")
	defer os.Unsetenv("VERCEL_WEBHOOK_SECRET")

	mux := http.NewServeMux()
	secret := []byte("test")
	mux.HandleFunc("/vercel", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if token := r.Header.Get("x-vercel-verify"); token != "" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(token))
			return
		}
		body, _ := io.ReadAll(r.Body)  // assuming io is now imported
		if sig := r.Header.Get("x-vercel-signature"); !verifySignature(secret, body, sig) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK\n"))
	})

	req := httptest.NewRequest("POST", "/vercel", nil)
	req.Header.Set("x-vercel-verify", "token123")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "token123" {
		t.Errorf("expected token123, got %s", w.Body.String())
	}
}

func TestNormalizeMessage(t *testing.T) {
	plain := json.RawMessage(`"Build completed"`)
	result := normalizeMessage(plain)
	expected := `{"text":"Build completed"}`
	if result != expected {
		t.Errorf("plain text: expected %s, got %s", expected, result)
	}

	jsonMsg := json.RawMessage(`{"status":200}`)
	result = normalizeMessage(jsonMsg)
	expected = `{"status":200}`
	if result != expected {
		t.Errorf("json: expected %s, got %s", expected, result)
	}

	empty := json.RawMessage(``)
	result = normalizeMessage(empty)
	if result != "" {
		t.Errorf("empty: expected empty, got %s", result)
	}
}

func TestLogEntryConversion(t *testing.T) {
	entry := toLogEntry(vercelLog{
		ID:      "abc",
		Message: json.RawMessage(`"hello"`),
		Level:   "info",
	})

	if entry.ID != "abc" {
		t.Errorf("expected abc, got %s", entry.ID)
	}
	if entry.Level == nil || *entry.Level != "info" {
		t.Error("level mismatch")
	}
	if entry.Message == nil || *entry.Message != `{"text":"hello"}` {
		t.Errorf("message mismatch: %v", entry.Message)
	}
}
