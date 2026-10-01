package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidatedCallbackHandler(t *testing.T) {
	tests := []struct {
		name, method, query string
		status              int
		code, failure       bool
	}{
		{"valid", "GET", "state=expected&code=sample", 200, true, false},
		{"missing state", "GET", "code=sample", 400, false, false},
		{"wrong state", "GET", "state=other&code=sample", 400, false, false},
		{"missing code", "GET", "state=expected", 400, false, false},
		{"wrong method", "POST", "state=expected&code=sample", 405, false, false},
		{"valid denial", "GET", "state=expected&error=access_denied", 400, false, true},
		{"forged denial", "GET", "state=other&error=access_denied", 400, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codes, errs := make(chan string, 1), make(chan error, 1)
			h := validatedCallbackHandler("expected", codes, errs)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(tt.method, "/callback?"+tt.query, nil))
			if w.Code != tt.status {
				t.Fatalf("status %d, want %d", w.Code, tt.status)
			}
			if (len(codes) > 0) != tt.code {
				t.Fatal("unexpected code acceptance")
			}
			if (len(errs) > 0) != tt.failure {
				t.Fatal("unexpected failure acceptance")
			}
		})
	}
}

func TestValidatedCallbackRejectThenAccept(t *testing.T) {
	codes, errs := make(chan string, 1), make(chan error, 1)
	h := validatedCallbackHandler("expected", codes, errs)
	for _, q := range []string{"state=wrong&code=bad", "state=expected&code=good"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/callback?"+q, nil))
	}
	if len(codes) != 1 || <-codes != "good" {
		t.Fatal("valid retry was not accepted")
	}
}
