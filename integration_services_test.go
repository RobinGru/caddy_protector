//go:build integration

package caddyprotector

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type syntheticCapService struct {
	*httptest.Server
	mu             sync.Mutex
	verifications  int
	allowlistLoads int
}

func newSyntheticCapService(t *testing.T) *syntheticCapService {
	t.Helper()
	service := &syntheticCapService{}
	service.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		service.mu.Lock()
		defer service.mu.Unlock()
		switch request.URL.Path {
		case "/synthetic-site/siteverify":
			service.verifications++
			var payload map[string]string
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil || payload["secret"] != "synthetic-secret" || payload["response"] != "synthetic-token" {
				http.Error(w, "invalid synthetic verification", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true}`))
		case "/allowlist":
			service.allowlistLoads++
			_, _ = w.Write([]byte("192.0.2.1\n"))
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(service.Close)
	return service
}

func (s *syntheticCapService) Verifications() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifications
}

func (s *syntheticCapService) AllowlistLoads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allowlistLoads
}

type recordingUpstream struct {
	*httptest.Server
	mu    sync.Mutex
	count int
}

func newRecordingUpstream(t *testing.T) *recordingUpstream {
	t.Helper()
	upstream := &recordingUpstream{}
	upstream.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstream.mu.Lock()
		upstream.count++
		upstream.mu.Unlock()
		_, _ = io.WriteString(w, "upstream")
	}))
	t.Cleanup(upstream.Close)
	return upstream
}

func (u *recordingUpstream) Count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.count
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(data)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}
