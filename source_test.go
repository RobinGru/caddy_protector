package caddyprotector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestLoadAllowlistMergesInlineFileAndURL(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "goodbots-*.ips")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	t.Cleanup(func() {
		if err := tmpFile.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	if _, err := tmpFile.WriteString("198.51.100.0/24\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("2001:db8::/32\n"))
	}))
	defer server.Close()
	bb := newTestProtector(t)
	bb.WhitelistIPs = []string{"192.0.2.1", "192.0.2.1 # duplicate"}
	bb.WhitelistFile = tmpFile.Name()
	bb.WhitelistURL = server.URL
	allowlist, err := bb.loadAllowlist(context.Background())
	if err != nil {
		t.Fatalf("loadAllowlist() error = %v", err)
	}
	if _, ok := allowlist.exactIPs[netip.MustParseAddr("192.0.2.1")]; !ok {
		t.Fatal("Inline-IP fehlt")
	}
	if allowlist.entries != 3 {
		t.Fatalf("entries = %d", allowlist.entries)
	}
}
func TestIPListRefreshRejectsRedirectAndRetainsSnapshot(t *testing.T) {
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://127.0.0.1/private", http.StatusFound)
	}))
	t.Cleanup(source.Close)

	bb := newTestProtector(t)
	bb.WhitelistURL = source.URL
	previous := &ipAllowlist{exactIPs: map[netip.Addr]struct{}{netip.MustParseAddr("192.0.2.1"): {}}}
	bb.allowlist.Store(previous)
	core, logs := observer.New(zap.WarnLevel)
	bb.logger = zap.New(core)
	stop := make(chan struct{})
	done := make(chan struct{})
	go bb.runIPListRefreshLoop("allowlist", time.Millisecond, stop, done, bb.loadAllowlist, bb.allowlist.Store)

	deadline := time.Now().Add(time.Second)
	for logs.FilterMessage("IP-Listen-Refresh fehlgeschlagen").Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(stop)
	<-done
	if logs.FilterMessage("IP-Listen-Refresh fehlgeschlagen").Len() == 0 {
		t.Fatal("refresh failure was not logged")
	}
	if current := bb.allowlist.Load().(*ipAllowlist); current != previous {
		t.Fatal("refresh replaced the previous snapshot after a rejected redirect")
	}
}
