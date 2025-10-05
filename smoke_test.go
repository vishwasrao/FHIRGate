package main

import (
	"net/http"
	"testing"
	"time"
)

// Smoke test that waits for Kong proxy to be available and hits the /cds-hooks route.
func TestSmoke_KongProxy(t *testing.T) {
	// Wait for Kong to become ready (up to 30s)
	client := &http.Client{Timeout: 5 * time.Second}
	url := "http://localhost:8000/cds-hooks"

	deadline := time.Now().Add(30 * time.Second)
	var resp *http.Response
	var err error
	for time.Now().Before(deadline) {
		resp, err = client.Get(url)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if err != nil {
		t.Fatalf("failed to reach Kong proxy at %s: %v", url, err)
	}
	defer resp.Body.Close()

	// Kong may return 200 (proxying to upstream) or 401 (plugin intercepting and requiring auth).
	if resp.StatusCode != 200 && resp.StatusCode != 401 {
		t.Fatalf("unexpected status from Kong proxy: %d", resp.StatusCode)
	}
}
