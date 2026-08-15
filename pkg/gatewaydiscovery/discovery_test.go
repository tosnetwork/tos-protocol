package gatewaydiscovery

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func expected() Expected {
	return Expected{"test", "sha256:root", "sha256:file", "tvm-cell-sha256:code"}
}
func document(origin string, expiry int64) string {
	return fmt.Sprintf(`{"schema":"%s","protocol":"%s","network":{"network_id":"test","genesis_root_hash":"sha256:root","genesis_file_hash":"sha256:file"},"registry_code_hash":"tvm-cell-sha256:code","services":{"native_connect":%q},"limits":{"max_request_bytes":1024,"max_response_bytes":2048},"expires_at_unix_seconds":%d}`, Schema, Protocol, origin, expiry)
}

func TestDecodeRejectsAuthorityExpiryAndAmbiguousJSON(t *testing.T) {
	now := time.Unix(1000, 0)
	if _, err := Decode([]byte(document("https://gateway.example", 2000)), expected(), now, false); err != nil {
		t.Fatal(err)
	}
	wrong := expected()
	wrong.NetworkID = "other"
	if _, err := Decode([]byte(document("https://gateway.example", 2000)), wrong, now, false); err == nil {
		t.Fatal("wrong authority accepted")
	}
	if _, err := Decode([]byte(document("https://gateway.example", 999)), expected(), now, false); err == nil {
		t.Fatal("expired document accepted")
	}
	duplicate := strings.Replace(document("https://gateway.example", 2000), `"schema":`, `"schema":"duplicate","schema":`, 1)
	if _, err := Decode([]byte(duplicate), expected(), now, false); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if _, err := Decode([]byte(document("http://gateway.example", 2000)), expected(), now, true); err == nil {
		t.Fatal("remote HTTP accepted")
	}
}

func TestFetchLoopbackWithoutRedirects(t *testing.T) {
	now := time.Unix(1000, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(document("http://127.0.0.1", 2000)))
	}))
	defer server.Close()
	if _, err := Fetch(context.Background(), FetchConfig{Origin: server.URL, Expected: expected(), AllowLoopbackHTTP: true, Now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	redirect := httptest.NewServer(http.RedirectHandler(server.URL, http.StatusFound))
	defer redirect.Close()
	if _, err := Fetch(context.Background(), FetchConfig{Origin: redirect.URL, Expected: expected(), AllowLoopbackHTTP: true, Now: func() time.Time { return now }}); err == nil {
		t.Fatal("redirect accepted")
	}
}
