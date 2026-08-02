package serve

import (
	"net/http"
	"strings"
	"testing"
)

func TestHTTPRejectsNilServerWithoutBackgroundPanic(t *testing.T) {
	if err := HTTP(nil); err == nil || err.Error() != "nil HTTP server" {
		t.Fatalf("nil server error=%v", err)
	}
}

func TestHTTPPropagatesListenFailure(t *testing.T) {
	server := &http.Server{Addr: "127.0.0.1:not-a-port"}
	if err := HTTP(server); err == nil ||
		!strings.Contains(err.Error(), "unknown port") {
		t.Fatalf("listen failure=%v", err)
	}
}
