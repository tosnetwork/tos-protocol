package verifiedproof

import "testing"

func TestNewProtocolObserverRejectsRemotePlaintextAndURLUserinfo(t *testing.T) {
	for name, rawURL := range map[string]string{
		"remote plaintext": "http://authority.example/v1",
		"userinfo":         "https://attacker@authority.example/v1",
		"relative":         "/v1",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewProtocolObserver(rawURL, "secret"); err == nil {
				t.Fatalf("unsafe observer URL accepted: %s", rawURL)
			}
		})
	}
	for _, rawURL := range []string{"https://authority.example/v1", "http://127.0.0.1:8080", "http://[::1]:8080", "http://localhost:8080"} {
		if _, err := NewProtocolObserver(rawURL, "secret"); err != nil {
			t.Fatalf("safe observer URL rejected: %s: %v", rawURL, err)
		}
	}
}
