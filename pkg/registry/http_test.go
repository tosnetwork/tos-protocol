package registry

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSearchRejectsDuplicateJSONKeys(t *testing.T) {
	index, err := NewIndex(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(index, "https://registry.example")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost, "/search",
		strings.NewReader(`{"query":{"text":"edge","text":"substituted"}}`),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestSearchRequiresExactJSONMediaType(t *testing.T) {
	index, err := NewIndex(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(index, "https://registry.example")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost, "/search",
		strings.NewReader(`{"query":{"text":"edge"}}`),
	)
	request.Header.Set("Content-Type", "application/jsonp")
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}
