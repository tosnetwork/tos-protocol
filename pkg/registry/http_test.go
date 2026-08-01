package registry

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

func TestSearchRejectsTransportAmbiguity(t *testing.T) {
	index, err := NewIndex(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(index, "https://registry.example")
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string][3]string{
		"query":           {"/search?ignored=1", "application/json", ""},
		"encoding":        {"/search", "application/json", "gzip"},
		"media parameter": {"/search", "application/json; profile=unexpected", ""},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodPost, test[0],
				strings.NewReader(`{"query":{"text":"edge"}}`),
			)
			request.Header.Set("Content-Type", test[1])
			if test[2] != "" {
				request.Header.Set("Content-Encoding", test[2])
			}
			response := httptest.NewRecorder()
			handler.Routes().ServeHTTP(response, request)
			if response.Code < 400 {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestListRejectsUnknownAndDuplicateQueryParameters(t *testing.T) {
	index, err := NewIndex(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(index, "https://registry.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"/agents?unknown=1", "/agents?pageSize=1&pageSize=2",
	} {
		response := httptest.NewRecorder()
		handler.Routes().ServeHTTP(
			response, httptest.NewRequest(http.MethodGet, target, nil),
		)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("target=%q status=%d body=%s", target, response.Code, response.Body.String())
		}
	}
}

func TestHandlerRejectsExcessConcurrentRequestsWithoutQueuing(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxConcurrentRequests = 1
	index, err := NewIndex(limits)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(index, "https://registry.example")
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		handler.limit(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			close(entered)
			<-release
		})).ServeHTTP(
			httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil),
		)
	}()
	<-entered

	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(
		response, httptest.NewRequest(http.MethodGet, "/agents", nil),
	)
	if response.Code != http.StatusServiceUnavailable ||
		response.Header().Get("Retry-After") != "1" ||
		!strings.Contains(response.Body.String(), "RESOURCE_EXHAUSTED") {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	health := httptest.NewRecorder()
	handler.Routes().ServeHTTP(
		health, httptest.NewRequest(http.MethodGet, "/healthz", nil),
	)
	if health.Code != http.StatusOK {
		t.Fatalf("health status=%d body=%s", health.Code, health.Body.String())
	}
	close(release)
	wait.Wait()
}
