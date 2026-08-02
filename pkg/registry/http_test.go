package registry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestListImplementsPinnedFilterOrderAndViewBoundPagination(t *testing.T) {
	index, err := NewIndex(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	catalog := testCatalog()
	catalog.Entries[0].UpdatedAt = "2026-08-02T10:00:00Z"
	catalog.Entries[1].UpdatedAt = "2026-08-01T10:00:00Z"
	if err := index.AddCatalog("file:///catalog.json", catalog); err != nil {
		t.Fatal(err)
	}
	handler, _ := NewHandler(index, "https://registry.example/search")
	target := "/agents?filter=" + url.QueryEscape("publisherId = 'example.com' AND updatedAfter > '2026-08-01T12:00:00Z'") +
		"&orderBy=" + url.QueryEscape("displayName DESC") + "&pageSize=1"
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var listed ListResponse
	if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if listed.Total != 1 || len(listed.Items) != 1 || listed.Items[0].DisplayName != "Factory Vision" {
		t.Fatalf("unexpected list response: %#v", listed)
	}

	first := httptest.NewRecorder()
	handler.Routes().ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/agents?pageSize=1", nil))
	if err := json.Unmarshal(first.Body.Bytes(), &listed); err != nil || listed.PageToken == "" {
		t.Fatalf("missing page token: %#v err=%v", listed, err)
	}
	mismatch := httptest.NewRecorder()
	handler.Routes().ServeHTTP(mismatch, httptest.NewRequest(
		http.MethodGet, "/agents?pageSize=1&orderBy=displayName&pageToken="+url.QueryEscape(listed.PageToken), nil,
	))
	if mismatch.Code != http.StatusBadRequest {
		t.Fatalf("mismatched token status=%d body=%s", mismatch.Code, mismatch.Body.String())
	}
}

func TestListRejectsUnsupportedOrAmbiguousGrammar(t *testing.T) {
	index, _ := NewIndex(DefaultLimits())
	handler, _ := NewHandler(index, "https://registry.example/search")
	for _, query := range []string{
		"filter=" + url.QueryEscape("createdAfter > '2026-01-01T00:00:00Z'"),
		"filter=" + url.QueryEscape("type = 'a' OR type = 'b'"),
		"filter=" + url.QueryEscape("metadata.owner = 'alice'"),
		"orderBy=" + url.QueryEscape("score DESC"),
		"orderBy=" + url.QueryEscape("displayName SIDEWAYS"),
	} {
		response := httptest.NewRecorder()
		handler.Routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/agents?"+query, nil))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("query=%q status=%d body=%s", query, response.Code, response.Body.String())
		}
	}
}

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

func TestHandlerRejectsUnsafePublicSource(t *testing.T) {
	index, _ := NewIndex(DefaultLimits())
	for _, source := range []string{
		"http://registry.example/search", "https://user@registry.example/search",
		"https://registry.example/search?shadow=1", "not-a-url",
	} {
		if _, err := NewHandler(index, source); err == nil {
			t.Fatalf("unsafe public source accepted: %q", source)
		}
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
