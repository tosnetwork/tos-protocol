package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientSearchAndListAgainstReferenceHandler(t *testing.T) {
	index, _ := NewIndex(DefaultLimits())
	if err := index.AddCatalog("file:///catalog.json", testCatalog()); err != nil {
		t.Fatal(err)
	}
	handler, _ := NewHandler(index, "https://registry.example/search")
	server := httptest.NewServer(handler.Routes())
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	search, err := client.Search(context.Background(), SearchRequest{Query: QueryModel{Text: "vision"}})
	if err != nil || len(search.Results) != 1 || search.Results[0].DisplayName != "Factory Vision" {
		t.Fatalf("search=%#v err=%v", search, err)
	}
	listed, err := client.List(context.Background(), ListRequest{
		Filter: "displayName = 'Local OCR'", OrderBy: "displayName DESC", PageSize: 1,
	})
	if err != nil || listed.Total != 1 || len(listed.Items) != 1 || listed.Items[0].DisplayName != "Local OCR" {
		t.Fatalf("list=%#v err=%v", listed, err)
	}
}

func TestClientRejectsUnsafeOriginAndMaliciousResponse(t *testing.T) {
	for _, endpoint := range []string{"http://example.com", "https://user@example.com", "https://example.com?target=other"} {
		if _, err := NewClient(endpoint, http.DefaultClient); err == nil {
			t.Fatalf("unsafe endpoint accepted: %q", endpoint)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"items":[],"items":[],"total":0}`))
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, server.Client())
	if _, err := client.List(context.Background(), ListRequest{}); err == nil {
		t.Fatal("duplicate-key response accepted")
	}

	large := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(strings.Repeat("x", MaxClientResponseBytes+1)))
	}))
	defer large.Close()
	client, _ = NewClient(large.URL, large.Client())
	if _, err := client.List(context.Background(), ListRequest{}); err == nil {
		t.Fatal("oversized response accepted")
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	destinationReached := false
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		destinationReached = true
	}))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	client, _ := NewClient(redirect.URL, redirect.Client())
	if _, err := client.List(context.Background(), ListRequest{}); err == nil || destinationReached {
		t.Fatal("Registry client followed a redirect")
	}
}

func TestClientRejectsListInputsBeforeTransport(t *testing.T) {
	called := false
	client, err := NewClient("https://registry.example", roundTripperClient(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []ListRequest{
		{PageSize: -1}, {PageSize: DefaultLimits().MaxPageSize + 1}, {PageToken: strings.Repeat("x", 4097)},
	} {
		if _, err := client.List(context.Background(), request); err == nil {
			t.Fatalf("invalid list request accepted: %#v", request)
		}
	}
	if called {
		t.Fatal("invalid list request reached transport")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func roundTripperClient(transport roundTripperFunc) *http.Client {
	return &http.Client{Transport: transport}
}
