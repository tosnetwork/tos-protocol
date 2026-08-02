package registry

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/tosnetwork/tos-protocol/pkg/ard"
)

func testCatalog() ard.Catalog {
	return ard.Catalog{
		SpecVersion: ard.SpecVersion,
		Entries: []ard.Entry{
			{
				Identifier:            "urn:air:example.com:ai:vision",
				DisplayName:           "Factory Vision",
				Type:                  "application/vnd.tos.service+json",
				URL:                   "https://example.com/vision",
				Tags:                  []string{"edge", "vision"},
				Capabilities:          []string{"object-detection"},
				RepresentativeQueries: []string{"inspect a product", "detect a defect"},
			},
			{
				Identifier:            "urn:air:example.com:ai:ocr",
				DisplayName:           "Local OCR",
				Type:                  "application/vnd.tos.service+json",
				URL:                   "https://example.com/ocr",
				Tags:                  []string{"edge", "ocr"},
				Capabilities:          []string{"text-recognition"},
				RepresentativeQueries: []string{"read an invoice", "extract image text"},
			},
		},
	}
}

func TestIndexRejectsInvalidRequestConcurrencyLimit(t *testing.T) {
	for _, value := range []int{0, maximumConcurrentRequests + 1} {
		limits := DefaultLimits()
		limits.MaxConcurrentRequests = value
		if _, err := NewIndex(limits); err == nil {
			t.Fatalf("concurrent request limit %d was accepted", value)
		}
	}
}

func TestIndexRejectsInvalidByteLimits(t *testing.T) {
	for _, mutate := range []func(*Limits){
		func(limits *Limits) { limits.MaxIndexedEntryBytes = 0 },
		func(limits *Limits) { limits.MaxIndexBytes = 0 },
	} {
		limits := DefaultLimits()
		mutate(&limits)
		if _, err := NewIndex(limits); err == nil {
			t.Fatal("invalid Registry byte limit was accepted")
		}
	}
}

func TestIndexEnforcesEntryAndAggregateByteLimits(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxIndexedEntryBytes = 256
	index, err := NewIndex(limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := index.AddCatalog("file:///entry-limit.json", testCatalog()); err == nil {
		t.Fatal("oversized indexed entry was accepted")
	}

	limits = DefaultLimits()
	limits.MaxIndexBytes = 1
	index, err = NewIndex(limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := index.AddCatalog("file:///index-limit.json", testCatalog()); err == nil {
		t.Fatal("aggregate index byte overflow was accepted")
	}
}

func TestIndexSearchAndPagination(t *testing.T) {
	index, err := NewIndex(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := index.AddCatalog("https://example.com/.well-known/ai-catalog.json", testCatalog()); err != nil {
		t.Fatal(err)
	}
	response, err := index.Search(SearchRequest{
		Query:    QueryModel{Text: "edge", Filter: map[string]interface{}{"capabilities": "object-detection"}},
		PageSize: 1,
	}, "https://registry.example/search")
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Results) != 1 || response.Results[0].Identifier != "urn:air:example.com:ai:vision" {
		t.Fatalf("unexpected results: %#v", response.Results)
	}
}

func TestSearchResultRejectsAmbiguousMetadataAndExtensionCollisions(t *testing.T) {
	var result SearchResult
	if err := json.Unmarshal([]byte(`{
		"identifier":"urn:air:example.com:ai:vision",
		"displayName":"vision","type":"application/json",
		"score":1,"score":2,"source":"registry"
	}`), &result); err == nil {
		t.Fatal("duplicate Registry score accepted")
	}
	for _, key := range []string{"score", "source"} {
		result = SearchResult{Entry: testCatalog().Entries[0], Score: 1, Source: "registry"}
		result.Entry.Extensions = map[string]json.RawMessage{key: json.RawMessage(`"shadow"`)}
		if _, err := json.Marshal(result); err == nil {
			t.Fatalf("entry extension collision %q accepted", key)
		}
	}
}

func TestIndexSearchesValidatedWorkerCapabilityExtension(t *testing.T) {
	extension, err := json.Marshal(ard.WorkerCatalogExtension{
		Version: ard.WorkerCatalogExtensionVersion, TerminalRevision: "worker-v1",
		Capabilities: []ard.WorkerCatalogCapability{
			{
				ServiceID: "tos.ai.inference", Operation: "generate",
				Model: "qwen3-edge", ModelDigest: "sha256:" + strings.Repeat("a", 64),
				Runtime: "ollama", RuntimeRevision: "ollama-v1",
				MaxInputBytes: "1048576", MaxOutputBytes: "1048576",
			},
			{
				ServiceID: "tos.ai.embedding", Operation: "embed",
				Model: "bge-m3", ModelDigest: "sha256:" + strings.Repeat("b", 64),
				Runtime: "onnx", RuntimeRevision: "onnx-v1",
				MaxInputBytes: "524288", MaxOutputBytes: "524288",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	catalog := ard.Catalog{
		SpecVersion: ard.SpecVersion,
		Entries: []ard.Entry{{
			Identifier:   "urn:air:edge.example:tos:ai-terminal",
			DisplayName:  "Private AI Terminal",
			Type:         "application/vnd.tos.service+json",
			URL:          "https://edge.example/.well-known/tos-service.json",
			Capabilities: []string{"inference"},
			Extensions: map[string]json.RawMessage{
				ard.WorkerCatalogExtensionName: extension,
			},
		}},
	}
	index, err := NewIndex(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := index.AddCatalog("file:///catalog.json", catalog); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"qwen3-edge", "generate", "ollama", "tos.ai.inference", "bge-m3",
	} {
		response, err := index.Search(SearchRequest{
			Query: QueryModel{Text: query},
		}, "https://registry.example/search")
		if err != nil || len(response.Results) != 1 ||
			response.Results[0].Identifier != catalog.Entries[0].Identifier {
			t.Fatalf("query=%q response=%#v err=%v", query, response, err)
		}
	}

	response, err := index.Search(SearchRequest{
		Query: QueryModel{
			Text: "inference",
			Filter: map[string]interface{}{
				WorkerFilterServiceID:   "TOS.AI.INFERENCE",
				WorkerFilterOperation:   "GENERATE",
				WorkerFilterModel:       "QWEN3-EDGE",
				WorkerFilterModelDigest: "sha256:" + strings.Repeat("a", 64),
				WorkerFilterRuntime:     []string{"VLLM", "OLLAMA"},
			},
		},
	}, "https://registry.example/search")
	if err != nil || len(response.Results) != 1 {
		t.Fatalf("exact Worker filters response=%#v err=%v", response, err)
	}

	response, err = index.Search(SearchRequest{
		Query: QueryModel{
			Text: "inference",
			Filter: map[string]interface{}{
				WorkerFilterModel:     "qwen3-edge",
				WorkerFilterOperation: "embed",
			},
		},
	}, "https://registry.example/search")
	if err != nil || len(response.Results) != 0 {
		t.Fatalf("cross-capability filter matched response=%#v err=%v", response, err)
	}
}

func TestIndexRejectsUnsafeWorkerFilters(t *testing.T) {
	index, _ := NewIndex(DefaultLimits())
	for _, filter := range []map[string]interface{}{
		{"x-tos.unknown": "value"},
		{WorkerFilterModel: "qwen\x1foperation=embed"},
	} {
		if _, err := index.Search(SearchRequest{
			Query: QueryModel{Text: "inference", Filter: filter},
		}, "https://registry.example/search"); err == nil {
			t.Fatalf("unsafe Worker filter accepted: %#v", filter)
		}
	}
}

func TestIndexRejectsMalformedOrUnindexableWorkerExtension(t *testing.T) {
	catalog := testCatalog()
	catalog.Entries = catalog.Entries[:1]
	catalog.Entries[0].Type = "application/vnd.tos.service+json"
	catalog.Entries[0].Extensions = map[string]json.RawMessage{
		ard.WorkerCatalogExtensionName: []byte(`{"version":"0.1","unknown":true}`),
	}
	index, _ := NewIndex(DefaultLimits())
	if err := index.AddCatalog("file:///bad.json", catalog); err == nil {
		t.Fatal("Registry accepted a malformed known Worker extension")
	}

	extension, err := json.Marshal(ard.WorkerCatalogExtension{
		Version: ard.WorkerCatalogExtensionVersion, TerminalRevision: "worker-v1",
		Capabilities: []ard.WorkerCatalogCapability{{
			ServiceID: "tos.ai.inference", Operation: "generate",
			Model: "qwen3-edge", ModelDigest: "sha256:" + strings.Repeat("a", 64),
			Runtime: "ollama", RuntimeRevision: "ollama-v1",
			MaxInputBytes: "1", MaxOutputBytes: "1",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	catalog.Entries[0].Extensions[ard.WorkerCatalogExtensionName] = extension
	limits := DefaultLimits()
	limits.MaxWorkerSearchBytes = 8
	limited, _ := NewIndex(limits)
	if err := limited.AddCatalog("file:///large.json", catalog); err == nil {
		t.Fatal("Registry accepted Worker search text over its memory limit")
	}
}

func TestIndexIsBoundedAndRejectsIdentifierCollision(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxEntries = 2
	index, _ := NewIndex(limits)
	if err := index.AddCatalog("https://one.example/catalog", testCatalog()); err != nil {
		t.Fatal(err)
	}
	if err := index.AddCatalog("https://two.example/catalog", testCatalog()); err == nil {
		t.Fatal("cross-source identifier replacement accepted")
	}

	overflow := testCatalog()
	overflow.Entries = []ard.Entry{{
		Identifier:  "urn:air:other.example:ai:new",
		DisplayName: "new",
		Type:        "application/json",
		URL:         "https://other.example/new",
	}}
	if err := index.AddCatalog("https://other.example/catalog", overflow); err == nil {
		t.Fatal("capacity overflow accepted")
	}
}

func TestCatalogReplacementWithdrawsMissingEntries(t *testing.T) {
	index, _ := NewIndex(DefaultLimits())
	source := "https://example.com/catalog"
	if err := index.AddCatalog(source, testCatalog()); err != nil {
		t.Fatal(err)
	}
	replacement := testCatalog()
	replacement.Entries = replacement.Entries[:1]
	if err := index.AddCatalog(source, replacement); err != nil {
		t.Fatal(err)
	}
	list, err := index.List(20, "")
	if err != nil {
		t.Fatal(err)
	}
	if list.Total != 1 || list.Items[0].Identifier != replacement.Entries[0].Identifier {
		t.Fatalf("stale entries survived replacement: %#v", list)
	}
}

func TestReplaceCatalogsIsAtomicAndPreservesFailedGeneration(t *testing.T) {
	index, _ := NewIndex(DefaultLimits())
	if err := index.ReplaceCatalogs([]CatalogInput{{
		Source: "file:///initial.json", Catalog: testCatalog(),
	}}); err != nil {
		t.Fatal(err)
	}
	first, err := index.Search(SearchRequest{
		Query: QueryModel{Text: "edge"}, PageSize: 1,
	}, "https://registry.example/search")
	if err != nil || first.PageToken == "" {
		t.Fatalf("first page=%#v err=%v", first, err)
	}

	replacement := testCatalog()
	replacement.Entries = replacement.Entries[:1]
	bad := testCatalog()
	bad.SpecVersion = "unsupported"
	if err := index.ReplaceCatalogs([]CatalogInput{
		{Source: "file:///replacement.json", Catalog: replacement},
		{Source: "file:///bad.json", Catalog: bad},
	}); err == nil {
		t.Fatal("partial invalid catalog set was accepted")
	}
	second, err := index.Search(SearchRequest{
		Query: QueryModel{Text: "edge"}, PageSize: 1,
		PageToken: first.PageToken,
	}, "https://registry.example/search")
	if err != nil || len(second.Results) != 1 {
		t.Fatalf("failed reload changed generation/state: %#v err=%v", second, err)
	}

	if err := index.ReplaceCatalogs([]CatalogInput{{
		Source: "file:///replacement.json", Catalog: replacement,
	}}); err != nil {
		t.Fatal(err)
	}
	list, err := index.List(20, "")
	if err != nil || list.Total != 1 ||
		list.Items[0].Identifier != replacement.Entries[0].Identifier {
		t.Fatalf("atomic replacement=%#v err=%v", list, err)
	}
}

func TestReplaceCatalogsRejectsDuplicateSourcesAndIdentifiers(t *testing.T) {
	index, _ := NewIndex(DefaultLimits())
	for name, inputs := range map[string][]CatalogInput{
		"source": {
			{Source: "file:///same.json", Catalog: testCatalog()},
			{Source: "file:///same.json", Catalog: ard.Catalog{SpecVersion: ard.SpecVersion}},
		},
		"identifier": {
			{Source: "file:///one.json", Catalog: testCatalog()},
			{Source: "file:///two.json", Catalog: testCatalog()},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := index.ReplaceCatalogs(inputs); err == nil {
				t.Fatal("ambiguous catalog set was accepted")
			}
		})
	}
}

func TestReplaceCatalogsAndSearchAreConcurrentSafe(t *testing.T) {
	index, _ := NewIndex(DefaultLimits())
	input := []CatalogInput{{Source: "file:///catalog.json", Catalog: testCatalog()}}
	if err := index.ReplaceCatalogs(input); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		for iteration := 0; iteration < 100; iteration++ {
			if err := index.ReplaceCatalogs(input); err != nil {
				t.Errorf("reload %d: %v", iteration, err)
				return
			}
		}
	}()
	for iteration := 0; iteration < 100; iteration++ {
		response, err := index.Search(SearchRequest{
			Query: QueryModel{Text: "edge"},
		}, "https://registry.example/search")
		if err != nil || len(response.Results) != 2 {
			t.Fatalf("search %d=%#v err=%v", iteration, response, err)
		}
	}
	wait.Wait()
}

func TestEmptySearchEncodesResultsArray(t *testing.T) {
	index, _ := NewIndex(DefaultLimits())
	response, err := index.Search(SearchRequest{
		Query: QueryModel{Text: "nothing"},
	}, "https://registry.example/search")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"results":[]`) {
		t.Fatalf("empty results are not an array: %s", encoded)
	}
}

func TestPageTokenRejectsDuplicateFields(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"o":0,"o":1,"g":7}`))
	if _, err := decodePageToken(token, 7); err == nil {
		t.Fatal("ambiguous pageToken accepted")
	}
}
