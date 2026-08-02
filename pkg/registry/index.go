// Package registry implements a bounded ARD index with local atomic reload and
// an opt-in cached federation adapter. Query paths never perform network I/O.
package registry

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	"github.com/tosnetwork/tos-protocol/pkg/ard"
)

type Limits struct {
	MaxEntries            int
	MaxPerPublisher       int
	MaxIndexedEntryBytes  int
	MaxIndexBytes         int64
	MaxQueryBytes         int
	MaxPageSize           int
	MaxWorkerSearchBytes  int
	MaxConcurrentRequests int
}

func DefaultLimits() Limits {
	return Limits{
		MaxEntries:            10_000,
		MaxPerPublisher:       1_000,
		MaxIndexedEntryBytes:  64 << 10,
		MaxIndexBytes:         64 << 20,
		MaxQueryBytes:         2_048,
		MaxPageSize:           100,
		MaxWorkerSearchBytes:  16 << 10,
		MaxConcurrentRequests: 16,
	}
}

type record struct {
	entry         ard.Entry
	catalogSource string
	publisher     string
	workerSearch  string
	indexedBytes  int64
}

const (
	workerCapabilitySeparator byte = 0x1e
	workerFieldSeparator      byte = 0x1f
	maximumConcurrentRequests      = 1024

	// WorkerFilter* names are the exact TOS Worker extension filters accepted
	// in QueryModel.Filter.
	WorkerFilterServiceID   = "x-tos.serviceId"
	WorkerFilterOperation   = "x-tos.operation"
	WorkerFilterModel       = "x-tos.model"
	WorkerFilterModelDigest = "x-tos.modelDigest"
	WorkerFilterRuntime     = "x-tos.runtime"
)

type Index struct {
	mu         sync.RWMutex
	limits     Limits
	generation uint64
	records    map[string]record
}

// CatalogInput is one candidate source replacement in an atomic Registry
// catalog-set reload. ReplaceCatalogs validates every candidate.
type CatalogInput struct {
	Source  string
	Catalog ard.Catalog
}

func NewIndex(limits Limits) (*Index, error) {
	if limits.MaxEntries <= 0 || limits.MaxPerPublisher <= 0 ||
		limits.MaxIndexedEntryBytes <= 0 || limits.MaxIndexBytes <= 0 ||
		limits.MaxQueryBytes <= 0 || limits.MaxPageSize <= 0 ||
		limits.MaxWorkerSearchBytes <= 0 || limits.MaxConcurrentRequests <= 0 ||
		limits.MaxConcurrentRequests > maximumConcurrentRequests {
		return nil, errors.New("invalid Registry limits")
	}
	return &Index{limits: limits, records: make(map[string]record)}, nil
}

func (i *Index) AddCatalog(source string, catalog ard.Catalog) error {
	next, err := i.buildCatalogRecords(source, catalog)
	if err != nil {
		return err
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	projected := make(map[string]record, len(i.records)+len(next))
	for identifier, existing := range i.records {
		if existing.catalogSource != source {
			projected[identifier] = existing
		}
	}
	for _, candidate := range next {
		if existing, exists := projected[candidate.entry.Identifier]; exists &&
			existing.catalogSource != source {
			return fmt.Errorf("identifier %q already belongs to another catalog source", candidate.entry.Identifier)
		}
		projected[candidate.entry.Identifier] = candidate
	}
	if err := i.validateProjectedRecords(projected); err != nil {
		return err
	}
	i.records = projected
	i.generation++
	return nil
}

// ReplaceCatalogs validates and indexes a complete catalog set before one
// locked pointer replacement. A failed reload leaves the previous generation
// and all of its pagination tokens unchanged.
func (i *Index) ReplaceCatalogs(inputs []CatalogInput) error {
	projected := make(map[string]record)
	sources := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		if _, duplicate := sources[input.Source]; duplicate {
			return fmt.Errorf("duplicate catalog source %q", input.Source)
		}
		sources[input.Source] = struct{}{}
		records, err := i.buildCatalogRecords(input.Source, input.Catalog)
		if err != nil {
			return err
		}
		for _, candidate := range records {
			if existing, exists := projected[candidate.entry.Identifier]; exists {
				return fmt.Errorf(
					"identifier %q belongs to both %q and %q",
					candidate.entry.Identifier, existing.catalogSource,
					candidate.catalogSource,
				)
			}
			projected[candidate.entry.Identifier] = candidate
		}
	}
	if err := i.validateProjectedRecords(projected); err != nil {
		return err
	}
	i.mu.Lock()
	i.records = projected
	i.generation++
	i.mu.Unlock()
	return nil
}

func (i *Index) buildCatalogRecords(
	source string, catalog ard.Catalog,
) ([]record, error) {
	if source == "" {
		return nil, errors.New("Registry catalog source is required")
	}
	if err := catalog.Validate(ard.DefaultLimits()); err != nil {
		return nil, fmt.Errorf("validate Registry catalog %q: %w", source, err)
	}
	next := make([]record, 0, len(catalog.Entries))
	for _, entry := range catalog.Entries {
		publisher, err := ard.Publisher(entry.Identifier)
		if err != nil {
			return nil, err
		}
		workerSearch, err := workerExtensionSearchText(
			entry, i.limits.MaxWorkerSearchBytes,
		)
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", entry.Identifier, err)
		}
		encoded, err := json.Marshal(entry)
		if err != nil {
			return nil, fmt.Errorf("entry %q: encode indexed entry: %w", entry.Identifier, err)
		}
		indexedBytes := len(encoded) + len(workerSearch)
		if indexedBytes > i.limits.MaxIndexedEntryBytes {
			return nil, fmt.Errorf("entry %q exceeds indexed byte limit", entry.Identifier)
		}
		next = append(next, record{
			entry: cloneEntry(entry), catalogSource: source,
			publisher: publisher, workerSearch: workerSearch,
			indexedBytes: int64(indexedBytes),
		})
	}
	return next, nil
}

func (i *Index) validateProjectedRecords(projected map[string]record) error {
	if len(projected) > i.limits.MaxEntries {
		return errors.New("Registry index capacity exceeded")
	}
	publisherCounts := make(map[string]int)
	var indexedBytes int64
	for _, candidate := range projected {
		if candidate.indexedBytes <= 0 ||
			indexedBytes > i.limits.MaxIndexBytes-candidate.indexedBytes {
			return errors.New("Registry index byte capacity exceeded")
		}
		indexedBytes += candidate.indexedBytes
		publisherCounts[candidate.publisher]++
		if publisherCounts[candidate.publisher] > i.limits.MaxPerPublisher {
			return fmt.Errorf("publisher %q exceeds entry limit", candidate.publisher)
		}
	}
	return nil
}

type SearchRequest struct {
	Query      QueryModel `json:"query"`
	Federation string     `json:"federation,omitempty"`
	PageSize   int        `json:"pageSize,omitempty"`
	PageToken  string     `json:"pageToken,omitempty"`
}

type QueryModel struct {
	Text   string                 `json:"text"`
	Filter map[string]interface{} `json:"filter,omitempty"`
}

type SearchResult struct {
	ard.Entry
	Score  int    `json:"score"`
	Source string `json:"source"`
}

type SearchResponse struct {
	Results   []SearchResult `json:"results"`
	PageToken string         `json:"pageToken,omitempty"`
}

type ListResponse struct {
	Items     []ard.Entry `json:"items"`
	Total     int         `json:"total"`
	PageToken string      `json:"pageToken,omitempty"`
}

func (i *Index) Search(request SearchRequest, registrySource string) (SearchResponse, error) {
	if len(request.Query.Text) == 0 || len(request.Query.Text) > i.limits.MaxQueryBytes {
		return SearchResponse{}, errors.New("query.text is required and bounded")
	}
	if request.Federation != "" && request.Federation != "none" &&
		request.Federation != "cached" {
		return SearchResponse{}, errors.New("federation is not enabled by this Registry")
	}
	filters, err := compileFilters(request.Query.Filter)
	if err != nil {
		return SearchResponse{}, err
	}
	pageSize, err := i.pageSize(request.PageSize, 10)
	if err != nil {
		return SearchResponse{}, err
	}

	i.mu.RLock()
	generation := i.generation
	candidates := make([]record, 0, len(i.records))
	for _, item := range i.records {
		if matchesFilters(item, filters) {
			candidates = append(candidates, item)
		}
	}
	i.mu.RUnlock()

	tokens := tokenize(request.Query.Text)
	results := make([]SearchResult, 0, len(candidates))
	for _, candidate := range candidates {
		score := lexicalScore(tokens, candidate.entry, candidate.workerSearch)
		if score == 0 {
			continue
		}
		results = append(results, SearchResult{
			Entry:  candidate.entry,
			Score:  score,
			Source: registrySource,
		})
	}
	sort.Slice(results, func(a, b int) bool {
		if results[a].Score == results[b].Score {
			return results[a].Identifier < results[b].Identifier
		}
		return results[a].Score > results[b].Score
	})

	offset, err := decodePageToken(request.PageToken, generation)
	if err != nil {
		return SearchResponse{}, err
	}
	if offset > len(results) {
		return SearchResponse{}, errors.New("pageToken offset is invalid")
	}
	end := min(offset+pageSize, len(results))
	page := make([]SearchResult, end-offset)
	copy(page, results[offset:end])
	response := SearchResponse{Results: page}
	if end < len(results) {
		response.PageToken = encodePageToken(end, generation)
	}
	return response, nil
}

func (i *Index) List(pageSize int, pageToken string) (ListResponse, error) {
	size, err := i.pageSize(pageSize, 20)
	if err != nil {
		return ListResponse{}, err
	}
	i.mu.RLock()
	generation := i.generation
	items := make([]ard.Entry, 0, len(i.records))
	for _, item := range i.records {
		items = append(items, cloneEntry(item.entry))
	}
	i.mu.RUnlock()
	sort.Slice(items, func(a, b int) bool { return items[a].Identifier < items[b].Identifier })
	offset, err := decodePageToken(pageToken, generation)
	if err != nil {
		return ListResponse{}, err
	}
	if offset > len(items) {
		return ListResponse{}, errors.New("pageToken offset is invalid")
	}
	end := min(offset+size, len(items))
	response := ListResponse{Items: items[offset:end], Total: len(items)}
	if end < len(items) {
		response.PageToken = encodePageToken(end, generation)
	}
	return response, nil
}

func (i *Index) pageSize(requested, fallback int) (int, error) {
	if requested == 0 {
		return fallback, nil
	}
	if requested < 1 || requested > i.limits.MaxPageSize {
		return 0, fmt.Errorf("pageSize must be 1..%d", i.limits.MaxPageSize)
	}
	return requested, nil
}

type compiledFilter struct {
	key    string
	values []string
}

type compiledFilters struct {
	generic []compiledFilter
	worker  []compiledFilter
}

func matchesFilters(item record, filters compiledFilters) bool {
	for _, filter := range filters.generic {
		var have []string
		switch filter.key {
		case "type":
			have = []string{item.entry.Type}
		case "publisher":
			have = []string{item.publisher}
		case "version":
			have = []string{item.entry.Version}
		case "tags":
			have = item.entry.Tags
		case "capabilities":
			have = item.entry.Capabilities
		}
		if !intersects(have, filter.values) {
			return false
		}
	}
	return matchesWorkerFilters(item.workerSearch, filters.worker)
}

func compileFilters(filters map[string]interface{}) (compiledFilters, error) {
	compiled := compiledFilters{}
	keys := make([]string, 0, len(filters))
	for key := range filters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		raw := filters[key]
		tag, workerFilter := workerFilterTag(key)
		switch key {
		case "type", "publisher", "version", "tags", "capabilities":
		default:
			if !workerFilter {
				return compiledFilters{}, fmt.Errorf("unsupported filter %q", key)
			}
		}
		values := filterStrings(raw)
		if len(values) == 0 || len(values) > 64 {
			return compiledFilters{}, fmt.Errorf("filter %q must be a string or a bounded string array", key)
		}
		for _, value := range values {
			if len(value) == 0 || len(value) > 1024 {
				return compiledFilters{}, fmt.Errorf("filter %q contains an invalid value", key)
			}
			if workerFilter && strings.IndexFunc(value, unicode.IsControl) >= 0 {
				return compiledFilters{}, fmt.Errorf("filter %q contains an invalid value", key)
			}
		}
		if workerFilter {
			terms := make([]string, 0, len(values))
			for _, value := range values {
				terms = append(terms, workerFilterTerm(tag, value))
			}
			compiled.worker = append(compiled.worker, compiledFilter{
				key: key, values: terms,
			})
			continue
		}
		compiled.generic = append(compiled.generic, compiledFilter{
			key: key, values: values,
		})
	}
	return compiled, nil
}

func workerFilterTag(key string) (byte, bool) {
	switch key {
	case WorkerFilterServiceID:
		return 's', true
	case WorkerFilterOperation:
		return 'o', true
	case WorkerFilterModel:
		return 'm', true
	case WorkerFilterModelDigest:
		return 'd', true
	case WorkerFilterRuntime:
		return 'r', true
	default:
		return 0, false
	}
}

func matchesWorkerFilters(projection string, filters []compiledFilter) bool {
	if len(filters) == 0 {
		return true
	}
	for len(projection) != 0 {
		start := strings.IndexByte(projection, workerCapabilitySeparator)
		if start < 0 {
			return false
		}
		projection = projection[start+1:]
		end := strings.IndexByte(projection, workerCapabilitySeparator)
		capability := projection
		if end >= 0 {
			capability = projection[:end]
		}
		matched := true
		for _, filter := range filters {
			found := false
			for _, term := range filter.values {
				if strings.Contains(capability, term) {
					found = true
					break
				}
			}
			if !found {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
		if end < 0 {
			return false
		}
		projection = projection[end:]
	}
	return false
}

func workerFilterTerm(tag byte, value string) string {
	return string([]byte{workerFieldSeparator, tag, '='}) +
		strings.ToLower(value) + string(workerFieldSeparator)
}

func filterStrings(value interface{}) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []string:
		return append([]string(nil), typed...)
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, value := range typed {
			text, ok := value.(string)
			if !ok {
				return nil
			}
			out = append(out, text)
		}
		return out
	default:
		return nil
	}
}

func intersects(a, b []string) bool {
	for _, left := range a {
		for _, right := range b {
			if strings.EqualFold(left, right) {
				return true
			}
		}
	}
	return false
}

func lexicalScore(tokens []string, entry ard.Entry, workerSearch string) int {
	if len(tokens) == 0 {
		return 0
	}
	haystack := strings.ToLower(strings.Join(append(
		[]string{entry.DisplayName, entry.Description, entry.Identifier},
		append(append(entry.Tags, entry.Capabilities...), entry.RepresentativeQueries...)...,
	), " "))
	matched := 0
	for _, token := range tokens {
		if strings.Contains(haystack, token) || strings.Contains(workerSearch, token) {
			matched++
		}
	}
	if matched == 0 {
		return 0
	}
	return min(100, 1+(99*matched)/len(tokens))
}

func workerExtensionSearchText(entry ard.Entry, maxBytes int) (string, error) {
	extension, present, err := ard.DecodeWorkerCatalogExtension(entry)
	if err != nil || !present {
		return "", err
	}
	var builder strings.Builder
	for _, capability := range extension.Capabilities {
		builder.WriteByte(workerCapabilitySeparator)
		for _, field := range []struct {
			tag   byte
			value string
		}{
			{'s', capability.ServiceID}, {'o', capability.Operation},
			{'m', capability.Model}, {'d', capability.ModelDigest},
			{'r', capability.Runtime},
		} {
			value := strings.ToLower(field.value)
			additional := 3 + len(value) + 1
			if builder.Len()+additional > maxBytes {
				return "", errors.New("Worker capability search text exceeds limit")
			}
			builder.WriteByte(workerFieldSeparator)
			builder.WriteByte(field.tag)
			builder.WriteByte('=')
			builder.WriteString(value)
			builder.WriteByte(workerFieldSeparator)
		}
	}
	return builder.String(), nil
}

func tokenize(text string) []string {
	fields := strings.Fields(strings.ToLower(text))
	if len(fields) > 32 {
		fields = fields[:32]
	}
	return fields
}

type pageCursor struct {
	Offset     int    `json:"o"`
	Generation uint64 `json:"g"`
}

func encodePageToken(offset int, generation uint64) string {
	data, _ := json.Marshal(pageCursor{Offset: offset, Generation: generation})
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodePageToken(token string, generation uint64) (int, error) {
	if token == "" {
		return 0, nil
	}
	if len(token) > 128 {
		return 0, errors.New("pageToken is too large")
	}
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, errors.New("invalid pageToken")
	}
	var cursor pageCursor
	if err := jsonstrict.Decode(data, &cursor); err != nil || cursor.Offset < 0 {
		return 0, errors.New("invalid pageToken")
	}
	if cursor.Generation != generation {
		return 0, errors.New("pageToken is stale")
	}
	return cursor.Offset, nil
}

func cloneEntry(entry ard.Entry) ard.Entry {
	data, _ := json.Marshal(entry)
	var clone ard.Entry
	_ = json.Unmarshal(data, &clone)
	return clone
}

// ParsePageSize is used by the HTTP adapter and rejects surprising syntax.
func ParsePageSize(value string) (int, error) {
	if value == "" {
		return 0, nil
	}
	size, err := strconv.Atoi(value)
	if err != nil {
		return 0, errors.New("invalid pageSize")
	}
	return size, nil
}
