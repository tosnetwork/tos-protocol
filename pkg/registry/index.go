// Package registry implements a bounded ARD index. It is deliberately an
// operator-fed bootstrap backend; hardened crawling and federation are later
// adapters.
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

	"github.com/tosnetwork/tos-protocol/pkg/ard"
)

type Limits struct {
	MaxEntries      int
	MaxPerPublisher int
	MaxQueryBytes   int
	MaxPageSize     int
}

func DefaultLimits() Limits {
	return Limits{
		MaxEntries:      10_000,
		MaxPerPublisher: 1_000,
		MaxQueryBytes:   2_048,
		MaxPageSize:     100,
	}
}

type record struct {
	entry         ard.Entry
	catalogSource string
	publisher     string
}

type Index struct {
	mu         sync.RWMutex
	limits     Limits
	generation uint64
	records    map[string]record
}

func NewIndex(limits Limits) (*Index, error) {
	if limits.MaxEntries <= 0 || limits.MaxPerPublisher <= 0 ||
		limits.MaxQueryBytes <= 0 || limits.MaxPageSize <= 0 {
		return nil, errors.New("invalid Registry limits")
	}
	return &Index{limits: limits, records: make(map[string]record)}, nil
}

func (i *Index) AddCatalog(source string, catalog ard.Catalog) error {
	next := make([]record, 0, len(catalog.Entries))
	for _, entry := range catalog.Entries {
		publisher, err := ard.Publisher(entry.Identifier)
		if err != nil {
			return err
		}
		next = append(next, record{entry: cloneEntry(entry), catalogSource: source, publisher: publisher})
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
	if len(projected) > i.limits.MaxEntries {
		return errors.New("Registry index capacity exceeded")
	}
	publisherCounts := make(map[string]int)
	for _, candidate := range projected {
		publisherCounts[candidate.publisher]++
		if publisherCounts[candidate.publisher] > i.limits.MaxPerPublisher {
			return fmt.Errorf("publisher %q exceeds entry limit", candidate.publisher)
		}
	}
	i.records = projected
	i.generation++
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
	if request.Federation != "" && request.Federation != "none" {
		return SearchResponse{}, errors.New("federation is not enabled by this Registry")
	}
	if err := validateFilters(request.Query.Filter); err != nil {
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
		if matchesFilters(item, request.Query.Filter) {
			candidates = append(candidates, item)
		}
	}
	i.mu.RUnlock()

	tokens := tokenize(request.Query.Text)
	results := make([]SearchResult, 0, len(candidates))
	for _, candidate := range candidates {
		score := lexicalScore(tokens, candidate.entry)
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

func matchesFilters(item record, filters map[string]interface{}) bool {
	for key, raw := range filters {
		want := filterStrings(raw)
		if len(want) == 0 {
			return false
		}
		var have []string
		switch key {
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
		default:
			return false
		}
		if !intersects(have, want) {
			return false
		}
	}
	return true
}

func validateFilters(filters map[string]interface{}) error {
	for key, raw := range filters {
		switch key {
		case "type", "publisher", "version", "tags", "capabilities":
		default:
			return fmt.Errorf("unsupported filter %q", key)
		}
		values := filterStrings(raw)
		if len(values) == 0 || len(values) > 64 {
			return fmt.Errorf("filter %q must be a string or a bounded string array", key)
		}
		for _, value := range values {
			if len(value) == 0 || len(value) > 1024 {
				return fmt.Errorf("filter %q contains an invalid value", key)
			}
		}
	}
	return nil
}

func filterStrings(value interface{}) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
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

func lexicalScore(tokens []string, entry ard.Entry) int {
	if len(tokens) == 0 {
		return 0
	}
	haystack := strings.ToLower(strings.Join(append(
		[]string{entry.DisplayName, entry.Description, entry.Identifier},
		append(append(entry.Tags, entry.Capabilities...), entry.RepresentativeQueries...)...,
	), " "))
	matched := 0
	for _, token := range tokens {
		if strings.Contains(haystack, token) {
			matched++
		}
	}
	if matched == 0 {
		return 0
	}
	return min(100, 1+(99*matched)/len(tokens))
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
	if err := json.Unmarshal(data, &cursor); err != nil || cursor.Offset < 0 {
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
