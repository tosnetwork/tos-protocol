package predictionmarket

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

var parserProfilePattern = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,47}/v[1-9][0-9]{0,8}$`)

type EvidenceEntryV1 struct {
	SourceKind             SourceKind
	CanonicalSourceID      string
	ContentDigest          Hash32
	ArchiveLocator         string
	PublicationTimeSeconds uint64
	EventTimeSeconds       uint64
	ParserProfileVersion   string
}

type PredictionEvidenceManifestV1 struct {
	MarketID         Hash32
	RulesHash        Hash32
	RoundContextHash Hash32
	Outcome          Outcome
	Entries          []EvidenceEntryV1
}

type PredictionChallengeEvidenceManifestV1 struct {
	MarketID              Hash32
	RulesHash             Hash32
	ProposedStatementHash Hash32
	CounterOutcome        Outcome
	Entries               []EvidenceEntryV1
}

func validateEvidenceEntry(value EvidenceEntryV1) error {
	if !value.SourceKind.valid() || value.ContentDigest.IsZero() {
		return errors.New("invalid evidence source kind or content digest")
	}
	if value.PublicationTimeSeconds == 0 || value.EventTimeSeconds == 0 || value.EventTimeSeconds > value.PublicationTimeSeconds {
		return errors.New("invalid authoritative evidence timestamps")
	}
	if !validSourceID(value.SourceKind, value.CanonicalSourceID) {
		return errors.New("invalid canonical evidence source id")
	}
	expectedLocator := "tos-cas-sha256:" + hex.EncodeToString(value.ContentDigest[:])
	if value.ArchiveLocator != expectedLocator || len(value.ArchiveLocator) > MaxArchiveLocatorBytes {
		return errors.New("archive locator must content-address the exact evidence digest")
	}
	if len(value.ParserProfileVersion) > MaxParserProfileBytes || !parserProfilePattern.MatchString(value.ParserProfileVersion) {
		return errors.New("invalid parser profile version")
	}
	return nil
}

func validSourceID(kind SourceKind, value string) bool {
	if len(value) == 0 || len(value) > MaxSourceIDBytes || !canonicalASCII(value) {
		return false
	}
	switch kind {
	case SourceHTTPS:
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
			return false
		}
		if parsed.Port() != "" || parsed.Hostname() != strings.ToLower(parsed.Hostname()) || strings.HasSuffix(parsed.Hostname(), ".") {
			return false
		}
		if parsed.Path != "" && (path.Clean(parsed.Path) != parsed.Path || strings.Contains(parsed.Path, "//")) {
			return false
		}
		return parsed.String() == value
	case SourceSignedDocument:
		if !strings.HasPrefix(value, "ed25519:") || len(value) != len("ed25519:")+64 {
			return false
		}
		keyHex := strings.TrimPrefix(value, "ed25519:")
		decoded, err := hex.DecodeString(keyHex)
		return err == nil && keyHex == strings.ToLower(keyHex) && ValidateTradingPublicKey(decoded) == nil
	case SourceTOSFinalized:
		if !strings.HasPrefix(value, "tos-account:") {
			return false
		}
		_, err := parseCanonicalAddress(strings.TrimPrefix(value, "tos-account:"))
		return err == nil
	default:
		return false
	}
}

func evidenceSortKey(value EvidenceEntryV1) []byte {
	result := make([]byte, 1+len(value.CanonicalSourceID)+1+len(value.ContentDigest))
	result[0] = byte(value.SourceKind)
	copy(result[1:], value.CanonicalSourceID)
	copy(result[2+len(value.CanonicalSourceID):], value.ContentDigest[:])
	return result
}

func canonicalEvidenceEntries(values []EvidenceEntryV1) ([]EvidenceEntryV1, error) {
	if len(values) == 0 || len(values) > MaxEvidenceEntries {
		return nil, errors.New("evidence manifest entry count is out of bounds")
	}
	result := append([]EvidenceEntryV1(nil), values...)
	for _, value := range result {
		if err := validateEvidenceEntry(value); err != nil {
			return nil, err
		}
	}
	sort.Slice(result, func(left, right int) bool {
		return bytes.Compare(evidenceSortKey(result[left]), evidenceSortKey(result[right])) < 0
	})
	for index := 1; index < len(result); index++ {
		if bytes.Equal(evidenceSortKey(result[index-1]), evidenceSortKey(result[index])) {
			return nil, errors.New("duplicate evidence source tuple")
		}
	}
	return result, nil
}

func buildEvidenceEntryCell(value EvidenceEntryV1) (*cell.Cell, error) {
	if err := validateEvidenceEntry(value); err != nil {
		return nil, err
	}
	source, err := textCell(value.CanonicalSourceID, MaxSourceIDBytes)
	if err != nil {
		return nil, err
	}
	locator, err := textCell(value.ArchiveLocator, MaxArchiveLocatorBytes)
	if err != nil {
		return nil, err
	}
	profile, err := textCell(value.ParserProfileVersion, MaxParserProfileBytes)
	if err != nil {
		return nil, err
	}
	meta := cell.BeginCell().MustStoreUInt(evidenceMetaMagic, 32).MustStoreUInt(uint64(SchemaVersion), 16).
		MustStoreSlice(value.ContentDigest[:], 256).MustStoreUInt(value.PublicationTimeSeconds, 64).
		MustStoreUInt(value.EventTimeSeconds, 64).EndCell()
	return cell.BeginCell().MustStoreUInt(evidenceEntryMagic, 32).MustStoreUInt(uint64(SchemaVersion), 16).
		MustStoreUInt(uint64(value.SourceKind), 8).MustStoreRef(source).MustStoreRef(locator).
		MustStoreRef(profile).MustStoreRef(meta).EndCell(), nil
}

func decodeEvidenceEntryCell(root *cell.Cell) (EvidenceEntryV1, error) {
	var result EvidenceEntryV1
	if err := ensureOrdinary(root); err != nil {
		return result, err
	}
	s, err := root.BeginParse()
	if err != nil {
		return result, errors.New("invalid evidence entry")
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != evidenceEntryMagic {
		return result, errors.New("invalid evidence entry magic")
	}
	version, err := s.LoadUInt(16)
	if err != nil || version != uint64(SchemaVersion) {
		return result, errors.New("unsupported evidence entry schema")
	}
	kind, err := s.LoadUInt(8)
	if err != nil {
		return result, errors.New("invalid evidence source kind")
	}
	sourceCell, err := s.LoadRefCell()
	if err != nil {
		return result, errors.New("missing evidence source id")
	}
	locatorCell, err := s.LoadRefCell()
	if err != nil {
		return result, errors.New("missing evidence archive locator")
	}
	profileCell, err := s.LoadRefCell()
	if err != nil {
		return result, errors.New("missing evidence parser profile")
	}
	metaCell, err := s.LoadRefCell()
	if err != nil || finish(s, "evidence entry") != nil {
		return result, errors.New("invalid evidence entry shape")
	}
	result.SourceKind = SourceKind(kind)
	result.CanonicalSourceID, err = decodeText(sourceCell, MaxSourceIDBytes)
	if err != nil {
		return result, err
	}
	result.ArchiveLocator, err = decodeText(locatorCell, MaxArchiveLocatorBytes)
	if err != nil {
		return result, err
	}
	result.ParserProfileVersion, err = decodeText(profileCell, MaxParserProfileBytes)
	if err != nil {
		return result, err
	}
	if err := ensureOrdinary(metaCell); err != nil {
		return result, err
	}
	meta, err := metaCell.BeginParse()
	if err != nil {
		return result, errors.New("invalid evidence metadata")
	}
	metaMagic, err := meta.LoadUInt(32)
	if err != nil || metaMagic != evidenceMetaMagic {
		return result, errors.New("invalid evidence metadata magic")
	}
	metaVersion, err := meta.LoadUInt(16)
	if err != nil || metaVersion != uint64(SchemaVersion) {
		return result, errors.New("unsupported evidence metadata schema")
	}
	result.ContentDigest, err = loadHash(meta, "evidence content digest")
	if err != nil {
		return result, err
	}
	result.PublicationTimeSeconds, err = meta.LoadUInt(64)
	if err != nil {
		return result, errors.New("invalid evidence publication time")
	}
	result.EventTimeSeconds, err = meta.LoadUInt(64)
	if err != nil || finish(meta, "evidence metadata") != nil {
		return result, errors.New("invalid evidence metadata shape")
	}
	if err := validateEvidenceEntry(result); err != nil {
		return result, err
	}
	return result, nil
}

// A deterministic balanced tree keeps 32-entry evidence manifests below the
// protocol depth limit. Count commitments prevent alternate tree shapes.
func buildEvidenceTree(values []EvidenceEntryV1) (*cell.Cell, error) {
	if len(values) == 1 {
		entry, err := buildEvidenceEntryCell(values[0])
		if err != nil {
			return nil, err
		}
		return cell.BeginCell().MustStoreUInt(evidenceListMagic, 32).MustStoreUInt(uint64(SchemaVersion), 16).
			MustStoreBoolBit(true).MustStoreUInt(1, 8).MustStoreRef(entry).EndCell(), nil
	}
	middle := len(values) / 2
	left, err := buildEvidenceTree(values[:middle])
	if err != nil {
		return nil, err
	}
	right, err := buildEvidenceTree(values[middle:])
	if err != nil {
		return nil, err
	}
	return cell.BeginCell().MustStoreUInt(evidenceListMagic, 32).MustStoreUInt(uint64(SchemaVersion), 16).
		MustStoreBoolBit(false).MustStoreUInt(uint64(len(values)), 8).
		MustStoreRef(left).MustStoreRef(right).EndCell(), nil
}

func decodeEvidenceTree(root *cell.Cell, expected int) ([]EvidenceEntryV1, error) {
	if expected <= 0 || expected > MaxEvidenceEntries {
		return nil, errors.New("invalid evidence tree count")
	}
	s, err := root.BeginParse()
	if err != nil {
		return nil, errors.New("invalid evidence tree")
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != evidenceListMagic {
		return nil, errors.New("invalid evidence tree magic")
	}
	version, err := s.LoadUInt(16)
	if err != nil || version != uint64(SchemaVersion) {
		return nil, errors.New("unsupported evidence tree schema")
	}
	leaf, err := s.LoadBoolBit()
	if err != nil {
		return nil, errors.New("invalid evidence tree tag")
	}
	count, err := s.LoadUInt(8)
	if err != nil || int(count) != expected {
		return nil, errors.New("evidence tree count mismatch")
	}
	if leaf {
		if expected != 1 {
			return nil, errors.New("invalid evidence leaf count")
		}
		entryCell, err := s.LoadRefCell()
		if err != nil || finish(s, "evidence leaf") != nil {
			return nil, errors.New("invalid evidence leaf shape")
		}
		entry, err := decodeEvidenceEntryCell(entryCell)
		if err != nil {
			return nil, err
		}
		return []EvidenceEntryV1{entry}, nil
	}
	if expected == 1 {
		return nil, errors.New("invalid evidence branch count")
	}
	leftCell, err := s.LoadRefCell()
	if err != nil {
		return nil, errors.New("missing evidence left branch")
	}
	rightCell, err := s.LoadRefCell()
	if err != nil || finish(s, "evidence branch") != nil {
		return nil, errors.New("invalid evidence branch shape")
	}
	middle := expected / 2
	left, err := decodeEvidenceTree(leftCell, middle)
	if err != nil {
		return nil, err
	}
	right, err := decodeEvidenceTree(rightCell, expected-middle)
	if err != nil {
		return nil, err
	}
	return append(left, right...), nil
}

func BuildPredictionEvidenceManifestCell(value PredictionEvidenceManifestV1) (*cell.Cell, error) {
	if value.MarketID.IsZero() || value.RulesHash.IsZero() || value.RoundContextHash.IsZero() || !value.Outcome.valid() {
		return nil, errors.New("invalid evidence manifest binding")
	}
	entries, err := canonicalEvidenceEntries(value.Entries)
	if err != nil {
		return nil, err
	}
	tree, err := buildEvidenceTree(entries)
	if err != nil {
		return nil, err
	}
	binding := cell.BeginCell().MustStoreSlice(value.MarketID[:], 256).MustStoreSlice(value.RulesHash[:], 256).
		MustStoreSlice(value.RoundContextHash[:], 256).EndCell()
	root := cell.BeginCell().MustStoreUInt(evidenceManifestMagic, 32).MustStoreUInt(uint64(SchemaVersion), 16).
		MustStoreUInt(uint64(value.Outcome), 8).MustStoreUInt(uint64(len(entries)), 8).
		MustStoreRef(binding).MustStoreRef(tree).EndCell()
	if err := ensureBoundedOrdinaryDAG(root, MaxCanonicalObjectCells, MaxCanonicalObjectDepth); err != nil {
		return nil, err
	}
	return root, nil
}

func DecodePredictionEvidenceManifestV1(root *cell.Cell) (*PredictionEvidenceManifestV1, error) {
	decoded, entries, err := decodeEvidenceManifestHeader(root, evidenceManifestMagic)
	if err != nil {
		return nil, err
	}
	result := &PredictionEvidenceManifestV1{MarketID: decoded[0], RulesHash: decoded[1], RoundContextHash: decoded[2], Outcome: Outcome(decoded[3][0]), Entries: entries}
	rebuilt, err := BuildPredictionEvidenceManifestCell(*result)
	if err != nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) {
		return nil, errors.New("evidence manifest is not canonical")
	}
	return result, nil
}

func BuildPredictionChallengeEvidenceManifestCell(value PredictionChallengeEvidenceManifestV1) (*cell.Cell, error) {
	if value.MarketID.IsZero() || value.RulesHash.IsZero() || value.ProposedStatementHash.IsZero() || !value.CounterOutcome.valid() {
		return nil, errors.New("invalid challenge evidence binding")
	}
	entries, err := canonicalEvidenceEntries(value.Entries)
	if err != nil {
		return nil, err
	}
	tree, err := buildEvidenceTree(entries)
	if err != nil {
		return nil, err
	}
	binding := cell.BeginCell().MustStoreSlice(value.MarketID[:], 256).MustStoreSlice(value.RulesHash[:], 256).
		MustStoreSlice(value.ProposedStatementHash[:], 256).EndCell()
	root := cell.BeginCell().MustStoreUInt(challengeManifestMagic, 32).MustStoreUInt(uint64(SchemaVersion), 16).
		MustStoreUInt(uint64(value.CounterOutcome), 8).MustStoreUInt(uint64(len(entries)), 8).
		MustStoreRef(binding).MustStoreRef(tree).EndCell()
	if err := ensureBoundedOrdinaryDAG(root, MaxCanonicalObjectCells, MaxCanonicalObjectDepth); err != nil {
		return nil, err
	}
	return root, nil
}

func DecodePredictionChallengeEvidenceManifestV1(root *cell.Cell) (*PredictionChallengeEvidenceManifestV1, error) {
	decoded, entries, err := decodeEvidenceManifestHeader(root, challengeManifestMagic)
	if err != nil {
		return nil, err
	}
	result := &PredictionChallengeEvidenceManifestV1{MarketID: decoded[0], RulesHash: decoded[1], ProposedStatementHash: decoded[2], CounterOutcome: Outcome(decoded[3][0]), Entries: entries}
	rebuilt, err := BuildPredictionChallengeEvidenceManifestCell(*result)
	if err != nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) {
		return nil, errors.New("challenge evidence manifest is not canonical")
	}
	return result, nil
}

func decodeEvidenceManifestHeader(root *cell.Cell, expectedMagic uint64) ([4]Hash32, []EvidenceEntryV1, error) {
	var decoded [4]Hash32
	if err := ensureBoundedOrdinaryDAG(root, MaxCanonicalObjectCells, MaxCanonicalObjectDepth); err != nil {
		return decoded, nil, err
	}
	s, err := root.BeginParse()
	if err != nil {
		return decoded, nil, errors.New("invalid evidence manifest")
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != expectedMagic {
		return decoded, nil, errors.New("invalid evidence manifest magic")
	}
	version, err := s.LoadUInt(16)
	if err != nil || version != uint64(SchemaVersion) {
		return decoded, nil, errors.New("unsupported evidence manifest schema")
	}
	outcome, err := s.LoadUInt(8)
	if err != nil || outcome > uint64(OutcomeInvalid) {
		return decoded, nil, errors.New("invalid evidence outcome")
	}
	decoded[3][0] = byte(outcome)
	count, err := s.LoadUInt(8)
	if err != nil || count == 0 || count > MaxEvidenceEntries {
		return decoded, nil, errors.New("invalid evidence entry count")
	}
	bindingCell, err := s.LoadRefCell()
	if err != nil {
		return decoded, nil, errors.New("missing evidence binding")
	}
	tree, err := s.LoadRefCell()
	if err != nil || finish(s, "evidence manifest") != nil {
		return decoded, nil, errors.New("invalid evidence manifest shape")
	}
	binding, err := bindingCell.BeginParse()
	if err != nil {
		return decoded, nil, errors.New("invalid evidence binding")
	}
	for index, name := range []string{"market id", "rules hash", "context or statement hash"} {
		decoded[index], err = loadHash(binding, name)
		if err != nil {
			return decoded, nil, err
		}
	}
	if err := finish(binding, "evidence binding"); err != nil {
		return decoded, nil, err
	}
	entries, err := decodeEvidenceTree(tree, int(count))
	if err != nil {
		return decoded, nil, err
	}
	canonical, err := canonicalEvidenceEntries(entries)
	if err != nil {
		return decoded, nil, err
	}
	for index := range entries {
		if !bytes.Equal(evidenceSortKey(entries[index]), evidenceSortKey(canonical[index])) {
			return decoded, nil, fmt.Errorf("evidence entries are not canonically sorted at index %d", index)
		}
	}
	return decoded, entries, nil
}
