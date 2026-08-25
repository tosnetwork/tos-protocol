package agentcommerce

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	MaxIntentSummaryBytes       = 512
	MaxIntentKeywordBytes       = 96
	MaxIntentKeywords           = 32
	MaxIntentTaxonomyPaths      = 16
	MaxIntentCapabilityHints    = 16
	MaxIntentValueHints         = 16
	MaxIntentInlineDetailBytes  = 64 << 10
	MaxIntentContentBytes       = 64 << 20
	MaxIntentLifetime           = 90 * 24 * time.Hour
	MaxIntentClockSkew          = 5 * time.Minute
	MaxIntentReplyRoutes        = 8
	MaxIntentSettlementProfiles = 16
)

type IntentMode string

const (
	IntentRequest     IntentMode = "REQUEST"
	IntentOffer       IntentMode = "OFFER"
	IntentBuy         IntentMode = "BUY"
	IntentSell        IntentMode = "SELL"
	IntentExchange    IntentMode = "EXCHANGE"
	IntentCollaborate IntentMode = "COLLABORATE"
	IntentAnnounce    IntentMode = "ANNOUNCE"
)

type SubjectClass string

const (
	SubjectService        SubjectClass = "SERVICE"
	SubjectPhysicalGood   SubjectClass = "PHYSICAL_GOOD"
	SubjectDigitalGood    SubjectClass = "DIGITAL_GOOD"
	SubjectAsset          SubjectClass = "ASSET"
	SubjectData           SubjectClass = "DATA"
	SubjectContentMedia   SubjectClass = "CONTENT_MEDIA"
	SubjectCompute        SubjectClass = "COMPUTE"
	SubjectAccessCapacity SubjectClass = "ACCESS_OR_CAPACITY"
	SubjectFunding        SubjectClass = "FUNDING"
	SubjectCollaboration  SubjectClass = "COLLABORATION"
	SubjectOther          SubjectClass = "OTHER"
)

type ValueState string

const (
	ValueSpecified   ValueState = "specified"
	ValueRange       ValueState = "range"
	ValueNegotiable  ValueState = "negotiable"
	ValueNonMonetary ValueState = "non_monetary"
	ValueUnknown     ValueState = "unknown"
)

type IntentKeyword struct {
	Text     string `json:"text"`
	Language string `json:"language,omitempty"`
}

type CapabilityHint struct {
	Relation             string `json:"relation"`
	CapabilityNamespace  string `json:"capability_namespace"`
	CapabilityIdentifier string `json:"capability_identifier"`
	VersionConstraint    string `json:"version_constraint,omitempty"`
}

type ValueHint struct {
	Role            string `json:"role"`
	AssetNamespace  string `json:"asset_namespace"`
	AssetIdentifier string `json:"asset_identifier"`
	AssetDisplay    string `json:"asset_display,omitempty"`
	AmountKind      string `json:"amount_kind"`
	MinimumDecimal  string `json:"minimum_decimal,omitempty"`
	MaximumDecimal  string `json:"maximum_decimal,omitempty"`
	Unit            string `json:"unit"`
	TaxAndFeeNote   string `json:"tax_and_fee_note,omitempty"`
}

type IntentSchedule struct {
	EarliestStartUnix     uint64 `json:"earliest_start_unix,omitempty"`
	LatestStartUnix       uint64 `json:"latest_start_unix,omitempty"`
	DesiredCompletionUnix uint64 `json:"desired_completion_unix,omitempty"`
	MinimumDurationSecs   uint64 `json:"minimum_duration_seconds,omitempty"`
	MaximumDurationSecs   uint64 `json:"maximum_duration_seconds,omitempty"`
	TimeZone              string `json:"time_zone,omitempty"`
	Flexibility           string `json:"flexibility"`
}

type DiscoveryCard struct {
	Summary          string           `json:"summary"`
	IntentModes      []IntentMode     `json:"intent_modes"`
	SubjectClasses   []SubjectClass   `json:"subject_classes"`
	TaxonomyPaths    []string         `json:"taxonomy_paths,omitempty"`
	Keywords         []IntentKeyword  `json:"keywords"`
	CapabilityHints  []CapabilityHint `json:"capability_hints,omitempty"`
	ValueState       ValueState       `json:"value_state"`
	ValueHints       []ValueHint      `json:"value_hints,omitempty"`
	Schedule         IntentSchedule   `json:"schedule"`
	FulfillmentModes []string         `json:"fulfillment_modes,omitempty"`
	Regions          []string         `json:"regions,omitempty"`
	Languages        []string         `json:"languages,omitempty"`
}

type ContentDescriptor struct {
	ContentType    string   `json:"content_type"`
	ContentDigest  string   `json:"content_digest"`
	ContentSize    uint64   `json:"content_size"`
	InlineContent  []byte   `json:"inline_content,omitempty"`
	RetrievalHints []string `json:"retrieval_hints,omitempty"`
}

type ReplyRoute struct {
	ProfileURI string `json:"profile_uri"`
	AgentID    string `json:"agent_id"`
	Endpoint   string `json:"endpoint,omitempty"`
}

type SettlementPreference struct {
	AdapterURI string `json:"adapter_uri"`
	Required   bool   `json:"required"`
	// Parameters contains the exact public Adapter offer needed to compile an
	// Agreement (for example a destination or escrow profile commitment). It is
	// opaque to Intent discovery and interpreted only by the selected Adapter.
	Parameters []byte `json:"parameters,omitempty"`
}

type AgentIntentPayload struct {
	DiscoveryCard              DiscoveryCard          `json:"discovery_card"`
	DetailDescriptor           ContentDescriptor      `json:"detail_descriptor"`
	PublicAttachmentDescriptor *ContentDescriptor     `json:"public_attachment_manifest_descriptor,omitempty"`
	ReplyRoutes                []ReplyRoute           `json:"reply_routes"`
	SettlementPreferences      []SettlementPreference `json:"settlement_preferences,omitempty"`
	RequiredExtensions         []string               `json:"required_extensions,omitempty"`
	OptionalExtensions         map[string][]byte      `json:"optional_extensions,omitempty"`
}

type AgentIntentBody struct {
	SchemaVersion     uint16             `json:"schema_version"`
	NetworkID         string             `json:"network_id"`
	IssuerAgentID     string             `json:"issuer_agent_id"`
	Audience          string             `json:"audience"`
	ObjectID          string             `json:"object_id"`
	Revision          uint64             `json:"revision"`
	PredecessorDigest string             `json:"predecessor_digest,omitempty"`
	CreatedAtUnix     uint64             `json:"created_at_unix"`
	ExpiresAtUnix     uint64             `json:"expires_at_unix"`
	Payload           AgentIntentPayload `json:"payload"`
}

type SignedAgentIntent struct {
	Body      AgentIntentBody `json:"body"`
	PublicKey string          `json:"public_key"`
	Signature string          `json:"signature"`
}

// AgentIntentWithdrawal is an immutable issuer-signed operation that removes
// one exact published revision from live discovery without erasing its bytes.
// It is deliberately not a mutable "latest" row: Carriers retain both the
// Intent and this tombstone, and consumers can verify either independently.
type AgentIntentWithdrawalBody struct {
	SchemaVersion  uint16 `json:"schema_version"`
	NetworkID      string `json:"network_id"`
	IssuerAgentID  string `json:"issuer_agent_id"`
	Audience       string `json:"audience"`
	ObjectID       string `json:"object_id"`
	IntentRevision uint64 `json:"intent_revision"`
	IntentDigest   string `json:"intent_digest"`
	ReasonCode     string `json:"reason_code"`
	CreatedAtUnix  uint64 `json:"created_at_unix"`
	ExpiresAtUnix  uint64 `json:"expires_at_unix"`
}

type SignedAgentIntentWithdrawal struct {
	Body      AgentIntentWithdrawalBody `json:"body"`
	PublicKey string                    `json:"public_key"`
	Signature string                    `json:"signature"`
}

type IntentAuthorityResolver interface {
	AuthorizeIntentKey(agentID string, publicKey ed25519.PublicKey, at time.Time) error
}

func SignIntent(body AgentIntentBody, privateKey ed25519.PrivateKey) (SignedAgentIntent, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedAgentIntent{}, errors.New("intent signing key is invalid")
	}
	if err := ValidateIntentBody(body, time.Unix(int64(body.CreatedAtUnix), 0).UTC()); err != nil {
		return SignedAgentIntent{}, err
	}
	message, err := intentSignatureMessage(body)
	if err != nil {
		return SignedAgentIntent{}, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return SignedAgentIntent{
		Body:      body,
		PublicKey: "ed25519:" + hex.EncodeToString(publicKey),
		Signature: "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message)),
	}, nil
}

func SignIntentWithdrawal(body AgentIntentWithdrawalBody, privateKey ed25519.PrivateKey) (SignedAgentIntentWithdrawal, error) {
	if len(privateKey) != ed25519.PrivateKeySize || ValidateIntentWithdrawalBody(body, time.Unix(int64(body.CreatedAtUnix), 0).UTC()) != nil {
		return SignedAgentIntentWithdrawal{}, errors.New("Intent withdrawal signing request is invalid")
	}
	message, err := intentWithdrawalSignatureMessage(body)
	if err != nil {
		return SignedAgentIntentWithdrawal{}, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return SignedAgentIntentWithdrawal{Body: body, PublicKey: "ed25519:" + hex.EncodeToString(publicKey),
		Signature: "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))}, nil
}

func VerifyIntentWithdrawal(withdrawal SignedAgentIntentWithdrawal, resolver IntentAuthorityResolver, now time.Time) error {
	if err := ValidateIntentWithdrawalBody(withdrawal.Body, now); err != nil {
		return err
	}
	publicKey, err := parseEd25519PublicKey(withdrawal.PublicKey)
	if err != nil || resolver == nil || resolver.AuthorizeIntentKey(withdrawal.Body.IssuerAgentID, publicKey, now.UTC()) != nil {
		return errors.New("Intent withdrawal key is not authorized")
	}
	signature, err := parseEd25519Signature(withdrawal.Signature)
	message, messageErr := intentWithdrawalSignatureMessage(withdrawal.Body)
	if err != nil || messageErr != nil || !ed25519.Verify(publicKey, message, signature) {
		return errors.New("Intent withdrawal signature is invalid")
	}
	return nil
}

func ValidateIntentWithdrawalBody(body AgentIntentWithdrawalBody, now time.Time) error {
	if body.SchemaVersion != 1 || !boundedIdentifier(body.NetworkID, 128) || !boundedIdentifier(body.IssuerAgentID, 256) ||
		!boundedIdentifier(body.Audience, 128) || !boundedIdentifier(body.ObjectID, 256) || body.IntentRevision == 0 ||
		!canonicalDigestPattern.MatchString(body.IntentDigest) || !boundedIdentifier(body.ReasonCode, 128) ||
		body.CreatedAtUnix == 0 || body.ExpiresAtUnix <= body.CreatedAtUnix {
		return errors.New("Intent withdrawal body is invalid")
	}
	created := time.Unix(int64(body.CreatedAtUnix), 0).UTC()
	expires := time.Unix(int64(body.ExpiresAtUnix), 0).UTC()
	if expires.Sub(created) > 24*time.Hour || created.After(now.UTC().Add(MaxIntentClockSkew)) || !now.UTC().Before(expires) {
		return errors.New("Intent withdrawal time bounds are invalid")
	}
	return nil
}

func IntentWithdrawalDigest(body AgentIntentWithdrawalBody) (string, error) {
	return codec.Digest("tos.agent-intent-withdrawal-body.v1", body)
}

func intentWithdrawalSignatureMessage(body AgentIntentWithdrawalBody) ([]byte, error) {
	canonical, err := codec.Marshal(body)
	if err != nil {
		return nil, err
	}
	hasher := sha256.New()
	hasher.Write([]byte("tos.agent-intent-withdrawal-signature.v1\x00"))
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(canonical)))
	hasher.Write(length[:])
	hasher.Write(canonical)
	return hasher.Sum(nil), nil
}

func VerifyIntent(intent SignedAgentIntent, resolver IntentAuthorityResolver, now time.Time) error {
	return verifyIntent(intent, resolver, now, false)
}

// VerifyHistoricalIntent verifies retained predecessor bytes at their issuance
// time. Expiry removes an Intent from discovery, but cannot erase the signed
// revision history needed to authenticate a live successor. The observation
// time still prevents future-dated history from being accepted.
func VerifyHistoricalIntent(intent SignedAgentIntent, resolver IntentAuthorityResolver, observedAt time.Time) error {
	return verifyIntent(intent, resolver, observedAt, true)
}

func verifyIntent(intent SignedAgentIntent, resolver IntentAuthorityResolver, observedAt time.Time, historical bool) error {
	validationTime := observedAt.UTC()
	if historical {
		created := time.Unix(int64(intent.Body.CreatedAtUnix), 0).UTC()
		if created.After(validationTime.Add(MaxIntentClockSkew)) {
			return errors.New("historical intent was created in the future")
		}
		validationTime = created
	}
	if err := ValidateIntentBody(intent.Body, validationTime); err != nil {
		return err
	}
	publicKey, err := parseEd25519PublicKey(intent.PublicKey)
	if err != nil {
		return err
	}
	if resolver == nil {
		return errors.New("intent authority resolver is required")
	}
	authorityTime := observedAt.UTC()
	if historical {
		authorityTime = time.Unix(int64(intent.Body.CreatedAtUnix), 0).UTC()
	}
	if err := resolver.AuthorizeIntentKey(intent.Body.IssuerAgentID, publicKey, authorityTime); err != nil {
		return fmt.Errorf("intent key is not authorized: %w", err)
	}
	signature, err := parseEd25519Signature(intent.Signature)
	if err != nil {
		return err
	}
	message, err := intentSignatureMessage(intent.Body)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return errors.New("intent signature is invalid")
	}
	return nil
}

func IntentBodyDigest(body AgentIntentBody) (string, error) {
	return codec.Digest("tos.agent-intent-body.v1", body)
}

func intentSignatureMessage(body AgentIntentBody) ([]byte, error) {
	canonical, err := codec.Marshal(body)
	if err != nil {
		return nil, err
	}
	hasher := sha256.New()
	hasher.Write([]byte("tos.agent-intent-signature.v1\x00"))
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(canonical)))
	hasher.Write(length[:])
	hasher.Write(canonical)
	return hasher.Sum(nil), nil
}

func ValidateIntentBody(body AgentIntentBody, now time.Time) error {
	if body.SchemaVersion != 1 || !boundedIdentifier(body.NetworkID, 128) || !boundedIdentifier(body.IssuerAgentID, 256) ||
		!boundedIdentifier(body.Audience, 128) || !boundedIdentifier(body.ObjectID, 256) || body.Revision == 0 ||
		body.CreatedAtUnix == 0 || body.ExpiresAtUnix <= body.CreatedAtUnix {
		return errors.New("intent envelope is invalid")
	}
	created := time.Unix(int64(body.CreatedAtUnix), 0).UTC()
	expires := time.Unix(int64(body.ExpiresAtUnix), 0).UTC()
	if expires.Sub(created) > MaxIntentLifetime || created.After(now.UTC().Add(MaxIntentClockSkew)) || !now.UTC().Before(expires) {
		return errors.New("intent time bounds are invalid")
	}
	if body.Revision == 1 {
		if body.PredecessorDigest != "" {
			return errors.New("first intent revision has a predecessor")
		}
	} else if !canonicalDigestPattern.MatchString(body.PredecessorDigest) {
		return errors.New("intent successor has no canonical predecessor")
	}
	if err := validateDiscoveryCard(body.Payload.DiscoveryCard); err != nil {
		return err
	}
	if err := validateContentDescriptor(body.Payload.DetailDescriptor, true); err != nil {
		return err
	}
	if body.Payload.PublicAttachmentDescriptor != nil {
		if err := validateContentDescriptor(*body.Payload.PublicAttachmentDescriptor, false); err != nil {
			return err
		}
	}
	if len(body.Payload.ReplyRoutes) == 0 || len(body.Payload.ReplyRoutes) > MaxIntentReplyRoutes {
		return errors.New("intent reply routes are invalid")
	}
	for _, route := range body.Payload.ReplyRoutes {
		if !boundedIdentifier(route.ProfileURI, 256) || !boundedIdentifier(route.AgentID, 256) || len(route.Endpoint) > 2048 {
			return errors.New("intent reply route is invalid")
		}
	}
	if len(body.Payload.SettlementPreferences) > MaxIntentSettlementProfiles {
		return errors.New("too many settlement preferences")
	}
	for _, preference := range body.Payload.SettlementPreferences {
		if !boundedIdentifier(preference.AdapterURI, 256) || len(preference.Parameters) > 4096 {
			return errors.New("settlement preference is invalid")
		}
	}
	if err := validateSortedStrings(body.Payload.RequiredExtensions, 64, 256); err != nil {
		return fmt.Errorf("required extensions: %w", err)
	}
	if len(body.Payload.OptionalExtensions) > 64 {
		return errors.New("too many optional extensions")
	}
	for name, value := range body.Payload.OptionalExtensions {
		if !boundedIdentifier(name, 256) || len(value) > MaxIntentInlineDetailBytes {
			return errors.New("optional extension is invalid")
		}
	}
	return nil
}

func validateDiscoveryCard(card DiscoveryCard) error {
	if !boundedUTF8(card.Summary, 1, MaxIntentSummaryBytes) || len(card.IntentModes) == 0 || len(card.IntentModes) > 8 ||
		len(card.SubjectClasses) == 0 || len(card.SubjectClasses) > 8 || len(card.Keywords) == 0 || len(card.Keywords) > MaxIntentKeywords {
		return errors.New("intent discovery card is incomplete")
	}
	if !sortedUniqueIntentModes(card.IntentModes) || !sortedUniqueSubjectClasses(card.SubjectClasses) {
		return errors.New("intent modes and classes must be known, sorted, and unique")
	}
	if err := validateSortedStrings(card.TaxonomyPaths, MaxIntentTaxonomyPaths, 256); err != nil {
		return errors.New("intent taxonomy paths are invalid")
	}
	previousKeyword := ""
	for _, keyword := range card.Keywords {
		key := keyword.Language + "\x00" + keyword.Text
		if !boundedUTF8(keyword.Text, 1, MaxIntentKeywordBytes) || len(keyword.Language) > 35 || key <= previousKeyword {
			return errors.New("intent keywords must be bounded, sorted, and unique")
		}
		previousKeyword = key
	}
	if len(card.CapabilityHints) > MaxIntentCapabilityHints || len(card.ValueHints) > MaxIntentValueHints {
		return errors.New("intent discovery card exceeds hint bounds")
	}
	for _, hint := range card.CapabilityHints {
		if hint.Relation != "required" && hint.Relation != "preferred" && hint.Relation != "offered" {
			return errors.New("capability hint relation is invalid")
		}
		if !boundedIdentifier(hint.CapabilityNamespace, 128) || !boundedIdentifier(hint.CapabilityIdentifier, 256) || len(hint.VersionConstraint) > 128 {
			return errors.New("capability hint is invalid")
		}
	}
	switch card.ValueState {
	case ValueSpecified, ValueRange:
		if len(card.ValueHints) == 0 {
			return errors.New("specified value state has no value hints")
		}
	case ValueNegotiable, ValueNonMonetary, ValueUnknown:
	default:
		return errors.New("intent value state is invalid")
	}
	for _, hint := range card.ValueHints {
		if !boundedIdentifier(hint.Role, 64) || !boundedIdentifier(hint.AssetNamespace, 128) || !boundedIdentifier(hint.AssetIdentifier, 256) ||
			!boundedIdentifier(hint.AmountKind, 64) || !boundedIdentifier(hint.Unit, 128) || len(hint.AssetDisplay) > 128 || len(hint.TaxAndFeeNote) > 512 {
			return errors.New("intent value hint is invalid")
		}
		if hint.MinimumDecimal != "" && !canonicalDecimal(hint.MinimumDecimal) || hint.MaximumDecimal != "" && !canonicalDecimal(hint.MaximumDecimal) {
			return errors.New("intent value amount is not canonical decimal")
		}
	}
	if card.Schedule.Flexibility != "fixed" && card.Schedule.Flexibility != "flexible" && card.Schedule.Flexibility != "ongoing" && card.Schedule.Flexibility != "unknown" {
		return errors.New("intent schedule flexibility is invalid")
	}
	if card.Schedule.LatestStartUnix != 0 && card.Schedule.EarliestStartUnix > card.Schedule.LatestStartUnix ||
		card.Schedule.MaximumDurationSecs != 0 && card.Schedule.MinimumDurationSecs > card.Schedule.MaximumDurationSecs {
		return errors.New("intent schedule bounds are inverted")
	}
	for _, set := range [][]string{card.FulfillmentModes, card.Regions, card.Languages} {
		if err := validateSortedStrings(set, 32, 128); err != nil {
			return errors.New("intent discovery set is invalid")
		}
	}
	return nil
}

func validateContentDescriptor(descriptor ContentDescriptor, allowInline bool) error {
	if !boundedIdentifier(descriptor.ContentType, 128) || !canonicalDigestPattern.MatchString(descriptor.ContentDigest) ||
		descriptor.ContentSize == 0 || descriptor.ContentSize > MaxIntentContentBytes || len(descriptor.RetrievalHints) > 16 {
		return errors.New("intent content descriptor is invalid")
	}
	if len(descriptor.InlineContent) > 0 {
		if !allowInline || len(descriptor.InlineContent) > MaxIntentInlineDetailBytes || uint64(len(descriptor.InlineContent)) != descriptor.ContentSize {
			return errors.New("inline intent content violates bounds")
		}
		digest := sha256.Sum256(descriptor.InlineContent)
		if descriptor.ContentDigest != "sha256:"+hex.EncodeToString(digest[:]) {
			return errors.New("inline intent content digest mismatch")
		}
	}
	for _, hint := range descriptor.RetrievalHints {
		if !boundedUTF8(hint, 1, 2048) {
			return errors.New("intent retrieval hint is invalid")
		}
	}
	return nil
}

func sortedUniqueIntentModes(values []IntentMode) bool {
	previous := ""
	for _, value := range values {
		switch value {
		case IntentRequest, IntentOffer, IntentBuy, IntentSell, IntentExchange, IntentCollaborate, IntentAnnounce:
		default:
			return false
		}
		if string(value) <= previous {
			return false
		}
		previous = string(value)
	}
	return true
}

func sortedUniqueSubjectClasses(values []SubjectClass) bool {
	known := map[SubjectClass]bool{SubjectService: true, SubjectPhysicalGood: true, SubjectDigitalGood: true, SubjectAsset: true,
		SubjectData: true, SubjectContentMedia: true, SubjectCompute: true, SubjectAccessCapacity: true, SubjectFunding: true,
		SubjectCollaboration: true, SubjectOther: true}
	previous := ""
	for _, value := range values {
		if !known[value] || string(value) <= previous {
			return false
		}
		previous = string(value)
	}
	return true
}

func canonicalDecimal(value string) bool {
	if len(value) == 0 || len(value) > 96 || strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-") || strings.ContainsAny(value, "eE") {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) > 2 || !canonicalUnsignedDecimal(parts[0]) {
		return false
	}
	if len(parts) == 2 {
		if len(parts[1]) == 0 || strings.HasSuffix(parts[1], "0") {
			return false
		}
		for _, character := range parts[1] {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func validateSortedStrings(values []string, maximumItems, maximumBytes int) error {
	if len(values) > maximumItems {
		return errors.New("set has too many values")
	}
	for index, value := range values {
		if !boundedIdentifier(value, maximumBytes) || index > 0 && values[index-1] >= value {
			return errors.New("set values must be bounded, sorted, and unique")
		}
	}
	return nil
}

func boundedIdentifier(value string, maximum int) bool {
	return boundedUTF8(value, 1, maximum) && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func boundedUTF8(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && utf8.ValidString(value)
}

func parseEd25519PublicKey(value string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(value, "ed25519:") {
		return nil, errors.New("public key scheme is invalid")
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "ed25519:"))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("public key is invalid")
	}
	return ed25519.PublicKey(decoded), nil
}

func parseEd25519Signature(value string) ([]byte, error) {
	if !strings.HasPrefix(value, "ed25519:") {
		return nil, errors.New("signature scheme is invalid")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "ed25519:"))
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return nil, errors.New("signature is invalid")
	}
	return decoded, nil
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
