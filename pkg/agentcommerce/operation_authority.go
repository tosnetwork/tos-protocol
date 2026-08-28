package agentcommerce

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	PinnedAgentOperationAuthorityProfileURI = "tos.identity.pinned-agent-operation-key.v1"
	PinnedAgentOperationAuthorityDomain     = "tos.identity.pinned-agent-operation-authority.v1"
)

// PinnedAgentOperationAuthorityProofV1 is a deployment trust-anchor proof.
// It is suitable for owner-configured keys and local/private streams. A
// deployment must retain superseded pins to verify historical operations.
// Decentralized identity or delegation systems implement the same resolver
// interface with their own historical proof profile.
type PinnedAgentOperationAuthorityProofV1 struct {
	SchemaVersion          uint16 `json:"schema_version"`
	ActorAgentID           string `json:"actor_agent_id"`
	PublicKey              string `json:"public_key"`
	ValidFromUnix          uint64 `json:"valid_from_unix"`
	ValidUntilUnix         uint64 `json:"valid_until_unix"`
	TrustConfigurationHash string `json:"trust_configuration_hash"`
}

type PinnedAgentOperationAuthorityRecordV1 struct {
	Profile ProfileRefV1
	Proof   []byte
	Key     ed25519.PublicKey
	Body    PinnedAgentOperationAuthorityProofV1
}

type PinnedAgentOperationAuthorityResolverV1 map[string][]PinnedAgentOperationAuthorityRecordV1

func NewPinnedAgentOperationAuthorityV1(actorAgentID string, key ed25519.PublicKey, validFrom, validUntil time.Time,
	trustConfigurationHash string) (PinnedAgentOperationAuthorityRecordV1, error) {
	if !operationToken(actorAgentID, 256) || len(key) != ed25519.PublicKeySize || validFrom.IsZero() || validUntil.IsZero() ||
		!validUntil.After(validFrom) || validFrom.Unix() <= 0 || !canonicalDigestPattern.MatchString(trustConfigurationHash) {
		return PinnedAgentOperationAuthorityRecordV1{}, errors.New("pinned Agent operation authority is invalid")
	}
	body := PinnedAgentOperationAuthorityProofV1{SchemaVersion: 1, ActorAgentID: actorAgentID,
		PublicKey: encodeEd25519Key(key), ValidFromUnix: uint64(validFrom.UTC().Unix()), ValidUntilUnix: uint64(validUntil.UTC().Unix()),
		TrustConfigurationHash: trustConfigurationHash}
	proof, err := codec.Marshal(body)
	if err != nil {
		return PinnedAgentOperationAuthorityRecordV1{}, err
	}
	digest, err := codec.Digest(PinnedAgentOperationAuthorityDomain, body)
	if err != nil {
		return PinnedAgentOperationAuthorityRecordV1{}, err
	}
	return PinnedAgentOperationAuthorityRecordV1{Profile: ProfileRefV1{ProfileURI: PinnedAgentOperationAuthorityProfileURI,
		ProfileVersion: 1, ProfileDigest: digest}, Proof: proof, Key: append(ed25519.PublicKey(nil), key...), Body: body}, nil
}

func (resolver PinnedAgentOperationAuthorityResolverV1) AuthorizeAgentOperationKey(actorAgentID string,
	profile ProfileRefV1, key ed25519.PublicKey, issuedAt time.Time, historicalProof []byte) error {
	if issuedAt.IsZero() || len(key) != ed25519.PublicKeySize || len(historicalProof) == 0 {
		return errors.New("pinned Agent operation authority request is invalid")
	}
	var proof PinnedAgentOperationAuthorityProofV1
	if codec.Unmarshal(historicalProof, &proof) != nil || proof.SchemaVersion != 1 || proof.ActorAgentID != actorAgentID ||
		proof.PublicKey != encodeEd25519Key(key) || proof.ValidFromUnix == 0 || proof.ValidUntilUnix <= proof.ValidFromUnix ||
		!canonicalDigestPattern.MatchString(proof.TrustConfigurationHash) || uint64(issuedAt.UTC().Unix()) < proof.ValidFromUnix ||
		uint64(issuedAt.UTC().Unix()) >= proof.ValidUntilUnix {
		return errors.New("pinned Agent operation authority proof is invalid")
	}
	digest, err := codec.Digest(PinnedAgentOperationAuthorityDomain, proof)
	if err != nil || profile != (ProfileRefV1{ProfileURI: PinnedAgentOperationAuthorityProfileURI,
		ProfileVersion: 1, ProfileDigest: digest}) {
		return errors.New("pinned Agent operation authority profile mismatch")
	}
	for _, record := range resolver[actorAgentID] {
		if record.Profile == profile && record.Key.Equal(key) && string(record.Proof) == string(historicalProof) {
			return nil
		}
	}
	return errors.New("pinned Agent operation authority is not trusted")
}

func encodeEd25519Key(key ed25519.PublicKey) string {
	return "ed25519:" + hex.EncodeToString(key)
}
