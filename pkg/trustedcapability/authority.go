package trustedcapability

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const Ed25519ProofProfile = "tos.profile-proof.ed25519.v1"

// Ed25519KeyReference returns the stable, profile-separated identity of an
// Ed25519 verification key.  Raw public keys are evidence, not authority
// names: the signed issuer subject and every proof must bind this reference.
func Ed25519KeyReference(publicKey ed25519.PublicKey) []byte {
	hash := sha256.New()
	hash.Write([]byte("tos.profile-proof.ed25519.v1/key-reference"))
	hash.Write([]byte{0})
	hash.Write(publicKey)
	return hash.Sum(nil)
}

type TypedAuthoritySubjectV1 struct {
	Kind       string `cbor:"1,keyasint" json:"kind"`
	Namespace  string `cbor:"2,keyasint" json:"namespace"`
	Identifier []byte `cbor:"3,keyasint" json:"identifier"`
}

type ProfileAuthorizationProofV1 struct {
	Algorithm                         string  `cbor:"1,keyasint" json:"algorithm"`
	KeyReference                      []byte  `cbor:"2,keyasint" json:"key_reference"`
	PublicKey                         []byte  `cbor:"3,keyasint" json:"public_key"`
	Signature                         []byte  `cbor:"4,keyasint" json:"signature"`
	HistoricalAuthorityProofReference *[]byte `cbor:"5,keyasint" json:"historical_authority_proof_reference"`
	NotBeforeUnix                     uint64  `cbor:"6,keyasint" json:"not_before_unix"`
	ExpiresAtUnix                     uint64  `cbor:"7,keyasint" json:"expires_at_unix"`
}

type ProfileAuthorizationEnvelopeBodyV1 struct {
	SchemaVersion             uint16                  `cbor:"1,keyasint" json:"schema_version"`
	DomainKind                uint8                   `cbor:"2,keyasint" json:"domain_kind"`
	DomainID                  []byte                  `cbor:"3,keyasint" json:"domain_id"`
	BodyKind                  string                  `cbor:"4,keyasint" json:"body_kind"`
	BodyProfileURI            string                  `cbor:"5,keyasint" json:"body_profile_uri"`
	BodyProfileVersion        uint16                  `cbor:"6,keyasint" json:"body_profile_version"`
	BodyDigest                []byte                  `cbor:"7,keyasint" json:"body_digest"`
	OwnerID                   []byte                  `cbor:"8,keyasint" json:"owner_id"`
	AgentID                   *[]byte                 `cbor:"9,keyasint" json:"agent_id"`
	AuthorityKind             string                  `cbor:"10,keyasint" json:"authority_kind"`
	AuthorityID               []byte                  `cbor:"11,keyasint" json:"authority_id"`
	AuthorityRevision         uint64                  `cbor:"12,keyasint" json:"authority_revision"`
	AuthorityEpoch            uint64                  `cbor:"13,keyasint" json:"authority_epoch"`
	PolicyRevision            uint64                  `cbor:"14,keyasint" json:"policy_revision"`
	PolicyDigest              []byte                  `cbor:"15,keyasint" json:"policy_digest"`
	IssuerSubject             TypedAuthoritySubjectV1 `cbor:"16,keyasint" json:"issuer_subject"`
	ProofProfileURI           string                  `cbor:"17,keyasint" json:"proof_profile_uri"`
	ProofProfileVersion       uint16                  `cbor:"18,keyasint" json:"proof_profile_version"`
	NotBeforeUnix             uint64                  `cbor:"19,keyasint" json:"not_before_unix"`
	ExpiresAtUnix             uint64                  `cbor:"20,keyasint" json:"expires_at_unix"`
	PredecessorEnvelopeDigest *[]byte                 `cbor:"21,keyasint" json:"predecessor_envelope_digest"`
	ProofSetDigest            []byte                  `cbor:"22,keyasint" json:"proof_set_digest"`
	ExtensionsDigest          []byte                  `cbor:"23,keyasint" json:"extensions_digest"`
}

type ProfileAuthorizationEnvelopeV1 struct {
	Body   ProfileAuthorizationEnvelopeBodyV1 `cbor:"1,keyasint" json:"body"`
	Proofs []ProfileAuthorizationProofV1      `cbor:"2,keyasint" json:"proofs"`
}

type unsignedProof struct {
	Algorithm                         string  `cbor:"1,keyasint"`
	KeyReference                      []byte  `cbor:"2,keyasint"`
	PublicKey                         []byte  `cbor:"3,keyasint"`
	Signature                         any     `cbor:"4,keyasint"`
	HistoricalAuthorityProofReference *[]byte `cbor:"5,keyasint"`
	NotBeforeUnix                     uint64  `cbor:"6,keyasint"`
	ExpiresAtUnix                     uint64  `cbor:"7,keyasint"`
}

func ProofSetDigest(proofs []ProfileAuthorizationProofV1) ([]byte, error) {
	unsigned := make([]unsignedProof, len(proofs))
	for i, proof := range proofs {
		unsigned[i] = unsignedProof{proof.Algorithm, proof.KeyReference, proof.PublicKey, nil,
			proof.HistoricalAuthorityProofReference, proof.NotBeforeUnix, proof.ExpiresAtUnix}
	}
	canonical, err := MarshalBody(unsigned)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canonical)
	return digest[:], nil
}

func AuthorizationSignatureMessage(body ProfileAuthorizationEnvelopeBodyV1) ([]byte, error) {
	canonical, err := MarshalBody(body)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	hash.Write([]byte("tos.profile-authorization-envelope.v1/signature"))
	hash.Write([]byte{0})
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(canonical)))
	hash.Write(length[:])
	hash.Write(canonical)
	return hash.Sum(nil), nil
}

func SignAuthorization(body ProfileAuthorizationEnvelopeBodyV1, proofs []ProfileAuthorizationProofV1, keys []ed25519.PrivateKey) (ProfileAuthorizationEnvelopeV1, error) {
	if len(proofs) != 1 || len(keys) != 1 {
		return ProfileAuthorizationEnvelopeV1{}, errors.New("proof and key count mismatch")
	}
	for i := range proofs {
		if proofs[i].Algorithm != Ed25519ProofProfile || len(keys[i]) != ed25519.PrivateKeySize {
			return ProfileAuthorizationEnvelopeV1{}, errors.New("unsupported proof profile")
		}
		proofs[i].PublicKey = append([]byte(nil), keys[i].Public().(ed25519.PublicKey)...)
		wantReference := Ed25519KeyReference(proofs[i].PublicKey)
		if len(proofs[i].KeyReference) == 0 {
			proofs[i].KeyReference = wantReference
		} else if !bytes.Equal(proofs[i].KeyReference, wantReference) {
			return ProfileAuthorizationEnvelopeV1{}, errors.New("proof key reference does not match signing key")
		}
		proofs[i].Signature = nil
	}
	if !proofsSorted(proofs) {
		return ProfileAuthorizationEnvelopeV1{}, errors.New("proofs must be canonically sorted and unique")
	}
	digest, err := ProofSetDigest(proofs)
	if err != nil {
		return ProfileAuthorizationEnvelopeV1{}, err
	}
	body.ProofSetDigest = digest
	message, err := AuthorizationSignatureMessage(body)
	if err != nil {
		return ProfileAuthorizationEnvelopeV1{}, err
	}
	for i := range proofs {
		proofs[i].Signature = ed25519.Sign(keys[i], message)
	}
	return ProfileAuthorizationEnvelopeV1{Body: body, Proofs: proofs}, nil
}

func VerifyAuthorization(envelope ProfileAuthorizationEnvelopeV1, object ProfileObjectV1, nowUnix uint64, minimumEpoch uint64) error {
	if err := ValidateObject(object); err != nil {
		return err
	}
	digest, err := ObjectDigest(object)
	if err != nil {
		return err
	}
	body := envelope.Body
	if body.SchemaVersion != SchemaVersion || body.DomainKind != object.DomainKind || !bytes.Equal(body.DomainID, object.DomainID) ||
		body.BodyKind != object.ObjectKind || body.BodyProfileURI != object.ProfileURI || body.BodyProfileVersion != object.ProfileVersion ||
		!bytes.Equal(body.BodyDigest, digest) {
		return errors.New("authorization scope does not match object")
	}
	if body.AuthorityEpoch < minimumEpoch {
		return errors.New("stale authority epoch")
	}
	if nowUnix < body.NotBeforeUnix || nowUnix >= body.ExpiresAtUnix {
		return errors.New("authorization is outside validity interval")
	}
	if len(body.AuthorityID) != 16 || len(body.PolicyDigest) != sha256.Size {
		return errors.New("authorization identifiers are invalid")
	}
	if body.ProofProfileURI != Ed25519ProofProfile || body.ProofProfileVersion != 1 {
		return errors.New("unsupported proof profile")
	}
	// This released profile is deliberately a one-key profile. Threshold and
	// delegated authority require a different released proof profile whose
	// verifier resolves that policy; accepting extra valid signatures here
	// would otherwise silently invent threshold semantics.
	if len(envelope.Proofs) != 1 || !proofsSorted(envelope.Proofs) {
		return errors.New("proofs are empty, unsorted, or duplicated")
	}
	if body.IssuerSubject.Kind != "verification-key" || body.IssuerSubject.Namespace != Ed25519ProofProfile ||
		len(body.IssuerSubject.Identifier) != sha256.Size {
		return errors.New("issuer subject is incompatible with proof profile")
	}
	want, err := ProofSetDigest(envelope.Proofs)
	if err != nil || !bytes.Equal(want, body.ProofSetDigest) {
		return errors.New("proof set digest mismatch")
	}
	message, err := AuthorizationSignatureMessage(body)
	if err != nil {
		return err
	}
	for _, proof := range envelope.Proofs {
		if proof.Algorithm != Ed25519ProofProfile || len(proof.PublicKey) != ed25519.PublicKeySize || len(proof.Signature) != ed25519.SignatureSize ||
			len(proof.KeyReference) != sha256.Size || !bytes.Equal(proof.KeyReference, Ed25519KeyReference(proof.PublicKey)) ||
			!bytes.Equal(proof.KeyReference, body.IssuerSubject.Identifier) ||
			proof.HistoricalAuthorityProofReference != nil ||
			nowUnix < proof.NotBeforeUnix || nowUnix >= proof.ExpiresAtUnix || !ed25519.Verify(proof.PublicKey, message, proof.Signature) {
			return errors.New("authorization proof is invalid")
		}
	}
	return nil
}

func proofsSorted(proofs []ProfileAuthorizationProofV1) bool {
	var previous []byte
	for _, proof := range proofs {
		candidate := proof
		candidate.Signature = nil
		canonical, err := MarshalBody(candidate)
		if err != nil || previous != nil && bytes.Compare(previous, canonical) >= 0 {
			return false
		}
		previous = canonical
	}
	return true
}

func ValidateLinearSuccessor(previousDigest []byte, previousRevision, previousEpoch uint64, next ProfileAuthorizationEnvelopeBodyV1) error {
	if next.AuthorityEpoch < previousEpoch {
		return errors.New("stale authority epoch")
	}
	if next.AuthorityRevision != previousRevision+1 {
		return errors.New("authority revision is not contiguous")
	}
	if next.PredecessorEnvelopeDigest == nil || !bytes.Equal(*next.PredecessorEnvelopeDigest, previousDigest) {
		return fmt.Errorf("authority predecessor mismatch")
	}
	return nil
}
