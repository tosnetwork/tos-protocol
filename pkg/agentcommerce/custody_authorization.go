package agentcommerce

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"
)

// CustodyActionAuthorization is the small, language-neutral admission proof
// consumed by a custody boundary before it signs an Agreement-bound transfer.
// It deliberately does not give custody authority to interpret an Agreement:
// the Owner Economic Action Authority has already reduced the decision to one
// exact semantic action and one exact transfer request.
type CustodyActionAuthorization struct {
	SchemaVersion        uint16 `json:"schema_version"`
	AuthorityID          string `json:"authority_id"`
	OwnerID              string `json:"owner_id"`
	AgentID              string `json:"agent_id"`
	SourceAccount        string `json:"source_account"`
	NetworkID            string `json:"network_id"`
	NetworkGlobalID      int32  `json:"network_global_id"`
	StableActionID       string `json:"stable_action_id"`
	ExactRequestDigest   string `json:"exact_request_digest"`
	WriterGeneration     uint64 `json:"writer_generation"`
	WriterFenceDigest    string `json:"writer_fence_digest"`
	PolicyRevision       uint64 `json:"policy_revision"`
	MandateDigest        string `json:"mandate_digest"`
	ApprovalDigestOrZero string `json:"approval_digest_or_zero"`
	AgreementBodyDigest  string `json:"agreement_body_digest"`
	ObligationInstanceID string `json:"obligation_instance_id"`
	Destination          string `json:"destination"`
	AmountAtomic         uint64 `json:"amount_atomic"`
	ExpiresAtUnix        uint64 `json:"expires_at_unix"`
	PublicKey            string `json:"public_key"`
	Proof                string `json:"proof"`
}

// CustodyAuthorityResolver pins the Action Authority independently of the
// proof. Accepting a public key merely because it appears in the proof would
// turn the proof into a self-signed bearer token.
type CustodyAuthorityResolver interface {
	AuthorizeCustodyKey(authorityID, ownerID, agentID string, publicKey ed25519.PublicKey, at time.Time) error
}

func SignCustodyActionAuthorization(body CustodyActionAuthorization, privateKey ed25519.PrivateKey) (CustodyActionAuthorization, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return CustodyActionAuthorization{}, errors.New("custody authority signing key is invalid")
	}
	body.PublicKey, body.Proof = "", ""
	preimage, err := custodyAuthorizationPreimage(body)
	if err != nil {
		return CustodyActionAuthorization{}, err
	}
	digest := sha256.Sum256(preimage)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	body.PublicKey = "ed25519:" + hex.EncodeToString(publicKey)
	body.Proof = "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, digest[:]))
	return body, nil
}

func VerifyCustodyActionAuthorization(authorization CustodyActionAuthorization, resolver CustodyAuthorityResolver, now time.Time) error {
	if resolver == nil || now.Unix() < 0 || uint64(now.Unix()) >= authorization.ExpiresAtUnix {
		return errors.New("custody authorization is expired or has no authority resolver")
	}
	publicKey, err := parseEd25519PublicKey(authorization.PublicKey)
	if err != nil {
		return err
	}
	if err := resolver.AuthorizeCustodyKey(authorization.AuthorityID, authorization.OwnerID, authorization.AgentID, publicKey, now); err != nil {
		return err
	}
	proof, err := parseHexEd25519Signature(authorization.Proof)
	if err != nil {
		return err
	}
	body := authorization
	body.PublicKey, body.Proof = "", ""
	preimage, err := custodyAuthorizationPreimage(body)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(preimage)
	if !ed25519.Verify(publicKey, digest[:], proof) {
		return errors.New("custody authorization proof is invalid")
	}
	return nil
}

// CustodyActionAuthorizationPreimage exposes a defensive copy for released
// cross-language vectors. It is not a generic serialization format.
func CustodyActionAuthorizationPreimage(authorization CustodyActionAuthorization) ([]byte, error) {
	body := authorization
	body.PublicKey, body.Proof = "", ""
	return custodyAuthorizationPreimage(body)
}

func custodyAuthorizationPreimage(body CustodyActionAuthorization) ([]byte, error) {
	if body.SchemaVersion != 1 || !boundedIdentifier(body.AuthorityID, 256) || !boundedIdentifier(body.OwnerID, 256) ||
		!boundedIdentifier(body.AgentID, 256) || !boundedIdentifier(body.SourceAccount, 256) || !boundedIdentifier(body.NetworkID, 128) ||
		body.NetworkGlobalID == 0 || !canonicalDigestPattern.MatchString(body.StableActionID) ||
		!canonicalDigestPattern.MatchString(body.ExactRequestDigest) || body.WriterGeneration == 0 ||
		!canonicalDigestPattern.MatchString(body.WriterFenceDigest) || body.PolicyRevision == 0 ||
		!canonicalDigestPattern.MatchString(body.MandateDigest) || !canonicalDigestOrZero(body.ApprovalDigestOrZero) ||
		!canonicalDigestPattern.MatchString(body.AgreementBodyDigest) || !canonicalDigestPattern.MatchString(body.ObligationInstanceID) ||
		!boundedIdentifier(body.Destination, 256) || body.AmountAtomic == 0 || body.ExpiresAtUnix == 0 {
		return nil, errors.New("custody authorization body is invalid")
	}
	var output bytes.Buffer
	output.WriteString("TOS-EAA\x00")
	_ = binary.Write(&output, binary.BigEndian, body.SchemaVersion)
	for _, value := range []string{body.AuthorityID, body.OwnerID, body.AgentID, body.SourceAccount, body.NetworkID} {
		writeLP32String(&output, value)
	}
	_ = binary.Write(&output, binary.BigEndian, body.NetworkGlobalID)
	for _, value := range []string{body.StableActionID, body.ExactRequestDigest} {
		writeLP32String(&output, value)
	}
	_ = binary.Write(&output, binary.BigEndian, body.WriterGeneration)
	writeLP32String(&output, body.WriterFenceDigest)
	_ = binary.Write(&output, binary.BigEndian, body.PolicyRevision)
	for _, value := range []string{body.MandateDigest, body.ApprovalDigestOrZero, body.AgreementBodyDigest, body.ObligationInstanceID, body.Destination} {
		writeLP32String(&output, value)
	}
	_ = binary.Write(&output, binary.BigEndian, body.AmountAtomic)
	_ = binary.Write(&output, binary.BigEndian, body.ExpiresAtUnix)
	return output.Bytes(), nil
}

func writeLP32String(output *bytes.Buffer, value string) {
	_ = binary.Write(output, binary.BigEndian, uint32(len(value)))
	output.WriteString(value)
}

func parseHexEd25519Signature(value string) ([]byte, error) {
	const prefix = "ed25519:"
	if len(value) != len(prefix)+ed25519.SignatureSize*2 || value[:len(prefix)] != prefix {
		return nil, errors.New("Ed25519 proof is malformed")
	}
	decoded, err := hex.DecodeString(value[len(prefix):])
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return nil, errors.New("Ed25519 proof is malformed")
	}
	return decoded, nil
}
