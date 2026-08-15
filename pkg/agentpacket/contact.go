package agentpacket

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
)

// ContactCard is a signed, non-canonical locator. It can be exchanged through
// any rendezvous mechanism; finalized Agent state remains the authority.
type ContactCard struct {
	AgentID       string
	Network       *nativev1.NetworkDomain
	Endpoint      string
	Capabilities  []string
	ExpiresAtUnix uint64
	PublicKey     ed25519.PublicKey
	Signature     []byte
}

func SignContact(card ContactCard, privateKey ed25519.PrivateKey) (ContactCard, error) {
	card.Signature = nil
	if len(privateKey) != ed25519.PrivateKeySize {
		return ContactCard{}, errors.New("invalid Contact Card signing key")
	}
	card.PublicKey = append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	if card.ExpiresAtUnix == 0 {
		return ContactCard{}, errors.New("invalid Contact Card expiry")
	}
	if err := validateContact(card, false, time.Unix(int64(card.ExpiresAtUnix-1), 0)); err != nil {
		return ContactCard{}, err
	}
	card.Signature = ed25519.Sign(privateKey, contactBytes(card))
	return card, nil
}

func VerifyContact(resolver AgentResolver, card ContactCard, now time.Time) error {
	if resolver == nil || now.IsZero() {
		return errors.New("invalid Contact Card verification context")
	}
	if err := validateContact(card, true, now); err != nil {
		return err
	}
	state, found, err := resolver.ResolveAgent(card.AgentID)
	if err != nil {
		return err
	}
	if !found || state == nil || state.Tombstoned || state.Policy == nil {
		return errors.New("Contact Card Agent is not finalized and live")
	}
	authorized := false
	for _, controller := range state.Policy.Controllers {
		if controller != nil && bytes.Equal(controller.Ed25519PublicKey, card.PublicKey) {
			authorized = true
			break
		}
	}
	if !authorized || !ed25519.Verify(card.PublicKey, contactBytes(card), card.Signature) {
		return errors.New("Contact Card signer is not authorized")
	}
	return nil
}

func validateContact(card ContactCard, signed bool, now time.Time) error {
	if !agentPattern.MatchString(card.AgentID) || card.Network == nil || strings.TrimSpace(card.Endpoint) != card.Endpoint ||
		card.ExpiresAtUnix == 0 || len(card.PublicKey) != ed25519.PublicKeySize || (signed && len(card.Signature) != ed25519.SignatureSize) {
		return errors.New("invalid Contact Card shape")
	}
	parsed, err := url.Parse(card.Endpoint)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host == "" ||
		(parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost" || parsed.Hostname() == "::1"))) {
		return errors.New("Contact Card endpoint must use HTTPS outside loopback")
	}
	if now.Unix() >= int64(card.ExpiresAtUnix) || card.ExpiresAtUnix > uint64(now.Add(24*time.Hour).Unix()) {
		return errors.New("Contact Card is expired or exceeds its lifetime")
	}
	seen := make(map[string]struct{}, len(card.Capabilities))
	for _, capability := range card.Capabilities {
		if !capPattern.MatchString(capability) {
			return errors.New("Contact Card contains invalid Capability")
		}
		if _, ok := seen[capability]; ok {
			return errors.New("Contact Card contains duplicate Capability")
		}
		seen[capability] = struct{}{}
	}
	return nil
}

func contactBytes(card ContactCard) []byte {
	buffer := bytes.NewBufferString("atos.agent.contact.v1\x00")
	text := func(value string) {
		binary.Write(buffer, binary.BigEndian, uint32(len(value)))
		buffer.WriteString(value)
	}
	text(card.AgentID)
	text(card.Network.NetworkId)
	text(card.Network.GenesisRootHash)
	text(card.Network.GenesisFileHash)
	text(card.Endpoint)
	binary.Write(buffer, binary.BigEndian, uint32(len(card.Capabilities)))
	for _, capability := range card.Capabilities {
		text(capability)
	}
	binary.Write(buffer, binary.BigEndian, card.ExpiresAtUnix)
	buffer.Write(card.PublicKey)
	return buffer.Bytes()
}

func ContactKey(card ContactCard) string {
	return card.AgentID + ":" + hex.EncodeToString(card.PublicKey)
}
