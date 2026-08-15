// Package agentpacket defines an off-chain, chain-authenticated Agent packet.
// Payload bytes never become consensus input; finalized Agent state authorizes
// the signing key and the optional commercial binding.
package agentpacket

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"regexp"
	"sync"
	"time"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
)

const MaxPayloadBytes = 1 << 20

var (
	agentPattern  = regexp.MustCompile(`^agent_[0-9a-f]{64}$`)
	capPattern    = regexp.MustCompile(`^cap_[0-9a-f]{64}$`)
	digestPattern = regexp.MustCompile(`^(?:sha256|tvm-cell-sha256):[0-9a-f]{64}$`)
)

type Packet struct {
	SenderAgentID    string
	RecipientAgentID string
	CapabilityID     string
	QuoteCommitment  string
	Sequence         uint64
	Nonce            [32]byte
	Payload          []byte
	CreatedAtUnix    uint64
	SenderPublicKey  ed25519.PublicKey
	Signature        []byte
}

type AgentResolver interface {
	ResolveAgent(string) (*nativev1.AgentStateV1, bool, error)
}

type ReplayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time
	TTL  time.Duration
}

func (g *ReplayGuard) claim(key string, now time.Time) error {
	if g == nil || key == "" || now.IsZero() {
		return errors.New("invalid packet replay guard")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen == nil {
		g.seen = make(map[string]time.Time)
	}
	ttl := g.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	for item, at := range g.seen {
		if now.Sub(at) > ttl {
			delete(g.seen, item)
		}
	}
	if _, exists := g.seen[key]; exists {
		return errors.New("Agent packet replay detected")
	}
	g.seen[key] = now
	return nil
}

func Sign(packet Packet, privateKey ed25519.PrivateKey) (Packet, error) {
	packet.Signature = nil
	if len(privateKey) != ed25519.PrivateKeySize {
		return Packet{}, errors.New("invalid packet signing key")
	}
	packet.SenderPublicKey = append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	if err := validate(packet, false); err != nil {
		return Packet{}, err
	}
	packet.Signature = ed25519.Sign(privateKey, signingBytes(packet))
	return packet, nil
}

func Verify(resolver AgentResolver, guard *ReplayGuard, packet Packet, now time.Time) error {
	if resolver == nil || guard == nil || now.IsZero() {
		return errors.New("invalid packet verification context")
	}
	if err := validate(packet, true); err != nil {
		return err
	}
	state, found, err := resolver.ResolveAgent(packet.SenderAgentID)
	if err != nil {
		return err
	}
	if !found || state == nil || state.Tombstoned || state.Policy == nil {
		return errors.New("sender Agent is not finalized and live")
	}
	authorized := false
	for _, controller := range state.Policy.Controllers {
		if controller != nil && bytes.Equal(controller.Ed25519PublicKey, packet.SenderPublicKey) {
			authorized = true
			break
		}
	}
	if !authorized || !ed25519.Verify(packet.SenderPublicKey, signingBytes(packet), packet.Signature) {
		return errors.New("packet signer is not authorized")
	}
	if _, found, err := resolver.ResolveAgent(packet.RecipientAgentID); err != nil {
		return err
	} else if !found {
		return errors.New("recipient Agent is not finalized")
	}
	if err := guard.claim(packetKey(packet), now); err != nil {
		return err
	}
	return nil
}

func validate(packet Packet, signature bool) error {
	if !agentPattern.MatchString(packet.SenderAgentID) || !agentPattern.MatchString(packet.RecipientAgentID) ||
		packet.SenderAgentID == packet.RecipientAgentID || !capPattern.MatchString(packet.CapabilityID) ||
		(packet.QuoteCommitment != "" && !digestPattern.MatchString(packet.QuoteCommitment)) || packet.Sequence == 0 ||
		len(packet.Payload) == 0 || len(packet.Payload) > MaxPayloadBytes || packet.CreatedAtUnix == 0 ||
		len(packet.SenderPublicKey) != ed25519.PublicKeySize || (signature && len(packet.Signature) != ed25519.SignatureSize) {
		return errors.New("invalid Agent packet shape")
	}
	hash := sha256.Sum256(packet.Payload)
	if bytes.Equal(hash[:], make([]byte, 32)) {
		return errors.New("invalid Agent packet payload digest")
	}
	return nil
}

func signingBytes(packet Packet) []byte {
	payloadHash := sha256.Sum256(packet.Payload)
	buffer := bytes.NewBufferString("atos.agent.packet.v1\x00")
	putText := func(value string) {
		binary.Write(buffer, binary.BigEndian, uint32(len(value)))
		buffer.WriteString(value)
	}
	putText(packet.SenderAgentID)
	putText(packet.RecipientAgentID)
	putText(packet.CapabilityID)
	putText(packet.QuoteCommitment)
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], packet.Sequence)
	buffer.Write(number[:])
	buffer.Write(packet.Nonce[:])
	binary.BigEndian.PutUint64(number[:], packet.CreatedAtUnix)
	buffer.Write(number[:])
	buffer.Write(packet.SenderPublicKey)
	buffer.Write(payloadHash[:])
	return buffer.Bytes()
}

func packetKey(packet Packet) string {
	return packet.SenderAgentID + ":" + hex.EncodeToString(packet.Nonce[:])
}
