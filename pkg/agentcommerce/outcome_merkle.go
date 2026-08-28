package agentcommerce

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const MaxOutcomeCohortMembers = uint64(1<<32 - 1)

type OutcomeCohortMembershipProofV1 struct {
	Member         OutcomeAssertionRefV1 `json:"member"`
	LeafIndex      uint64                `json:"leaf_index"`
	LeafCount      uint64                `json:"leaf_count"`
	SiblingDigests []string              `json:"sibling_digests"`
}

// OutcomeAssertionSetRootV1 implements the released canonical cohort Merkle
// set. Callers cannot choose order, duplicate a member, or use the generic
// empty hash in place of the typed empty-set commitment.
func OutcomeAssertionSetRootV1(refs []OutcomeAssertionRefV1) (string, error) {
	type member struct {
		canonical []byte
		leaf      []byte
	}
	members := make([]member, len(refs))
	for index, ref := range refs {
		if !outcomeToken(ref.NetworkID, 256) || !outcomeToken(ref.ActorAgentID, 256) || !outcomeToken(ref.OperationID, 256) || !digest32(ref.OperationEnvelopeDigest) {
			return "", errors.New("cohort assertion reference is invalid")
		}
		canonical, err := codec.Marshal(ref)
		if err != nil {
			return "", err
		}
		message := append([]byte("tos.outcome.cohort.leaf.v1\x00"), canonical...)
		digest := sha256.Sum256(message)
		members[index] = member{canonical: canonical, leaf: append([]byte(nil), digest[:]...)}
	}
	sort.Slice(members, func(i, j int) bool { return bytes.Compare(members[i].canonical, members[j].canonical) < 0 })
	for index := 1; index < len(members); index++ {
		if bytes.Equal(members[index-1].canonical, members[index].canonical) {
			return "", errors.New("cohort assertion reference is duplicated")
		}
	}
	if len(members) == 0 {
		digest := sha256.Sum256([]byte("tos.outcome.cohort.empty.v1\x00"))
		return "sha256:" + hex.EncodeToString(digest[:]), nil
	}
	level := make([][]byte, len(members))
	for index := range members {
		level[index] = members[index].leaf
	}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for index := 0; index < len(level); index += 2 {
			if index+1 == len(level) {
				next = append(next, level[index])
				continue
			}
			message := append([]byte("tos.outcome.cohort.node.v1\x00"), level[index]...)
			message = append(message, level[index+1]...)
			digest := sha256.Sum256(message)
			next = append(next, append([]byte(nil), digest[:]...))
		}
		level = next
	}
	return "sha256:" + hex.EncodeToString(level[0]), nil
}

func BuildOutcomeCohortMembershipProofV1(refs []OutcomeAssertionRefV1,
	wanted OutcomeAssertionRefV1) (OutcomeCohortMembershipProofV1, string, error) {
	if len(refs) == 0 || uint64(len(refs)) > MaxOutcomeCohortMembers {
		return OutcomeCohortMembershipProofV1{}, "", errors.New("cohort membership set is invalid")
	}
	type member struct {
		ref       OutcomeAssertionRefV1
		canonical []byte
		hash      []byte
	}
	members := make([]member, len(refs))
	wantedCanonical, err := codec.Marshal(wanted)
	if err != nil {
		return OutcomeCohortMembershipProofV1{}, "", err
	}
	for index, ref := range refs {
		canonical, marshalErr := codec.Marshal(ref)
		if marshalErr != nil {
			return OutcomeCohortMembershipProofV1{}, "", marshalErr
		}
		digest := sha256.Sum256(append([]byte("tos.outcome.cohort.leaf.v1\x00"), canonical...))
		members[index] = member{ref: ref, canonical: canonical, hash: append([]byte(nil), digest[:]...)}
	}
	sort.Slice(members, func(i, j int) bool { return bytes.Compare(members[i].canonical, members[j].canonical) < 0 })
	wantedIndex := -1
	level := make([][]byte, len(members))
	for index := range members {
		if index > 0 && bytes.Equal(members[index-1].canonical, members[index].canonical) {
			return OutcomeCohortMembershipProofV1{}, "", errors.New("cohort assertion reference is duplicated")
		}
		if bytes.Equal(members[index].canonical, wantedCanonical) {
			wantedIndex = index
		}
		level[index] = members[index].hash
	}
	if wantedIndex < 0 {
		return OutcomeCohortMembershipProofV1{}, "", errors.New("cohort member is absent")
	}
	position := wantedIndex
	siblings := make([]string, 0, 32)
	for len(level) > 1 {
		if position%2 == 1 {
			siblings = append(siblings, "sha256:"+hex.EncodeToString(level[position-1]))
		} else if position+1 < len(level) {
			siblings = append(siblings, "sha256:"+hex.EncodeToString(level[position+1]))
		}
		next := make([][]byte, 0, (len(level)+1)/2)
		for index := 0; index < len(level); index += 2 {
			if index+1 == len(level) {
				next = append(next, level[index])
				continue
			}
			message := append([]byte("tos.outcome.cohort.node.v1\x00"), level[index]...)
			message = append(message, level[index+1]...)
			digest := sha256.Sum256(message)
			next = append(next, append([]byte(nil), digest[:]...))
		}
		position /= 2
		level = next
	}
	proof := OutcomeCohortMembershipProofV1{Member: wanted, LeafIndex: uint64(wantedIndex), LeafCount: uint64(len(members)),
		SiblingDigests: siblings}
	root := "sha256:" + hex.EncodeToString(level[0])
	if err := VerifyOutcomeCohortMembershipProofV1(proof, root); err != nil {
		return OutcomeCohortMembershipProofV1{}, "", err
	}
	return proof, root, nil
}

func VerifyOutcomeCohortMembershipProofV1(proof OutcomeCohortMembershipProofV1, expectedRoot string) error {
	if proof.LeafCount == 0 || proof.LeafCount > MaxOutcomeCohortMembers || proof.LeafIndex >= proof.LeafCount ||
		len(proof.SiblingDigests) > 32 || !digest32(expectedRoot) || !outcomeToken(proof.Member.NetworkID, 256) ||
		!outcomeToken(proof.Member.ActorAgentID, 256) || !outcomeToken(proof.Member.OperationID, 256) ||
		!digest32(proof.Member.OperationEnvelopeDigest) {
		return errors.New("cohort membership proof bounds are invalid")
	}
	canonical, err := codec.Marshal(proof.Member)
	if err != nil {
		return err
	}
	leaf := sha256.Sum256(append([]byte("tos.outcome.cohort.leaf.v1\x00"), canonical...))
	current := append([]byte(nil), leaf[:]...)
	position, width, siblingIndex := proof.LeafIndex, proof.LeafCount, 0
	for width > 1 {
		hasSibling := position%2 == 1 || position+1 < width
		if hasSibling {
			if siblingIndex >= len(proof.SiblingDigests) || !digest32(proof.SiblingDigests[siblingIndex]) {
				return errors.New("cohort membership proof is incomplete")
			}
			sibling, decodeErr := hex.DecodeString(proof.SiblingDigests[siblingIndex][len("sha256:"):])
			if decodeErr != nil || len(sibling) != sha256.Size {
				return errors.New("cohort membership sibling is invalid")
			}
			var message []byte
			if position%2 == 1 {
				message = append([]byte("tos.outcome.cohort.node.v1\x00"), sibling...)
				message = append(message, current...)
			} else {
				message = append([]byte("tos.outcome.cohort.node.v1\x00"), current...)
				message = append(message, sibling...)
			}
			digest := sha256.Sum256(message)
			current = append([]byte(nil), digest[:]...)
			siblingIndex++
		}
		position /= 2
		width = (width + 1) / 2
	}
	if siblingIndex != len(proof.SiblingDigests) || "sha256:"+hex.EncodeToString(current) != expectedRoot {
		return errors.New("cohort membership proof root mismatch")
	}
	return nil
}
