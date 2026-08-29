package trustedcapability

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sort"
)

func ValidateUseBindingShape(binding CapabilityUseBindingV1, remote bool) error {
	allPromotion := binding.PromotionEnvelopeDigest != nil && binding.PromotionRevision != nil && binding.PromotionRevocationGeneration != nil
	noPromotion := binding.PromotionEnvelopeDigest == nil && binding.PromotionRevision == nil && binding.PromotionRevocationGeneration == nil
	if binding.PromotionRequired && !allPromotion || !binding.PromotionRequired && !noPromotion {
		return errors.New("promotion binding fields are inconsistent")
	}
	if remote != (binding.RemoteSessionHandshakeDigest != nil) {
		return errors.New("remote session binding is inconsistent")
	}
	digests := [][]byte{binding.AgreementDigest, binding.ObligationID, binding.ExecutionID, binding.ActionID, binding.ArtifactVersionDigest,
		binding.LoadedObjectDigest, binding.PermissionSubsetDigest, binding.AdmissionEnvelopeDigest, binding.PolicyDigest,
		binding.RuntimeAndSandboxDigest, binding.EffectiveEnvironmentDigest, binding.CredentialCapabilityReferenceSetDigest,
		binding.FilesystemHandleSetDigest, binding.NetworkBrokerPolicyDigest, binding.InvocationDescriptorDigest}
	for _, digest := range digests {
		if len(digest) != sha256.Size {
			return errors.New("capability use binding has malformed digest identity")
		}
	}
	if len(binding.OwnerID) == 0 || len(binding.AgentID) == 0 || binding.InstallationRevision == 0 || binding.AdmissionRevision == 0 ||
		binding.AdmissionRevocationGeneration == 0 || binding.AuthorityEpoch == 0 ||
		binding.ControlScopeGeneration == 0 || binding.InventoryRevision == 0 || binding.StartNotAfterUnix == 0 ||
		!bytes.Equal(binding.LoadedObjectDigest, binding.ArtifactVersionDigest) {
		return errors.New("capability use binding is incomplete")
	}
	if binding.RemoteSessionHandshakeDigest != nil && len(*binding.RemoteSessionHandshakeDigest) != sha256.Size {
		return errors.New("remote session handshake digest is malformed")
	}
	if allPromotion && (len(*binding.PromotionEnvelopeDigest) != sha256.Size || *binding.PromotionRevision == 0 || *binding.PromotionRevocationGeneration == 0) {
		return errors.New("promotion binding is incomplete")
	}
	return nil
}

func ValidateAdmission(body CapabilityAdmissionBodyV1, nowUnix uint64) error {
	if body.SchemaVersion != SchemaVersion || len(body.AdmissionID) != 16 || len(body.OwnerID) == 0 || len(body.AgentID) == 0 ||
		len(body.ArtifactVersionDigest) != sha256.Size || len(body.PermissionManifestDigest) != sha256.Size || len(body.PolicyDigest) != sha256.Size ||
		body.PolicyRevision == 0 || body.RevocationGeneration == 0 || body.NotBeforeUnix > nowUnix || nowUnix >= body.ExpiresAtUnix {
		return errors.New("capability admission is invalid or expired")
	}
	switch body.InFlightRevocationPolicy {
	case "kill-and-reconcile", "checkpoint-and-stop", "drain":
	default:
		return errors.New("unknown in-flight revocation policy")
	}
	return nil
}

func ValidateUseLease(lease CapabilityUseLeaseV1, nowUnix, minimumEpoch, minimumAdmissionGeneration, minimumPromotionGeneration uint64) error {
	if lease.SchemaVersion != SchemaVersion || len(lease.LeaseID) != sha256.Size || len(lease.OwnerID) == 0 || len(lease.AgentID) == 0 || len(lease.SinkID) == 0 ||
		len(lease.ExecutionID) != sha256.Size || len(lease.ActionID) != sha256.Size || len(lease.ArtifactVersionDigest) != sha256.Size ||
		len(lease.PermissionSubsetDigest) != sha256.Size || len(lease.AdmissionEnvelopeDigest) != sha256.Size || len(lease.PolicyDigest) != sha256.Size ||
		len(lease.InvocationDescriptorDigest) != sha256.Size ||
		lease.AuthorityEpoch < minimumEpoch || lease.PolicyRevision == 0 || lease.AdmissionRevision == 0 || lease.InstallationRevision == 0 ||
		lease.InventoryRevision == 0 || lease.ControlScopeGeneration == 0 || lease.AdmissionRevocationGeneration < minimumAdmissionGeneration || nowUnix < lease.NotBeforeUnix ||
		nowUnix >= lease.ExpiresAtUnix || lease.StartNotAfterUnix > lease.ExpiresAtUnix || nowUnix > lease.StartNotAfterUnix {
		return errors.New("capability use lease is stale, expired, or malformed")
	}
	if lease.PromotionEnvelopeDigest == nil && (lease.PromotionRevocationGeneration != nil || lease.PromotionRevision != nil) ||
		lease.PromotionEnvelopeDigest != nil && (lease.PromotionRevocationGeneration == nil || lease.PromotionRevision == nil || *lease.PromotionRevision == 0) {
		return errors.New("promotion lease fields are inconsistent")
	}
	if lease.PromotionRevocationGeneration != nil && *lease.PromotionRevocationGeneration < minimumPromotionGeneration {
		return errors.New("stale promotion revocation generation")
	}
	return nil
}

// ValidateLeaseBinding proves that the signed lease body and the execution
// binding describe exactly one authorization.  Callers must pass the lease
// decoded from the verified ProfileObject; an independently supplied struct is
// never authoritative.
func ValidateLeaseBinding(lease CapabilityUseLeaseV1, binding CapabilityUseBindingV1, sinkID []byte) error {
	if !bytes.Equal(lease.OwnerID, binding.OwnerID) || !bytes.Equal(lease.AgentID, binding.AgentID) ||
		!bytes.Equal(lease.SinkID, sinkID) || !bytes.Equal(lease.ExecutionID, binding.ExecutionID) ||
		!bytes.Equal(lease.ActionID, binding.ActionID) || !bytes.Equal(lease.ArtifactVersionDigest, binding.ArtifactVersionDigest) ||
		!bytes.Equal(lease.PermissionSubsetDigest, binding.PermissionSubsetDigest) ||
		!bytes.Equal(lease.AdmissionEnvelopeDigest, binding.AdmissionEnvelopeDigest) ||
		lease.AdmissionRevocationGeneration != binding.AdmissionRevocationGeneration ||
		lease.AdmissionRevision != binding.AdmissionRevision || lease.InstallationRevision != binding.InstallationRevision ||
		lease.InventoryRevision != binding.InventoryRevision || lease.ControlScopeGeneration != binding.ControlScopeGeneration ||
		lease.AuthorityEpoch != binding.AuthorityEpoch || lease.PolicyRevision != binding.PolicyRevision ||
		!bytes.Equal(lease.PolicyDigest, binding.PolicyDigest) || lease.StartNotAfterUnix != binding.StartNotAfterUnix ||
		!bytes.Equal(lease.InvocationDescriptorDigest, binding.InvocationDescriptorDigest) {
		return errors.New("signed lease does not match capability use binding")
	}
	if !equalOptionalBytes(lease.PromotionEnvelopeDigest, binding.PromotionEnvelopeDigest) ||
		!equalOptionalUint64(lease.PromotionRevision, binding.PromotionRevision) ||
		!equalOptionalUint64(lease.PromotionRevocationGeneration, binding.PromotionRevocationGeneration) {
		return errors.New("signed lease promotion scope does not match capability use binding")
	}
	return nil
}

func equalOptionalBytes(left, right *[]byte) bool {
	return left == nil && right == nil || left != nil && right != nil && bytes.Equal(*left, *right)
}

func equalOptionalUint64(left, right *uint64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func ValidateInventorySnapshot(snapshot CapabilityInventorySnapshotV1, nowUnix uint64) error {
	if len(snapshot.OwnerID) == 0 || len(snapshot.AgentID) == 0 || snapshot.SnapshotRevision == 0 || snapshot.SourceGeneration == 0 ||
		snapshot.PolicyRevision == 0 || len(snapshot.PolicyDigest) != sha256.Size || len(snapshot.ConsistencyToken) == 0 ||
		snapshot.CreatedAtUnix > nowUnix || nowUnix >= snapshot.ExpiresAtUnix {
		return errors.New("inventory snapshot is stale or incomplete")
	}
	if !sort.SliceIsSorted(snapshot.Entries, func(i, j int) bool {
		return bytes.Compare(snapshot.Entries[i].ArtifactVersionDigest, snapshot.Entries[j].ArtifactVersionDigest) < 0
	}) {
		return errors.New("inventory entries are not canonically ordered")
	}
	for i, entry := range snapshot.Entries {
		if len(entry.ArtifactVersionDigest) != sha256.Size || entry.AdmissionRevision == 0 || entry.RevocationGeneration == 0 {
			return errors.New("inventory entry is incomplete")
		}
		if i > 0 && bytes.Equal(entry.ArtifactVersionDigest, snapshot.Entries[i-1].ArtifactVersionDigest) {
			return errors.New("duplicate inventory entry")
		}
	}
	return nil
}
