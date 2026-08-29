package trustedcapability

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"net/url"
	"sort"
	"strings"
)

func ArtifactID(domainKind DomainKind, domainID []byte, publisher TypedAuthoritySubjectV1, kind, namespace, name string) ([]byte, error) {
	if domainKind != DomainTOSNetwork && domainKind != DomainOwnerLocal || len(domainID) == 0 || kind == "" || namespace == "" || name == "" {
		return nil, errors.New("artifact identity is incomplete")
	}
	canonicalPublisher, err := MarshalBody(publisher)
	if err != nil {
		return nil, err
	}
	return framedDigest("tos.capability-artifact-id.v1", []byte{byte(domainKind)}, domainID, canonicalPublisher, []byte(kind), []byte(namespace), []byte(name)), nil
}

func ArtifactPreManifestDigest(body ExecutableCapabilityArtifactBodyV1) ([]byte, error) {
	body.PermissionManifestDigest = nil
	body.DependencyManifestDigest = nil
	canonical, err := MarshalBody(body)
	if err != nil {
		return nil, err
	}
	return framedDigest("tos.capability-artifact-pre-manifest.v1", canonical), nil
}

func ValidateExecutableArtifact(body ExecutableCapabilityArtifactBodyV1) error {
	if body.SchemaVersion != SchemaVersion || body.ArtifactKind == "" || body.ArtifactNamespace == "" || body.ArtifactName == "" || body.ArtifactVersion == "" ||
		body.PublisherSubject.Kind == "" || body.PublisherSubject.Namespace == "" || len(body.PublisherSubject.Identifier) == 0 ||
		len(body.PublisherAuthorityProfile) != sha256.Size || len(body.SourceDescriptorDigest) != sha256.Size ||
		len(body.ContentManifestDigest) != sha256.Size || len(body.EntrypointDescriptorDigest) != sha256.Size ||
		len(body.LicenseManifestDigest) != sha256.Size || len(body.StandardsProfileSetDigest) != sha256.Size ||
		len(body.CompatibilityManifestDigest) != sha256.Size || len(body.SupplyChainEvidenceDigest) != sha256.Size || body.CreatedAtUnix == 0 {
		return errors.New("executable capability artifact is incomplete")
	}
	if body.PermissionManifestDigest != nil && len(*body.PermissionManifestDigest) != sha256.Size ||
		body.DependencyManifestDigest != nil && len(*body.DependencyManifestDigest) != sha256.Size ||
		body.OptionalServiceCapabilityID != nil && len(*body.OptionalServiceCapabilityID) != sha256.Size {
		return errors.New("executable capability artifact has malformed optional digest")
	}
	switch body.ArtifactKind {
	case "builtin", "skill", "mcp-local", "mcp-remote", "model-adapter", "tool-bundle", "local-adapter":
	default:
		return errors.New("unsupported executable capability artifact kind")
	}
	return nil
}

func ValidateContentManifest(manifest CapabilityContentManifestV1) error {
	if manifest.SchemaVersion != SchemaVersion || len(manifest.ClosureRoot) != sha256.Size || len(manifest.Entries) > MaxCollectionItems {
		return errors.New("content manifest is incomplete")
	}
	previous := ""
	for index, entry := range manifest.Entries {
		if entry.Path == "" || entry.Path == "." || strings.HasPrefix(entry.Path, "/") || strings.Contains(entry.Path, "\\") ||
			strings.Contains("/"+entry.Path+"/", "/../") || index > 0 && previous >= entry.Path ||
			(entry.ObjectType != "directory" && entry.ObjectType != "regular") || entry.Mode&^uint32(0o755) != 0 ||
			entry.ObjectType == "regular" && len(entry.ContentDigest) != sha256.Size || entry.ObjectType == "directory" && (entry.Size != 0 || entry.ContentDigest != nil) {
			return errors.New("content manifest entry is unsafe or not canonically sorted")
		}
		previous = entry.Path
	}
	want, err := ContentClosureRoot(manifest.Entries)
	if err != nil {
		return err
	}
	if !bytes.Equal(want, manifest.ClosureRoot) {
		return errors.New("content manifest closure root mismatch")
	}
	return nil
}

func ContentClosureRoot(entries []ContentManifestEntryV1) ([]byte, error) {
	canonical, err := MarshalBody(entries)
	if err != nil {
		return nil, err
	}
	return framedDigest("tos.capability-content-closure.v1", canonical), nil
}

func ValidateEntrypointDescriptor(descriptor CapabilityEntrypointDescriptorV1) error {
	if descriptor.SchemaVersion != SchemaVersion || len(descriptor.ExecutableObjectDigest) != sha256.Size ||
		len(descriptor.WorkingDirectoryPolicyDigest) != sha256.Size || len(descriptor.RuntimeSubjectDigest) != sha256.Size ||
		len(descriptor.EnvironmentNameSetDigest) != sha256.Size || len(descriptor.EnvironmentValueSourceDigest) != sha256.Size ||
		len(descriptor.FilesystemRootSetDigest) != sha256.Size || len(descriptor.ProcessModelDigest) != sha256.Size ||
		len(descriptor.SandboxProfileDigest) != sha256.Size ||
		descriptor.RemoteServiceDescriptorDigest != nil && len(*descriptor.RemoteServiceDescriptorDigest) != sha256.Size {
		return errors.New("entrypoint descriptor is incomplete")
	}
	for _, argument := range descriptor.Arguments {
		if strings.ContainsRune(argument, 0) {
			return errors.New("entrypoint argument contains NUL")
		}
	}
	return nil
}

func ValidateDependencyManifest(manifest DependencyManifestV1, preManifestDigest []byte) error {
	if manifest.SchemaVersion != SchemaVersion || !bytes.Equal(manifest.ArtifactPreManifestDigest, preManifestDigest) ||
		len(manifest.ResolverArtifactDigest) != sha256.Size || len(manifest.BuildToolchainDigest) != sha256.Size ||
		len(manifest.PlatformAndFeaturePredicateDigest) != sha256.Size || len(manifest.ClosureRootDigest) != sha256.Size ||
		len(manifest.Nodes) > MaxCollectionItems || len(manifest.Edges) > MaxCollectionItems {
		return errors.New("dependency manifest is incomplete")
	}
	seen := make(map[string]struct{}, len(manifest.Nodes))
	var previous []byte
	for _, node := range manifest.Nodes {
		if len(node.NodeID) != sha256.Size || previous != nil && bytes.Compare(previous, node.NodeID) >= 0 ||
			ValidateReference(node.ImmutableArtifactReference) != nil || ValidateReference(node.PublisherEnvelopeReference) != nil ||
			ValidateReference(node.SourceSnapshotReference) != nil || len(node.BuildInputDigest) != sha256.Size ||
			len(node.BuildOutputDigest) != sha256.Size || len(node.InstallAndBuildHookDigest) != sha256.Size ||
			len(node.EffectivePermissionContributionDigest) != sha256.Size {
			return errors.New("dependency node is invalid or not sorted")
		}
		seen[string(node.NodeID)] = struct{}{}
		previous = node.NodeID
	}
	previous = nil
	for _, edge := range manifest.Edges {
		encoded, err := MarshalBody(edge)
		if err != nil || previous != nil && bytes.Compare(previous, encoded) >= 0 {
			return errors.New("dependency edges are not sorted and unique")
		}
		if _, ok := seen[string(edge.FromNodeID)]; !ok {
			return errors.New("dependency edge source is unknown")
		}
		if _, ok := seen[string(edge.ToNodeID)]; !ok || edge.DependencyKind == "" {
			return errors.New("dependency edge target or kind is invalid")
		}
		previous = encoded
	}
	canonical, err := MarshalBody(struct {
		Nodes []DependencyNodeV1 `cbor:"1,keyasint"`
		Edges []DependencyEdgeV1 `cbor:"2,keyasint"`
	}{manifest.Nodes, manifest.Edges})
	if err != nil || !bytes.Equal(framedDigest("tos.capability-dependency-closure.v1", canonical), manifest.ClosureRootDigest) {
		return errors.New("dependency closure root mismatch")
	}
	return nil
}

func ValidatePublisherEnvelope(body ArtifactPublisherEnvelopeBodyV1, artifact ExecutableCapabilityArtifactBodyV1, now uint64) error {
	pre, err := ArtifactPreManifestDigest(artifact)
	if err != nil {
		return err
	}
	if body.SchemaVersion != SchemaVersion || !bytes.Equal(body.ArtifactPreManifestDigest, pre) || body.ArtifactKind != artifact.ArtifactKind ||
		body.ArtifactNamespace != artifact.ArtifactNamespace || body.ArtifactName != artifact.ArtifactName || body.ArtifactVersion != artifact.ArtifactVersion ||
		!equalAuthoritySubject(body.PublisherSubject, artifact.PublisherSubject) || !equalOptionalDigest(body.PermissionManifestDigest, artifact.PermissionManifestDigest) ||
		!equalOptionalDigest(body.DependencyManifestDigest, artifact.DependencyManifestDigest) || !bytes.Equal(body.ContentManifestDigest, artifact.ContentManifestDigest) ||
		!bytes.Equal(body.EntrypointDescriptorDigest, artifact.EntrypointDescriptorDigest) || body.CreatedAtUnix != artifact.CreatedAtUnix ||
		now < body.NotBeforeUnix || now >= body.ExpiresAtUnix || body.RevocationGeneration == 0 {
		return errors.New("publisher envelope does not bind the artifact or is stale")
	}
	return nil
}

func equalAuthoritySubject(left, right TypedAuthoritySubjectV1) bool {
	return left.Kind == right.Kind && left.Namespace == right.Namespace && bytes.Equal(left.Identifier, right.Identifier)
}

func equalOptionalDigest(left, right *[]byte) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return bytes.Equal(*left, *right)
}

func framedDigest(domain string, fields ...[]byte) []byte {
	hash := sha256.New()
	hash.Write([]byte(domain))
	hash.Write([]byte{0})
	var length [4]byte
	for _, field := range fields {
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		hash.Write(length[:])
		hash.Write(field)
	}
	return hash.Sum(nil)
}

func ValidatePermissionManifest(manifest CapabilityPermissionManifestV1) error {
	if manifest.SchemaVersion != SchemaVersion || len(manifest.ArtifactPreManifestDigest) != sha256.Size || manifest.ConcurrencyCeiling == 0 {
		return errors.New("permission manifest is incomplete")
	}
	cost, canonicalCost := new(big.Int).SetString(manifest.DirectCostCeiling, 10)
	if !canonicalCost || cost.Sign() < 0 || cost.String() != manifest.DirectCostCeiling {
		return errors.New("direct cost ceiling is not canonical atomic units")
	}
	if !sortedUnique(manifest.ToolCapabilities) || !sortedUnique(manifest.ProcessCapabilities) || !sortedUnique(manifest.DataClassesRead) ||
		!sortedUnique(manifest.DataClassesWrite) || !sortedUnique(manifest.DestructiveCapabilities) {
		return errors.New("permission sets are not sorted and unique")
	}
	for _, value := range append(append([]string{}, manifest.ToolCapabilities...), manifest.ProcessCapabilities...) {
		if value == "*" || strings.Contains(value, "**") {
			return errors.New("wildcard capability is forbidden")
		}
	}
	for _, network := range manifest.NetworkCapabilities {
		if err := ValidateNetworkCapability(network); err != nil {
			return err
		}
	}
	if len(manifest.FilesystemCapabilities) > MaxCollectionItems || len(manifest.NetworkCapabilities) > MaxCollectionItems ||
		len(manifest.CredentialCapabilities) > MaxCollectionItems || len(manifest.DisclosureCapabilities) > MaxCollectionItems ||
		len(manifest.UploadCapabilities) > MaxCollectionItems {
		return errors.New("permission collection exceeds released limit")
	}
	if !canonicalSortedUnique(manifest.FilesystemCapabilities) || !canonicalSortedUnique(manifest.NetworkCapabilities) ||
		!canonicalSortedUnique(manifest.CredentialCapabilities) || !canonicalSortedUnique(manifest.DisclosureCapabilities) ||
		!canonicalSortedUnique(manifest.UploadCapabilities) {
		return errors.New("typed permission sets are not canonically sorted and unique")
	}
	for _, filesystem := range manifest.FilesystemCapabilities {
		if len(filesystem.RootHandleDigest) != sha256.Size || filesystem.RelativePrefix == "" || strings.HasPrefix(filesystem.RelativePrefix, "/") ||
			strings.Contains(filesystem.RelativePrefix, "\\") || strings.Contains("/"+filesystem.RelativePrefix+"/", "/../") ||
			!filesystem.NoFollow || filesystem.MaximumBytes == 0 || !sortedUnique(filesystem.Operations) {
			return errors.New("filesystem capability is unsafe or incomplete")
		}
		for _, operation := range filesystem.Operations {
			if operation != "read" && operation != "write" && operation != "create" && operation != "delete" {
				return errors.New("filesystem operation is unsupported")
			}
			if filesystem.ReadOnly && operation != "read" {
				return errors.New("read-only filesystem capability grants mutation")
			}
		}
	}
	for _, disclosure := range manifest.DisclosureCapabilities {
		if disclosure.DataClass == "" || len(disclosure.AudienceDigest) != sha256.Size || len(disclosure.PurposeDigest) != sha256.Size ||
			disclosure.MaximumBytes == 0 || disclosure.ExpiresAtUnix == 0 {
			return errors.New("disclosure capability is incomplete")
		}
	}
	for _, upload := range manifest.UploadCapabilities {
		parsed, err := url.Parse(upload.DestinationOrigin)
		if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
			upload.DataClass == "" || len(upload.ObjectDigest) != sha256.Size || upload.MaximumBytes == 0 || len(upload.CredentialHandle) == 0 {
			return errors.New("upload capability is unsafe or incomplete")
		}
	}
	if manifest.ResourceCeiling.CPUMillis == 0 || manifest.ResourceCeiling.MemoryBytes == 0 || manifest.ResourceCeiling.StorageBytes == 0 ||
		manifest.ResourceCeiling.RuntimeMillis == 0 || manifest.RetentionPolicy.MaximumRetentionSeconds == 0 ||
		manifest.LoggingPolicy.MaximumBytes == 0 || !manifest.LoggingPolicy.RedactionRequired || !sortedUnique(manifest.LoggingPolicy.AllowedDataClasses) {
		return errors.New("resource, retention, or logging policy is incomplete")
	}
	for _, credential := range manifest.CredentialCapabilities {
		if len(credential.BrokerHandle) == 0 || credential.Issuer == "" || credential.Audience == "" || credential.Origin == "" ||
			credential.Destination == "" || credential.Action == "" || credential.ExpiresAtUnix == 0 || credential.UseCount == 0 || !credential.NonDelegable || !sortedUnique(credential.Scopes) {
			return errors.New("credential capability is incomplete or delegable")
		}
	}
	return nil
}

func PermissionSubsetOf(selected, admitted CapabilityPermissionManifestV1) error {
	if err := ValidatePermissionManifest(selected); err != nil {
		return err
	}
	if err := ValidatePermissionManifest(admitted); err != nil {
		return err
	}
	if !bytes.Equal(selected.ArtifactPreManifestDigest, admitted.ArtifactPreManifestDigest) ||
		!stringSubset(selected.ToolCapabilities, admitted.ToolCapabilities) || !stringSubset(selected.ProcessCapabilities, admitted.ProcessCapabilities) ||
		!canonicalObjectSubset(selected.FilesystemCapabilities, admitted.FilesystemCapabilities) || !canonicalObjectSubset(selected.NetworkCapabilities, admitted.NetworkCapabilities) ||
		!canonicalObjectSubset(selected.CredentialCapabilities, admitted.CredentialCapabilities) || !stringSubset(selected.DataClassesRead, admitted.DataClassesRead) ||
		!stringSubset(selected.DataClassesWrite, admitted.DataClassesWrite) || !canonicalObjectSubset(selected.DisclosureCapabilities, admitted.DisclosureCapabilities) ||
		!canonicalObjectSubset(selected.UploadCapabilities, admitted.UploadCapabilities) || !stringSubset(selected.DestructiveCapabilities, admitted.DestructiveCapabilities) ||
		selected.ResourceCeiling.CPUMillis > admitted.ResourceCeiling.CPUMillis || selected.ResourceCeiling.MemoryBytes > admitted.ResourceCeiling.MemoryBytes ||
		selected.ResourceCeiling.StorageBytes > admitted.ResourceCeiling.StorageBytes || selected.ResourceCeiling.RuntimeMillis > admitted.ResourceCeiling.RuntimeMillis ||
		selected.ConcurrencyCeiling > admitted.ConcurrencyCeiling || selected.RetentionPolicy.MaximumRetentionSeconds > admitted.RetentionPolicy.MaximumRetentionSeconds ||
		selected.RetentionPolicy.DeleteOnTerminal != admitted.RetentionPolicy.DeleteOnTerminal || selected.RetentionPolicy.EvidenceOnlyAfterDelete != admitted.RetentionPolicy.EvidenceOnlyAfterDelete ||
		selected.LoggingPolicy.MaximumBytes > admitted.LoggingPolicy.MaximumBytes || !selected.LoggingPolicy.RedactionRequired ||
		!stringSubset(selected.LoggingPolicy.AllowedDataClasses, admitted.LoggingPolicy.AllowedDataClasses) {
		return errors.New("selected permission manifest exceeds admitted authority")
	}
	selectedCost, selectedOK := new(big.Int).SetString(selected.DirectCostCeiling, 10)
	admittedCost, admittedOK := new(big.Int).SetString(admitted.DirectCostCeiling, 10)
	if !selectedOK || !admittedOK || selectedCost.Cmp(admittedCost) > 0 {
		return errors.New("selected direct cost exceeds admitted ceiling")
	}
	return nil
}

func stringSubset(selected, admitted []string) bool {
	for _, item := range selected {
		index := sort.SearchStrings(admitted, item)
		if index == len(admitted) || admitted[index] != item {
			return false
		}
	}
	return true
}

func canonicalObjectSubset[T any](selected, admitted []T) bool {
	want := make(map[string]struct{}, len(admitted))
	for _, item := range admitted {
		encoded, err := MarshalBody(item)
		if err != nil {
			return false
		}
		want[string(encoded)] = struct{}{}
	}
	for _, item := range selected {
		encoded, err := MarshalBody(item)
		if err != nil {
			return false
		}
		if _, ok := want[string(encoded)]; !ok {
			return false
		}
	}
	return true
}

func canonicalSortedUnique[T any](values []T) bool {
	var previous []byte
	for _, value := range values {
		encoded, err := MarshalBody(value)
		if err != nil || previous != nil && bytes.Compare(previous, encoded) >= 0 {
			return false
		}
		previous = encoded
	}
	return true
}

func ValidateNetworkCapability(capability NetworkCapabilityV1) error {
	if capability.Scheme != "https" || capability.Host == "" || strings.Contains(capability.Host, "*") || capability.Port == 0 ||
		len(capability.ResolverProfileDigest) != sha256.Size || capability.MaximumDNSTTL == 0 || len(capability.TLSProfileDigest) != sha256.Size ||
		capability.MaximumDNSAnswers == 0 || capability.MaximumDNSAnswers > 32 || capability.RedirectCount > 8 ||
		capability.MaximumRequestBytes == 0 || capability.MaximumResponseBytes == 0 || capability.TimeoutMillis == 0 ||
		capability.ConnectionCeiling == 0 {
		return errors.New("network capability is unsafe or incomplete")
	}
	if capability.ProxyIdentity == nil && len(capability.ProxyConnectDestinations) != 0 || capability.ProxyIdentity != nil &&
		(len(*capability.ProxyIdentity) != sha256.Size || !sortedUnique(capability.ProxyConnectDestinations)) {
		return errors.New("proxy identity and exact CONNECT destinations must be bound together")
	}
	parsed, err := url.Parse(capability.Scheme + "://" + net.JoinHostPort(capability.Host, binaryPort(capability.Port)))
	if err != nil || parsed.Hostname() != capability.Host {
		return errors.New("network origin is not canonical")
	}
	if ip := net.ParseIP(capability.Host); ip != nil && deniedIP(ip) {
		return errors.New("network capability targets a prohibited address")
	}
	if !sort.StringsAreSorted(capability.ProhibitedAddressClasses) || !containsAll(capability.ProhibitedAddressClasses,
		[]string{"link-local", "loopback", "metadata", "multicast", "private", "unspecified"}) {
		return errors.New("prohibited address classes are incomplete")
	}
	return nil
}

func deniedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

func binaryPort(port uint16) string {
	if port == 443 {
		return "443"
	}
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], port)
	const digits = "0123456789"
	value := int(binary.BigEndian.Uint16(raw[:]))
	output := ""
	for value > 0 {
		output = string(digits[value%10]) + output
		value /= 10
	}
	return output
}

func sortedUnique(values []string) bool {
	if !sort.StringsAreSorted(values) {
		return false
	}
	for index, value := range values {
		if value == "" || index > 0 && value == values[index-1] {
			return false
		}
	}
	return true
}

func containsAll(have, required []string) bool {
	for _, item := range required {
		index := sort.SearchStrings(have, item)
		if index == len(have) || have[index] != item {
			return false
		}
	}
	return true
}

func ValidateReference(reference ImmutableObjectReferenceV1) error {
	if len(reference.DomainID) == 0 || len(reference.ObjectDigest) != sha256.Size || reference.CanonicalSize == 0 ||
		reference.CanonicalSize > MaxCanonicalBytes || len(reference.RetrievalPolicyDigest) != sha256.Size || reference.MediaType == "" {
		return errors.New("immutable reference is incomplete")
	}
	for _, hint := range reference.RetrievalHints {
		parsed, err := url.Parse(hint)
		if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Fragment != "" {
			return errors.New("retrieval hint is unsafe")
		}
	}
	return nil
}

func ReferenceMatchesObject(reference ImmutableObjectReferenceV1, object ProfileObjectV1) error {
	if err := ValidateReference(reference); err != nil {
		return err
	}
	canonical, err := EncodeObject(object)
	if err != nil {
		return err
	}
	digest, err := ObjectDigest(object)
	if err != nil || reference.DomainKind != object.DomainKind || !bytes.Equal(reference.DomainID, object.DomainID) ||
		reference.ObjectKind != object.ObjectKind || reference.ProfileURI != object.ProfileURI || reference.ProfileVersion != object.ProfileVersion ||
		!bytes.Equal(reference.ObjectDigest, digest) || reference.CanonicalSize != uint32(len(canonical)) {
		return errors.New("immutable reference does not match supplied object")
	}
	return nil
}

func EqualDigest(a, b []byte) bool { return len(a) == sha256.Size && bytes.Equal(a, b) }
