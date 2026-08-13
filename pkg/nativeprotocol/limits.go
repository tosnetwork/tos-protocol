package nativeprotocol

// Phase 5A V1 pre-deployment execution limits. These values are part of the
// canonical protocol, not implementation tuning knobs. They keep the complete
// signed action and its Phase 5B execution envelope below TOS's consensus
// external-message limit while leaving room for transaction framing.
const (
	MaxCanonicalActionBytes  = 24 << 10
	MaxCanonicalPayloadBytes = 16 << 10
	MaxControllerPolicyBytes = 12 << 10

	MaxPurposesPerController        = 16
	MaxDelegationPurposes           = 16
	MaxDelegationResources          = 32
	MaxManifestLocations            = 16
	MaxCapabilityEndpoints          = 32
	MaxQuoteSignerKeyIDs            = 32
	MaxReceiptSignerKeyIDs          = 32
	MaxDelegationsPerGeneration     = 128
	MaxCapabilityVersionsPerLineage = 256
)
