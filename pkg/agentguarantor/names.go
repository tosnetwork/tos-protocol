package agentguarantor

import "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"

// The public specification uses the Guarantor prefix on profile-level types.
// These aliases keep the Go API concise without making the canonical type
// names in the released verifier registry fictional.
type GuarantorServiceProfileV1 = ServiceProfileV1
type GuarantorClaimProfileV1 = ClaimProfileV1
type GuarantorCollateralProfileV1 = CollateralProfileV1
type GuarantorCoverageTermsV1 = CoverageTermsV1
type GuarantorObjectVerifierRegistryV1 = ObjectVerifierRegistryV1
type GuarantorMutationVerifierRegistryV1 = MutationVerifierRegistryV1
type AgentAgreementBodyV1 = agentcommerce.AgentAgreementBody
type CommerceProfileEventV1 = agentcommerce.CommerceProfileEventV1
