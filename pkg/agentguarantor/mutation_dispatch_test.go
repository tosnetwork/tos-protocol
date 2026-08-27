package agentguarantor

import (
	"testing"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func TestMutationDispatcherMatchesReleasedRegistry(t *testing.T) {
	if err := verifyMutationFactoriesMatchRegistryV1(); err != nil {
		t.Fatal(err)
	}
	request := ClaimSubmissionIngressActionBodyV1{SchemaVersion: 1, TargetIngressState: "received"}
	canonical, err := codec.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeMutationRequestV1("conditional.claim.ingress", "claim-submission-ingress", canonical); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeMutationRequestV1("conditional.claim.submit", "claim-submission-ingress", canonical); err == nil {
		t.Fatal("mutation request was decoded under a substituted dispatch key")
	}
}
