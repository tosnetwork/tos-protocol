package localrpc

import (
	"testing"

	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"google.golang.org/protobuf/proto"
)

func TestStructuredWorkerResourceFieldsRoundTrip(t *testing.T) {
	message := &edgev1.GetCapabilitiesResponse{
		CapacityRevision: "capacity-1",
		TerminalRevision: "terminal-1",
		Resources: []*edgev1.ResourceClaim{{
			Id:                "memory.host",
			ResourceClass:     edgev1.ResourceClass_RESOURCE_CLASS_MEMORY,
			Unit:              edgev1.ResourceUnit_RESOURCE_UNIT_BYTES,
			Total:             64 << 30,
			OwnerReserved:     16 << 30,
			AvailableExternal: 32 << 30,
			Revision:          "probe-v1",
			Attributes:        map[string]string{"architecture.name": "amd64"},
			Evidence: &edgev1.ClaimEvidence{
				Level:  edgev1.EvidenceLevel_EVIDENCE_LEVEL_OBSERVED,
				Issuer: "runtime-key-1",
			},
		}},
	}
	encoded, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	var decoded edgev1.GetCapabilitiesResponse
	if err := proto.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Resources) != 1 ||
		decoded.Resources[0].AvailableExternal != 32<<30 ||
		decoded.Resources[0].Attributes["architecture.name"] != "amd64" ||
		decoded.Resources[0].Evidence.Level != edgev1.EvidenceLevel_EVIDENCE_LEVEL_OBSERVED {
		t.Fatalf("unexpected resource round trip: %#v", &decoded)
	}
}

func TestQuoteResourceLimitsRoundTrip(t *testing.T) {
	message := &edgev1.QuoteResponse{
		QuoteId: "quote-0001", RequestId: "request-0001",
		CommittedLimits: []*edgev1.ResourceLimit{{
			Id: "memory.ram", Unit: edgev1.ResourceUnit_RESOURCE_UNIT_BYTES,
			Quantity: 4 << 30,
		}},
	}
	encoded, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	var decoded edgev1.QuoteResponse
	if err := proto.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.CommittedLimits) != 1 || decoded.CommittedLimits[0].Quantity != 4<<30 {
		t.Fatalf("unexpected quote round trip: %#v", &decoded)
	}
}
