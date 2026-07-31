package localrpc

import (
	"testing"
	"time"

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

func TestQuoteCommitmentsStayWithinRequestedUpperBounds(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000).UTC()
	request := validQuoteRequest(now)
	request.RequestedLimits = []*edgev1.ResourceLimit{{
		Id: "memory.ram", Unit: edgev1.ResourceUnit_RESOURCE_UNIT_BYTES,
		Quantity: 8 << 30,
	}}
	response := &edgev1.QuoteResponse{
		QuoteId: "quote-0001", RequestId: request.RequestId,
		ExpiresUnixMillis: now.Add(time.Minute).UnixMilli(),
		CapacityRevision:  "capacity-1", ModelRevision: "model-1",
		RuntimeRevision: "runtime-1",
		CommittedLimits: []*edgev1.ResourceLimit{{
			Id: "memory.ram", Unit: edgev1.ResourceUnit_RESOURCE_UNIT_BYTES,
			Quantity: 4 << 30,
		}},
	}
	if err := validateQuoteResponse(response, request, now); err != nil {
		t.Fatal(err)
	}
	response.CommittedLimits[0].Quantity = 9 << 30
	if err := validateQuoteResponse(response, request, now); err == nil {
		t.Fatal("commitment above requested upper bound was accepted")
	}
	response.CommittedLimits[0].Quantity = 4 << 30
	response.CommittedLimits[0].Id = "memory.vram"
	if err := validateQuoteResponse(response, request, now); err == nil {
		t.Fatal("missing requested commitment was accepted")
	}
}

func TestCapabilitySnapshotFreshnessAndEvidenceCoverage(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000).UTC()
	valid := &edgev1.GetCapabilitiesResponse{
		CapacityRevision: "capacity-1", TerminalRevision: "terminal-1",
		CollectedUnixMillis: now.Add(-time.Second).UnixMilli(),
		ExpiresUnixMillis:   now.Add(time.Minute).UnixMilli(),
		Resources: []*edgev1.ResourceClaim{{
			Id: "memory.ram", ResourceClass: edgev1.ResourceClass_RESOURCE_CLASS_MEMORY,
			Unit: edgev1.ResourceUnit_RESOURCE_UNIT_BYTES, Total: 1024,
			AvailableExternal: 512, Revision: "probe-1",
			Evidence: &edgev1.ClaimEvidence{
				Level:  edgev1.EvidenceLevel_EVIDENCE_LEVEL_DECLARED,
				Issuer: "worker-runtime", CollectedUnixMillis: now.Add(-time.Minute).UnixMilli(),
				ExpiresUnixMillis: now.Add(2 * time.Minute).UnixMilli(),
			},
		}},
	}
	if err := validateCapabilitiesResponse(valid, now); err != nil {
		t.Fatal(err)
	}

	expired := proto.Clone(valid).(*edgev1.GetCapabilitiesResponse)
	expired.ExpiresUnixMillis = now.UnixMilli()
	if err := validateCapabilitiesResponse(expired, now); err == nil {
		t.Fatal("expired capability snapshot was accepted")
	}

	uncovered := proto.Clone(valid).(*edgev1.GetCapabilitiesResponse)
	uncovered.Resources[0].Evidence.ExpiresUnixMillis = now.Add(30 * time.Second).UnixMilli()
	if err := validateCapabilitiesResponse(uncovered, now); err == nil {
		t.Fatal("resource evidence shorter than the capability snapshot was accepted")
	}

	tooLong := proto.Clone(valid).(*edgev1.GetCapabilitiesResponse)
	tooLong.ExpiresUnixMillis = tooLong.CollectedUnixMillis +
		(maxWorkerCapabilityValidity + time.Millisecond).Milliseconds()
	tooLong.Resources[0].Evidence.ExpiresUnixMillis = tooLong.ExpiresUnixMillis
	if err := validateCapabilitiesResponse(tooLong, now); err == nil {
		t.Fatal("overlong capability snapshot was accepted")
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
