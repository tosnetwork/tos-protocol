// Command agent-guarantor-fixtures emits the released Guarantor V1 dispatch
// registries and canonical digests for independent implementations.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func main() {
	output := flag.String("output", "", "write fixtures to this path instead of stdout")
	flag.Parse()
	objects := guarantor.ReleasedObjectVerifierRegistryV1()
	mutations := guarantor.ReleasedMutationVerifierRegistryV1()
	objectCanonical, err := codec.Marshal(objects)
	if err != nil {
		fatal(err)
	}
	mutationCanonical, err := codec.Marshal(mutations)
	if err != nil {
		fatal(err)
	}
	objectDigest, err := guarantor.ObjectVerifierRegistryDigestV1()
	if err != nil {
		fatal(err)
	}
	mutationDigest, err := guarantor.MutationVerifierRegistryDigestV1()
	if err != nil {
		fatal(err)
	}
	genesis, err := guarantor.NewAcceptedCoverageRecord(fixtureDigest("1"), "obligation:coverage", fixtureDigest("2"), fixtureDigest("3"))
	if err != nil {
		fatal(err)
	}
	activated, err := guarantor.ActivateAcceptedCoverage(genesis, 1, 1, fixtureDigest("4"))
	if err != nil {
		fatal(err)
	}
	frozen, err := guarantor.FreezeClaimFiling(activated, 2, 2, 0, fixtureDigest("5"), fixtureDigest("6"), false)
	if err != nil {
		fatal(err)
	}
	stateVectors := []struct {
		Name             string                   `json:"name"`
		State            guarantor.CoverageRecord `json:"state"`
		CanonicalCBORHex string                   `json:"canonical_cbor_hex"`
		Digest           string                   `json:"digest"`
	}{
		{Name: "accepted-genesis", State: genesis}, {Name: "activated", State: activated}, {Name: "filing-frozen-zero-claims", State: frozen}}
	for index := range stateVectors {
		canonical, encodeErr := codec.Marshal(stateVectors[index].State)
		if encodeErr != nil {
			fatal(encodeErr)
		}
		stateVectors[index].CanonicalCBORHex = hex.EncodeToString(canonical)
		stateVectors[index].Digest, err = guarantor.Digest("tos.service.agent-guarantor-coverage-state-vector.v1", stateVectors[index].State)
		if err != nil {
			fatal(err)
		}
	}
	actionKind := "payment.domain-bound"
	actionValues := map[string]commerce.SemanticValue{
		"owner_id":               commerce.ID("owner:guarantor"),
		"agent_id":               commerce.ID("agent:guarantor"),
		"agreement_body_digest":  commerce.Digest32(fixtureDigest("1")),
		"obligation_instance_id": commerce.Digest32(fixtureDigest("2")),
		"payer_id":               commerce.ID("agent:guarantor"),
		"payee_id":               commerce.ID("agent:beneficiary"),
		"network_domain_digest":  commerce.Digest32(fixtureDigest("3")),
		"asset_digest":           commerce.Digest32(fixtureDigest("4")),
		"amount_atomic":          commerce.ID("1250000"),
		"destination_digest":     commerce.Digest32(fixtureDigest("5")),
	}
	stableActionID, semanticPreimage, err := commerce.DeriveStableActionID(actionKind, actionValues)
	if err != nil {
		fatal(err)
	}
	semanticFields, err := commerce.ExportSemanticFields(actionKind, actionValues)
	if err != nil {
		fatal(err)
	}
	actionVectors := []struct {
		Name           string                        `json:"name"`
		ActionKind     string                        `json:"action_kind"`
		Fields         []commerce.SemanticFieldValue `json:"fields"`
		StableActionID string                        `json:"stable_action_id"`
		PreimageHex    string                        `json:"preimage_hex"`
	}{
		{Name: "guarantor-domain-bound-payout", ActionKind: actionKind, Fields: semanticFields,
			StableActionID: stableActionID, PreimageHex: hex.EncodeToString(semanticPreimage)},
	}
	document := struct {
		Schema                        string                               `json:"schema"`
		ProfileURI                    string                               `json:"profile_uri"`
		CommerceProfileContentType    string                               `json:"commerce_profile_event_content_type"`
		CommerceCarriageRegistry      []guarantor.CommerceCarriageObjectV1 `json:"commerce_carriage_registry"`
		ObjectRegistry                guarantor.ObjectVerifierRegistryV1   `json:"object_registry"`
		ObjectRegistryCanonicalCBOR   string                               `json:"object_registry_canonical_cbor_hex"`
		ObjectRegistryDigest          string                               `json:"object_registry_digest"`
		MutationRegistry              guarantor.MutationVerifierRegistryV1 `json:"mutation_registry"`
		MutationRegistryCanonicalCBOR string                               `json:"mutation_registry_canonical_cbor_hex"`
		MutationRegistryDigest        string                               `json:"mutation_registry_digest"`
		CoverageStateVectors          interface{}                          `json:"coverage_state_vectors"`
		SemanticActionVectors         interface{}                          `json:"semantic_action_vectors"`
	}{"tos.service.agent-guarantor-conformance-fixture.v1", guarantor.ProfileURI,
		commerce.CommerceProfileEventContentType, guarantor.ReleasedCommerceCarriageObjectsV1(), objects,
		hex.EncodeToString(objectCanonical), objectDigest, mutations, hex.EncodeToString(mutationCanonical), mutationDigest,
		stateVectors, actionVectors}
	var writer io.Writer = os.Stdout
	var file *os.File
	if *output != "" {
		file, err = os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			fatal(err)
		}
		defer file.Close()
		writer = file
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		fatal(err)
	}
}

func fixtureDigest(ch string) string {
	value := "sha256:"
	for range 64 {
		value += ch
	}
	return value
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
