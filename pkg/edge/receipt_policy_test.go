package edge

import (
	"context"
	"testing"

	"github.com/tosnetwork/tos-protocol/pkg/authorization"
)

func TestSuccessfulReceiptPolicyUsesBoundedDeterministicArithmetic(
	t *testing.T,
) {
	tests := []struct {
		name   string
		basis  uint16
		quote  uint64
		charge uint64
	}{
		{name: "zero", basis: 0, quote: 5, charge: 0},
		{name: "half-rounds-down", basis: 5_000, quote: 5, charge: 2},
		{name: "third", basis: 3_333, quote: 10_001, charge: 3_333},
		{name: "full", basis: 10_000, quote: ^uint64(0), charge: ^uint64(0)},
		{
			name: "half-max", basis: 5_000, quote: ^uint64(0),
			charge: (^uint64(0)) / 2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, err := NewProportionalSuccessfulReceiptPolicy(test.basis)
			if err != nil {
				t.Fatal(err)
			}
			charged, err := policy.chargedNanoTOS(test.quote)
			if err != nil || charged != test.charge {
				t.Fatalf("charge = %d, want %d, err = %v", charged, test.charge, err)
			}
		})
	}
	if _, err := NewProportionalSuccessfulReceiptPolicy(10_001); err == nil {
		t.Fatal("policy above full quoted price was accepted")
	}
	if _, err := (SuccessfulReceiptPolicy{}).chargedNanoTOS(1); err == nil {
		t.Fatal("zero-value policy was accepted outside registration normalization")
	}
}

func TestProfileInvocationPlanBindsSuccessfulReceiptPolicy(t *testing.T) {
	partial, err := NewProportionalSuccessfulReceiptPolicy(2_500)
	if err != nil {
		t.Fatal(err)
	}
	mapper := ProfileInvocationMapperFunc(func(
		context.Context,
		ProfileInvocationInput,
	) (ProfileInvocationOutput, error) {
		return ProfileInvocationOutput{Model: "model"}, nil
	})
	registration := ProfileInvocationRegistration{
		ProfileID: "tos.ai.inference", ProfileVersion: "0.1.0",
		Operation: "invoke", Mapper: mapper,
		SuccessfulReceiptPolicy: partial,
	}
	requirement := ProfileInvocationRequirement{
		ProfileID: "tos.ai.inference", ProfileVersion: "0.1.0",
		Operation: "invoke",
	}
	plan, err := NewProfileInvocationPlan(
		[]ProfileInvocationRegistration{registration},
		[]ProfileInvocationRequirement{requirement},
	)
	if err != nil {
		t.Fatal(err)
	}
	material := authorization.ReceiptInvocationMaterial{
		ProfileID: "tos.ai.inference", ProfileVersion: "0.1.0",
		Operation: "invoke", PriceNanoTOS: 11,
	}
	policy, err := plan.resolveSuccessfulReceiptPolicy(material)
	if err != nil {
		t.Fatal(err)
	}
	charged, err := policy.chargedNanoTOS(material.PriceNanoTOS)
	if err != nil || charged != 2 {
		t.Fatalf("partial charge = %d, err = %v", charged, err)
	}

	registration.SuccessfulReceiptPolicy = SuccessfulReceiptPolicy{}
	defaultPlan, err := NewProfileInvocationPlan(
		[]ProfileInvocationRegistration{registration},
		[]ProfileInvocationRequirement{requirement},
	)
	if err != nil {
		t.Fatal(err)
	}
	policy, err = defaultPlan.resolveSuccessfulReceiptPolicy(material)
	if err != nil {
		t.Fatal(err)
	}
	charged, err = policy.chargedNanoTOS(material.PriceNanoTOS)
	if err != nil || charged != material.PriceNanoTOS {
		t.Fatalf("default charge = %d, err = %v", charged, err)
	}

	if _, err := plan.resolveSuccessfulReceiptPolicy(
		authorization.ReceiptInvocationMaterial{
			ProfileID: "tos.ai.other", ProfileVersion: "0.1.0",
			Operation: "invoke",
		},
	); err == nil {
		t.Fatal("undeclared selector obtained a receipt policy")
	}
	registration.SuccessfulReceiptPolicy = SuccessfulReceiptPolicy{
		chargeBasisPoints: 10_001,
		valid:             true,
	}
	if _, err := NewProfileInvocationPlan(
		[]ProfileInvocationRegistration{registration},
		[]ProfileInvocationRequirement{requirement},
	); err == nil {
		t.Fatal("registration with an invalid receipt policy was accepted")
	}
}
