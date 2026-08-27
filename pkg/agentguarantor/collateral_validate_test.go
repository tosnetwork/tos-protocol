package agentguarantor

import "testing"

func TestCollateralTransitionIsAgreementBoundAndBalances(t *testing.T) {
	authority := CollateralAuthorizationBindingV1{AuthorizationProfile: testRef("1", "custody-authority"),
		AuthorizationSubjects: []string{"agent:custodian"}, AuthorizationQuorumRule: "all"}
	profile := CollateralTransitionProfileV1{TransitionKind: "payout", SuccessorDerivationProfile: testRef("2", "successor"),
		AdapterProfile: testRef("3", "custody-adapter"), AdapterRequestContentType: "application/vnd.tos.collateral-request.v1+cbor",
		AdapterRequestProfile: testRef("4", "request"), MaximumAdapterRequestBytes: 4096,
		AdapterEvidenceContentType: "application/vnd.tos.collateral-evidence.v1+cbor", AdapterEvidenceProfile: testRef("5", "evidence"),
		AuthorizationSubjectSource: "custodian", CustodianAuthorizationBinding: &authority,
		PermittedPriorStates: []string{"encumbered", "partially_consumed"}, PermittedResultingStates: []string{"depleted", "partially_consumed"},
		PrerequisiteEvidenceRoles: []string{"terminal-decision"}, AuthorizedClaimDecisionBinding: "required",
		PayoutDestinationBinding: "agreement_fixed"}
	profileDigest, err := CollateralTransitionProfileDigestV1(profile)
	if err != nil {
		t.Fatal(err)
	}
	binding := CollateralTransitionBindingV1{TransitionProfileDigest: profileDigest, TransitionProfile: profile,
		AuthorizationBinding: authority}
	disclosure := CollateralControlDisclosureV1{SchemaVersion: 1, CustodyAdapterProfile: profile.AdapterProfile,
		AdapterOperatorSubjects: []string{"agent:custodian"}, CustodianControllerRootSubjects: []string{"root:custodian"},
		DeclaredGuarantorControlRelationship: "control_undetermined"}
	terms := CollateralTermsV1{PositionID: "position:one", SelectedCollateralProfileDigest: testDigest("6"),
		AssuranceLevel: AssuranceCollateralAttested, Asset: testAsset(), Amount: AtomicAmountV1{Asset: testAsset(), AmountAtomic: "1000"},
		CollateralPrincipalSubject: "agent:principal", CustodyAdapterProfile: profile.AdapterProfile,
		CollateralControlDisclosure: disclosure, PositionIdentityProfile: testRef("7", "position"),
		TransitionBindings: []CollateralTransitionBindingV1{binding}, ContractOrAccountDigest: testDigest("8"),
		ExclusiveAllocationRequired: true, LockByUnix: 100, LockUntilUnix: 200, ReleaseNotBeforeUnix: 300,
		FinalityProfile: testRef("9", "finality"), MaximumEvidenceAgeSeconds: 60}
	position := CollateralPositionStateV1{SchemaVersion: 1, CoverageAgreementBodyDigest: testDigest("a"),
		CollateralObligationID: "obligation:collateral", PositionID: terms.PositionID, PositionDigest: testDigest("b"),
		CoverageBindingDigest: testDigest("c"), StateRevision: 3, Status: CollateralEncumbered, Asset: testAsset(),
		AllocatedAmount:    AtomicAmountV1{Asset: testAsset(), AmountAtomic: "1000"},
		CumulativeConsumed: AtomicAmountV1{Asset: testAsset(), AmountAtomic: "200"},
		CumulativeReleased: AtomicAmountV1{Asset: testAsset(), AmountAtomic: "0"},
		CumulativeImpaired: AtomicAmountV1{Asset: testAsset(), AmountAtomic: "0"},
		RemainingAmount:    AtomicAmountV1{Asset: testAsset(), AmountAtomic: "800"}}
	stateDigest, err := CollateralPositionStateDigestV1(position)
	if err != nil {
		t.Fatal(err)
	}
	bindingDigest, _ := CollateralTransitionBindingDigestV1(binding)
	request := CollateralAdapterRequestV1{SchemaVersion: 1, AdapterProfile: profile.AdapterProfile,
		AdapterRequestProfile: profile.AdapterRequestProfile, CoverageAgreementBodyDigest: position.CoverageAgreementBodyDigest,
		CollateralObligationID: position.CollateralObligationID, CollateralPositionID: position.PositionID,
		TransitionBindingDigest: bindingDigest, TransitionKind: "payout", ExpectedPositionState: position,
		ExpectedStateDigest: stateDigest, Asset: testAsset(), Amount: AtomicAmountV1{Asset: testAsset(), AmountAtomic: "300"},
		PayoutDestinationDigest: testDigest("d"), AgreementPaymentRequestDigest: testDigest("e"),
		ObligationInstanceID: "obligation-instance:1", AuthorizedClaimDecisionEnvelopeDigest: testDigest("f"),
		PrerequisiteEvidenceSetDigest: testDigest("0"), AdapterOperationParameters: []byte{0xa0}}
	next, err := ApplyCollateralAdapterTransitionV1(request, binding, terms)
	if err != nil {
		t.Fatal(err)
	}
	if next.Status != CollateralPartiallyConsumed || next.StateRevision != 4 ||
		next.CumulativeConsumed.AmountAtomic != "500" || next.RemainingAmount.AmountAtomic != "500" {
		t.Fatalf("unexpected collateral successor: %#v", next)
	}
	tampered := request
	tampered.AdapterProfile = testRef("1", "substituted-adapter")
	if _, err := ApplyCollateralAdapterTransitionV1(tampered, binding, terms); err == nil {
		t.Fatal("collateral request substituted its Agreement-bound Adapter")
	}
	overdrawn := request
	overdrawn.Amount.AmountAtomic = "801"
	if _, err := ApplyCollateralAdapterTransitionV1(overdrawn, binding, terms); err == nil {
		t.Fatal("collateral payout exceeded the remaining allocation")
	}
}
