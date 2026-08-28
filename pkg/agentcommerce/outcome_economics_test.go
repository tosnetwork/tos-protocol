package agentcommerce

import "testing"

func TestOutcomeEconomicAndTransferProfilesFailClosed(t *testing.T) {
	d := outcomeDigest("a")
	conversion := AssetConversionEvidenceV1{SourceAssetDigest: d, TargetAssetDigest: outcomeDigest("b"), SourceAmountAtomic: "10",
		RateNumerator: "3", RateDenominator: "2", RateType: "executed", PriceSourceProfileURI: "tos.price.oracle.v1",
		PriceEvidenceDigest: outcomeDigest("c"), QuotedAtUnix: 10, ValidUntilUnix: 20, FeeAmountAtomic: "1", RoundingRule: "floor",
		TargetAmountAtomic: "14", ConversionPolicyDigest: outcomeDigest("d")}
	if err := ValidateAssetConversionEvidenceV1(conversion); err != nil {
		t.Fatal(err)
	}
	conversion.TargetAmountAtomic = "15"
	if ValidateAssetConversionEvidenceV1(conversion) == nil {
		t.Fatal("conversion accepted inconsistent exact arithmetic")
	}

	revenue := RevenueRecognitionV1{AgreementBodyDigest: d, ObligationInstanceID: outcomeDigest("b"), PaymentAssertionDigest: outcomeDigest("c"),
		SellerPerimeterDigest: outcomeDigest("d"), BuyerPerimeterDigest: outcomeDigest("e"), RelationshipClass: "related_party",
		ConsiderationAssetDigest: outcomeDigest("f"), GrossAmountAtomic: "100", RecognizedAmountAtomic: "0",
		RecognitionPolicyDigest: outcomeDigest("1"), AuthorityEvidenceSetRoot: outcomeDigest("2")}
	if err := ValidateRevenueRecognitionV1(revenue); err != nil {
		t.Fatal(err)
	}
	revenue.RecognizedAmountAtomic = "100"
	if ValidateRevenueRecognitionV1(revenue) == nil {
		t.Fatal("related-party transfer was recognized as external revenue")
	}

	gift := TransferObservationV1{TransferClass: "gift", NetworkID: "tos:test", TransactionDigest: d,
		FinalityEvidenceDigest: outcomeDigest("b"), PayerID: "agent:a", PayeeID: "agent:b", AssetIdentityDigest: outcomeDigest("c"),
		AmountAtomic: "5", DestinationDigest: outcomeDigest("d"), GiftObjectDigest: outcomeDigest("e"),
		AdapterProfileURI: "tos.transfer.tos.v1", ResolutionState: "validator_finalized", ObservedAtUnix: 10}
	if err := ValidateTransferObservationV1(gift); err != nil {
		t.Fatal(err)
	}
	gift.AgreementBodyDigest = outcomeDigest("f")
	if ValidateTransferObservationV1(gift) == nil {
		t.Fatal("Gift accepted an Agreement settlement binding")
	}

	payment := gift
	payment.TransferClass, payment.GiftObjectDigest = "agreement_bound", ""
	payment.AgreementBodyDigest, payment.ObligationInstanceID, payment.PaymentRequestDigest = outcomeDigest("1"), outcomeDigest("2"), outcomeDigest("3")
	payment.StableActionID, payment.ExactRequestDigest = outcomeDigest("4"), outcomeDigest("5")
	if err := ValidateTransferObservationV1(payment); err != nil {
		t.Fatal(err)
	}
	payment.PaymentRequestDigest = outcomeDigest("6")
	if err := ValidateTransferObservationV1(payment); err != nil {
		t.Fatal(err)
	}
}

func TestTOSEscrowObservationDoesNotRecognizeLockedPrincipalAsRevenue(t *testing.T) {
	value := TOSEscrowObservationV1{Stage: "principal_locked", TransferClass: "collateral", NetworkID: "tos:test",
		AcceptedQuoteDigest: outcomeDigest("1"), AgreementBodyDigest: outcomeDigest("2"), ObligationInstanceID: outcomeDigest("3"),
		EscrowAccountDigest: outcomeDigest("4"), ContractCodeDigest: outcomeDigest("5"), ContractConfigurationHash: outcomeDigest("6"),
		StableActionID: outcomeDigest("7"), ExactRequestDigest: outcomeDigest("8"), TransactionBytesDigest: outcomeDigest("9"),
		TransactionDigest: outcomeDigest("a"), FinalizedCheckpointDigest: outcomeDigest("b"), AssetIdentityDigest: outcomeDigest("c"),
		AmountAtomic: "50", AuthorityEvidenceSetRoot: outcomeDigest("d"), ObservedAtUnix: 2_000_000_000}
	if err := ValidateTOSEscrowObservationV1(value); err != nil {
		t.Fatal(err)
	}
	value.TransferClass = "agreement_bound"
	if ValidateTOSEscrowObservationV1(value) == nil {
		t.Fatal("locked principal was accepted as Agreement revenue")
	}
	value.Stage, value.TransferClass = "release_finalized", "agreement_bound"
	if err := ValidateTOSEscrowObservationV1(value); err != nil {
		t.Fatal(err)
	}
}
