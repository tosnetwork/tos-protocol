package predictionmarket

import (
	"math"
	"testing"
)

func modelOrder(owner string, action Action, outcome Outcome, role LiquidityRole, limit uint16) PredictionOrderV1 {
	return PredictionOrderV1{GlobalID: 42, WorkchainID: 0, MarketAddress: testAddress(0x11), MarketConfigHash: testHash(0x22),
		OwnerAddress: owner, KeyEpoch: 1, Nonce: uint64(owner[len(owner)-1]), Salt: testHash(owner[len(owner)-1]),
		Action: action, Outcome: outcome, LiquidityRole: role, QuantityLots: 10, MinFillLots: 1,
		AllowPartial: true, LimitPriceTick: limit, ValidAfter: 100, ValidUntil: 200}
}

func seededModel(t *testing.T) (*ReferenceModel, string, string, string) {
	t.Helper()
	model, err := NewReferenceModel(10_000)
	if err != nil {
		t.Fatal(err)
	}
	yesOwner, noOwner, third := testAddress(0x31), testAddress(0x32), testAddress(0x33)
	for _, owner := range []string{yesOwner, noOwner, third} {
		if err := model.Deposit(owner, 200_000); err != nil {
			t.Fatal(err)
		}
	}
	return model, yesOwner, noOwner, third
}

func prepareDistributedPositions(t *testing.T) (*ReferenceModel, string, string, string, uint64) {
	t.Helper()
	model, yesOwner, noOwner, third := seededModel(t)
	initial, _ := model.TotalBacking()
	buyYes := modelOrder(yesOwner, ActionBuy, OutcomeYes, RoleMaker, 6_000)
	buyNo := modelOrder(noOwner, ActionBuy, OutcomeNo, RoleTaker, 4_500)
	amounts, err := model.Match(buyYes, buyNo, 10)
	if err != nil {
		t.Fatal(err)
	}
	if amounts.YesValue != 60_000 || amounts.NoValue != 40_000 || amounts.Notional != 100_000 {
		t.Fatalf("wrong exact match amounts: %#v", amounts)
	}
	if backing, _ := model.TotalBacking(); backing != initial {
		t.Fatal("mint changed total backing")
	}

	sellYes := modelOrder(yesOwner, ActionSell, OutcomeYes, RoleMaker, 6_000)
	buyTransferredYes := modelOrder(third, ActionBuy, OutcomeYes, RoleTaker, 6_500)
	if _, err := model.Match(sellYes, buyTransferredYes, 5); err != nil {
		t.Fatal(err)
	}
	if model.Accounts[yesOwner].YesLots != 5 || model.Accounts[third].YesLots != 5 {
		t.Fatal("same-outcome transfer moved the wrong positions")
	}

	mergeYes := modelOrder(third, ActionSell, OutcomeYes, RoleMaker, 6_000)
	mergeNo := modelOrder(noOwner, ActionSell, OutcomeNo, RoleTaker, 3_500)
	if _, err := model.Match(mergeYes, mergeNo, 5); err != nil {
		t.Fatal(err)
	}
	if model.CompleteSets != 5 || model.LockedCollateral != 50_000 {
		t.Fatal("complementary sell did not release exact complete-set backing")
	}
	if backing, _ := model.TotalBacking(); backing != initial {
		t.Fatal("merge match changed total backing")
	}
	return model, yesOwner, noOwner, third, initial
}

func TestReferenceModelThreeMatchPathsConserveBacking(t *testing.T) {
	model, _, _, _, _ := prepareDistributedPositions(t)
	if err := model.CheckInvariants(); err != nil {
		t.Fatal(err)
	}
}

func TestReferenceModelSplitAndMergeAreExactInverses(t *testing.T) {
	model, owner, _, _ := seededModel(t)
	before, _ := model.TotalBacking()
	accountBefore := model.Accounts[owner]
	if err := model.Split(owner, 7); err != nil {
		t.Fatal(err)
	}
	if err := model.Merge(owner, 7); err != nil {
		t.Fatal(err)
	}
	if model.Accounts[owner] != accountBefore || model.CompleteSets != 0 || model.LockedCollateral != 0 {
		t.Fatal("split and merge were not exact inverses")
	}
	if after, _ := model.TotalBacking(); after != before {
		t.Fatal("split/merge changed total backing")
	}
}

func TestReferenceModelFinalPayoutIsClaimOrderIndependent(t *testing.T) {
	for _, outcome := range []Outcome{OutcomeYes, OutcomeNo, OutcomeInvalid} {
		t.Run(map[Outcome]string{OutcomeYes: "YES", OutcomeNo: "NO", OutcomeInvalid: "INVALID"}[outcome], func(t *testing.T) {
			model, yesOwner, noOwner, third, initial := prepareDistributedPositions(t)
			if err := model.Finalize(outcome); err != nil {
				t.Fatal(err)
			}
			if err := model.Deposit(yesOwner, 1); err == nil {
				t.Fatal("deposit after finalization was accepted")
			}
			if model.LockedCollateral != 0 || model.RemainingPayoutLiability != 50_000 || model.FinalBacking != 50_000 {
				t.Fatal("finalize did not atomically swap backing representations")
			}
			var paid uint64
			for _, owner := range []string{third, noOwner, yesOwner} {
				amount, err := model.Claim(owner)
				if err != nil {
					t.Fatal(err)
				}
				paid += amount
			}
			if paid != 50_000 || model.RemainingPayoutLiability != 0 || model.CumulativeClaimedPayout != model.FinalBacking {
				t.Fatal("claims did not consume the exact final backing")
			}
			if total, _ := model.TotalBacking(); total != initial {
				t.Fatal("finalization or claims changed aggregate backing")
			}
		})
	}
}

func TestReferenceModelRejectsInvalidPairsAndIsAtomic(t *testing.T) {
	model, first, second, _ := seededModel(t)
	before, _ := model.TotalBacking()
	badPairs := [][2]PredictionOrderV1{
		{modelOrder(first, ActionBuy, OutcomeYes, RoleMaker, 6_000), modelOrder(second, ActionBuy, OutcomeYes, RoleTaker, 7_000)},
		{modelOrder(first, ActionBuy, OutcomeYes, RoleMaker, 6_000), modelOrder(second, ActionSell, OutcomeNo, RoleTaker, 3_000)},
		{modelOrder(first, ActionSell, OutcomeYes, RoleMaker, 6_000), modelOrder(second, ActionSell, OutcomeYes, RoleTaker, 5_000)},
	}
	for _, pair := range badPairs {
		if _, err := model.Match(pair[0], pair[1], 1); err == nil {
			t.Fatal("non-conserving pair was accepted")
		}
		if after, _ := model.TotalBacking(); after != before || model.CompleteSets != 0 {
			t.Fatal("rejected match mutated the model")
		}
	}
	self := modelOrder(first, ActionBuy, OutcomeYes, RoleMaker, 6_000)
	other := modelOrder(first, ActionBuy, OutcomeNo, RoleTaker, 4_000)
	if _, err := model.Match(self, other, 1); err == nil {
		t.Fatal("self match was accepted")
	}
}

func TestOrderFillHalfOpenWindowAndNoDust(t *testing.T) {
	order := modelOrder(testAddress(0x31), ActionBuy, OutcomeYes, RoleMaker, 6_000)
	order.QuantityLots, order.MinFillLots = 100, 10
	for _, valid := range []struct{ filled, quantity, now uint64 }{{0, 10, 100}, {10, 80, 150}, {90, 10, 199}} {
		if err := ValidateOrderFill(order, valid.filled, valid.quantity, 5, valid.now, 200); err != nil {
			t.Fatalf("valid fill rejected: %v", err)
		}
	}
	for _, invalid := range []struct{ filled, quantity, now uint64 }{{0, 9, 100}, {0, 91, 100}, {0, 10, 99}, {0, 10, 200}} {
		if err := ValidateOrderFill(order, invalid.filled, invalid.quantity, 5, invalid.now, 200); err == nil {
			t.Fatal("invalid fill boundary was accepted")
		}
	}
	order.AllowPartial = false
	if err := ValidateOrderFill(order, 20, 79, 1, 150, 200); err == nil {
		t.Fatal("partial fill of all-or-nothing order was accepted")
	}
	if err := ValidateOrderFill(order, 20, 80, 1, 150, 200); err != nil {
		t.Fatal(err)
	}
}

func TestReferenceModelCheckedArithmetic(t *testing.T) {
	if _, err := NewReferenceModel(uint64(PriceScale) - 1); err == nil {
		t.Fatal("inexact lot payout was accepted")
	}
	model, err := NewReferenceModel(uint64(PriceScale))
	if err != nil {
		t.Fatal(err)
	}
	owner := testAddress(0x31)
	model.Accounts[owner] = AccountBalance{Free: math.MaxUint64}
	if err := model.Deposit(owner, 1); err == nil {
		t.Fatal("free-balance overflow was accepted")
	}
}
