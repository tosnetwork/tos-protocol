package predictionmarket

import (
	"errors"
	"math/bits"
)

type AccountBalance struct {
	Free    uint64
	YesLots uint64
	NoLots  uint64
}

// ReferenceModel is a pure, bounded-arithmetic oracle for contract tests. It
// deliberately excludes storage contributions and gas, which live in separate
// liability classes in the on-chain design.
type ReferenceModel struct {
	LotPayout                uint64
	CompleteSets             uint64
	LockedCollateral         uint64
	Finalized                bool
	FinalOutcome             Outcome
	FinalBacking             uint64
	RemainingPayoutLiability uint64
	CumulativeClaimedPayout  uint64
	Accounts                 map[string]AccountBalance
}

type MatchAmounts struct {
	YesValue uint64
	NoValue  uint64
	Notional uint64
	YesPrice uint16
}

func NewReferenceModel(lotPayout uint64) (*ReferenceModel, error) {
	if lotPayout == 0 || lotPayout%uint64(PriceScale) != 0 {
		return nil, errors.New("lot payout must be non-zero and divisible by the price scale")
	}
	return &ReferenceModel{LotPayout: lotPayout, Accounts: make(map[string]AccountBalance)}, nil
}

func (model *ReferenceModel) Deposit(owner string, amount uint64) error {
	if _, err := parseCanonicalAddress(owner); err != nil || amount == 0 || model.Finalized {
		return errors.New("invalid model deposit")
	}
	nextModel := model.clone()
	account := nextModel.Accounts[owner]
	next, ok := add64(account.Free, amount)
	if !ok {
		return errors.New("free-balance overflow")
	}
	account.Free = next
	nextModel.Accounts[owner] = account
	if err := nextModel.CheckInvariants(); err != nil {
		return err
	}
	*model = *nextModel
	return nil
}

func (model *ReferenceModel) Split(owner string, quantity uint64) error {
	if model.Finalized || quantity == 0 {
		return errors.New("split quantity must be non-zero")
	}
	nextModel := model.clone()
	debit, ok := mul64(quantity, nextModel.LotPayout)
	account := nextModel.Accounts[owner]
	if !ok || account.Free < debit {
		return errors.New("insufficient split collateral")
	}
	yes, yesOK := add64(account.YesLots, quantity)
	no, noOK := add64(account.NoLots, quantity)
	sets, setsOK := add64(nextModel.CompleteSets, quantity)
	locked, lockedOK := add64(nextModel.LockedCollateral, debit)
	if !yesOK || !noOK || !setsOK || !lockedOK {
		return errors.New("split arithmetic overflow")
	}
	account.Free -= debit
	account.YesLots, account.NoLots = yes, no
	nextModel.Accounts[owner] = account
	nextModel.CompleteSets, nextModel.LockedCollateral = sets, locked
	if err := nextModel.CheckInvariants(); err != nil {
		return err
	}
	*model = *nextModel
	return nil
}

func (model *ReferenceModel) Merge(owner string, quantity uint64) error {
	if model.Finalized || quantity == 0 {
		return errors.New("merge quantity must be non-zero")
	}
	nextModel := model.clone()
	account := nextModel.Accounts[owner]
	credit, ok := mul64(quantity, nextModel.LotPayout)
	free, freeOK := add64(account.Free, credit)
	if !ok || !freeOK || account.YesLots < quantity || account.NoLots < quantity ||
		nextModel.CompleteSets < quantity || nextModel.LockedCollateral < credit {
		return errors.New("insufficient merge position or arithmetic overflow")
	}
	account.Free = free
	account.YesLots -= quantity
	account.NoLots -= quantity
	nextModel.Accounts[owner] = account
	nextModel.CompleteSets -= quantity
	nextModel.LockedCollateral -= credit
	if err := nextModel.CheckInvariants(); err != nil {
		return err
	}
	*model = *nextModel
	return nil
}

func ValidateOrderFill(order PredictionOrderV1, alreadyFilled, quantity, marketMinimum, now, tradeClose uint64) error {
	if _, _, _, err := validateOrder(order); err != nil {
		return err
	}
	if quantity == 0 || alreadyFilled > order.QuantityLots || quantity > order.QuantityLots-alreadyFilled {
		return errors.New("fill exceeds order remaining quantity")
	}
	if now < order.ValidAfter || now >= order.ValidUntil || order.ValidUntil > tradeClose {
		return errors.New("order is outside its half-open validity interval")
	}
	remaining := order.QuantityLots - alreadyFilled
	if !order.AllowPartial {
		if quantity != remaining {
			return errors.New("all-or-nothing order requires a full remaining fill")
		}
		return nil
	}
	minimum := marketMinimum
	if order.MinFillLots > minimum {
		minimum = order.MinFillLots
	}
	if quantity != remaining && (quantity < minimum || remaining-quantity < minimum) {
		return errors.New("partial fill would violate the effective minimum or leave dust")
	}
	return nil
}

func (model *ReferenceModel) Match(left, right PredictionOrderV1, quantity uint64) (MatchAmounts, error) {
	if model.Finalized || quantity == 0 || left.OwnerAddress == right.OwnerAddress {
		return MatchAmounts{}, errors.New("match must be non-zero and cannot self-trade")
	}
	var maker, taker PredictionOrderV1
	if left.LiquidityRole == RoleMaker && right.LiquidityRole == RoleTaker {
		maker, taker = left, right
	} else if right.LiquidityRole == RoleMaker && left.LiquidityRole == RoleTaker {
		maker, taker = right, left
	} else {
		return MatchAmounts{}, errors.New("match requires exactly one maker and one taker")
	}
	if _, _, _, err := validateOrder(maker); err != nil {
		return MatchAmounts{}, err
	}
	if _, _, _, err := validateOrder(taker); err != nil {
		return MatchAmounts{}, err
	}
	if maker.GlobalID != taker.GlobalID || maker.WorkchainID != taker.WorkchainID ||
		maker.MarketAddress != taker.MarketAddress || maker.MarketConfigHash != taker.MarketConfigHash {
		return MatchAmounts{}, errors.New("orders belong to different market domains")
	}
	if (maker.OptionalCounterparty != nil && *maker.OptionalCounterparty != taker.OwnerAddress) ||
		(taker.OptionalCounterparty != nil && *taker.OptionalCounterparty != maker.OwnerAddress) {
		return MatchAmounts{}, errors.New("order counterparty restriction does not match")
	}
	yesPrice := maker.LimitPriceTick
	if maker.Outcome == OutcomeNo {
		yesPrice = PriceScale - maker.LimitPriceTick
	}
	if yesPrice == 0 || yesPrice >= PriceScale {
		return MatchAmounts{}, errors.New("maker price is outside the open payout interval")
	}
	noPrice := PriceScale - yesPrice
	if !orderAcceptsPrice(taker, yesPrice, noPrice) {
		return MatchAmounts{}, errors.New("maker execution price violates the taker limit")
	}
	unit := model.LotPayout / uint64(PriceScale)
	base, ok := mul64(quantity, unit)
	yesValue, yesOK := mul64(base, uint64(yesPrice))
	notional, notionalOK := mul64(quantity, model.LotPayout)
	if !ok || !yesOK || !notionalOK || yesValue > notional {
		return MatchAmounts{}, errors.New("match value overflow")
	}
	amounts := MatchAmounts{YesValue: yesValue, NoValue: notional - yesValue, Notional: notional, YesPrice: yesPrice}

	before, err := model.TotalBacking()
	if err != nil {
		return MatchAmounts{}, err
	}
	next := model.clone()
	switch {
	case maker.Action == ActionBuy && taker.Action == ActionBuy && maker.Outcome != taker.Outcome:
		err = next.applyMint(maker, taker, quantity, amounts)
	case maker.Action != taker.Action && maker.Outcome == taker.Outcome:
		err = next.applyTransfer(maker, taker, quantity, amounts)
	case maker.Action == ActionSell && taker.Action == ActionSell && maker.Outcome != taker.Outcome:
		err = next.applyMergeMatch(maker, taker, quantity, amounts)
	default:
		err = errors.New("order pair has no collateral-conserving match semantics")
	}
	if err != nil {
		return MatchAmounts{}, err
	}
	after, err := next.TotalBacking()
	if err != nil || before != after {
		return MatchAmounts{}, errors.New("match violated total backing conservation")
	}
	if err := next.CheckInvariants(); err != nil {
		return MatchAmounts{}, err
	}
	*model = *next
	return amounts, nil
}

// Finalize atomically converts K into the mutually exclusive payout-liability
// representation. It does not pay or burn any individual account position.
func (model *ReferenceModel) Finalize(finalOutcome Outcome) error {
	if model.Finalized || !finalOutcome.valid() || (finalOutcome == OutcomeInvalid && model.LotPayout%2 != 0) {
		return errors.New("invalid or repeated finalization")
	}
	if err := model.CheckInvariants(); err != nil {
		return err
	}
	next := model.clone()
	next.Finalized = true
	next.FinalOutcome = finalOutcome
	next.FinalBacking = next.LockedCollateral
	next.RemainingPayoutLiability = next.LockedCollateral
	next.LockedCollateral = 0
	if err := next.CheckInvariants(); err != nil {
		return err
	}
	*model = *next
	return nil
}

// Claim converts one owner's outcome positions into free balance. Claim order
// cannot affect aggregate payouts or solvency.
func (model *ReferenceModel) Claim(owner string) (uint64, error) {
	if !model.Finalized {
		return 0, errors.New("market is not finalized")
	}
	next := model.clone()
	account, ok := next.Accounts[owner]
	if !ok {
		return 0, errors.New("unknown claim account")
	}
	var lots, unit uint64
	switch next.FinalOutcome {
	case OutcomeYes:
		lots, unit = account.YesLots, next.LotPayout
	case OutcomeNo:
		lots, unit = account.NoLots, next.LotPayout
	case OutcomeInvalid:
		var addOK bool
		lots, addOK = add64(account.YesLots, account.NoLots)
		if !addOK {
			return 0, errors.New("position overflow during invalid payout")
		}
		unit = next.LotPayout / 2
	}
	payout, payoutOK := mul64(lots, unit)
	free, freeOK := add64(account.Free, payout)
	claimed, claimedOK := add64(next.CumulativeClaimedPayout, payout)
	if !payoutOK || !freeOK || !claimedOK || next.RemainingPayoutLiability < payout {
		return 0, errors.New("claim arithmetic or solvency failure")
	}
	account.Free, account.YesLots, account.NoLots = free, 0, 0
	next.Accounts[owner] = account
	next.RemainingPayoutLiability -= payout
	next.CumulativeClaimedPayout = claimed
	if err := next.CheckInvariants(); err != nil {
		return 0, err
	}
	*model = *next
	return payout, nil
}

func orderAcceptsPrice(order PredictionOrderV1, yesPrice, noPrice uint16) bool {
	price := yesPrice
	if order.Outcome == OutcomeNo {
		price = noPrice
	}
	if order.Action == ActionBuy {
		return price <= order.LimitPriceTick
	}
	return price >= order.LimitPriceTick
}

func (model *ReferenceModel) applyMint(maker, taker PredictionOrderV1, quantity uint64, amounts MatchAmounts) error {
	for _, order := range []PredictionOrderV1{maker, taker} {
		account := model.Accounts[order.OwnerAddress]
		debit := amounts.YesValue
		if order.Outcome == OutcomeNo {
			debit = amounts.NoValue
		}
		if account.Free < debit {
			return errors.New("buyer has insufficient free collateral")
		}
		account.Free -= debit
		if order.Outcome == OutcomeYes {
			var ok bool
			account.YesLots, ok = add64(account.YesLots, quantity)
			if !ok {
				return errors.New("YES position overflow")
			}
		} else {
			var ok bool
			account.NoLots, ok = add64(account.NoLots, quantity)
			if !ok {
				return errors.New("NO position overflow")
			}
		}
		model.Accounts[order.OwnerAddress] = account
	}
	sets, setsOK := add64(model.CompleteSets, quantity)
	locked, lockedOK := add64(model.LockedCollateral, amounts.Notional)
	if !setsOK || !lockedOK {
		return errors.New("mint backing overflow")
	}
	model.CompleteSets, model.LockedCollateral = sets, locked
	return nil
}

func (model *ReferenceModel) applyTransfer(maker, taker PredictionOrderV1, quantity uint64, amounts MatchAmounts) error {
	buyer, seller := maker, taker
	if buyer.Action != ActionBuy {
		buyer, seller = taker, maker
	}
	value := amounts.YesValue
	if buyer.Outcome == OutcomeNo {
		value = amounts.NoValue
	}
	buyAccount, sellAccount := model.Accounts[buyer.OwnerAddress], model.Accounts[seller.OwnerAddress]
	if buyAccount.Free < value {
		return errors.New("buyer has insufficient free balance")
	}
	sellerFree, ok := add64(sellAccount.Free, value)
	if !ok {
		return errors.New("seller free-balance overflow")
	}
	buyAccount.Free -= value
	sellAccount.Free = sellerFree
	if buyer.Outcome == OutcomeYes {
		if sellAccount.YesLots < quantity {
			return errors.New("seller has insufficient YES position")
		}
		buyAccount.YesLots, ok = add64(buyAccount.YesLots, quantity)
		sellAccount.YesLots -= quantity
	} else {
		if sellAccount.NoLots < quantity {
			return errors.New("seller has insufficient NO position")
		}
		buyAccount.NoLots, ok = add64(buyAccount.NoLots, quantity)
		sellAccount.NoLots -= quantity
	}
	if !ok {
		return errors.New("buyer position overflow")
	}
	model.Accounts[buyer.OwnerAddress], model.Accounts[seller.OwnerAddress] = buyAccount, sellAccount
	return nil
}

func (model *ReferenceModel) applyMergeMatch(maker, taker PredictionOrderV1, quantity uint64, amounts MatchAmounts) error {
	for _, order := range []PredictionOrderV1{maker, taker} {
		account := model.Accounts[order.OwnerAddress]
		credit := amounts.YesValue
		if order.Outcome == OutcomeNo {
			credit = amounts.NoValue
		}
		var ok bool
		account.Free, ok = add64(account.Free, credit)
		if !ok {
			return errors.New("seller free-balance overflow")
		}
		if order.Outcome == OutcomeYes {
			if account.YesLots < quantity {
				return errors.New("seller has insufficient YES position")
			}
			account.YesLots -= quantity
		} else {
			if account.NoLots < quantity {
				return errors.New("seller has insufficient NO position")
			}
			account.NoLots -= quantity
		}
		model.Accounts[order.OwnerAddress] = account
	}
	if model.CompleteSets < quantity || model.LockedCollateral < amounts.Notional {
		return errors.New("merge match exceeds complete-set backing")
	}
	model.CompleteSets -= quantity
	model.LockedCollateral -= amounts.Notional
	return nil
}

func (model *ReferenceModel) CheckInvariants() error {
	if model.Finalized {
		total, ok := add64(model.RemainingPayoutLiability, model.CumulativeClaimedPayout)
		if !ok || total != model.FinalBacking || model.LockedCollateral != 0 {
			return errors.New("final payout-liability conservation violated")
		}
		return nil
	}
	var yesTotal, noTotal uint64
	for _, account := range model.Accounts {
		var ok bool
		yesTotal, ok = add64(yesTotal, account.YesLots)
		if !ok {
			return errors.New("aggregate YES overflow")
		}
		noTotal, ok = add64(noTotal, account.NoLots)
		if !ok {
			return errors.New("aggregate NO overflow")
		}
	}
	if yesTotal != model.CompleteSets || noTotal != model.CompleteSets {
		return errors.New("conditional-position conservation violated")
	}
	expected, ok := mul64(model.CompleteSets, model.LotPayout)
	if !ok || expected != model.LockedCollateral {
		return errors.New("locked collateral does not back every complete set")
	}
	return nil
}

func (model *ReferenceModel) TotalBacking() (uint64, error) {
	total := model.LockedCollateral
	if model.Finalized {
		total = model.RemainingPayoutLiability
	}
	for _, account := range model.Accounts {
		var ok bool
		total, ok = add64(total, account.Free)
		if !ok {
			return 0, errors.New("total backing overflow")
		}
	}
	return total, nil
}

func (model *ReferenceModel) clone() *ReferenceModel {
	result := &ReferenceModel{LotPayout: model.LotPayout, CompleteSets: model.CompleteSets,
		LockedCollateral: model.LockedCollateral, Finalized: model.Finalized, FinalOutcome: model.FinalOutcome,
		FinalBacking: model.FinalBacking, RemainingPayoutLiability: model.RemainingPayoutLiability,
		CumulativeClaimedPayout: model.CumulativeClaimedPayout, Accounts: make(map[string]AccountBalance, len(model.Accounts))}
	for owner, account := range model.Accounts {
		result.Accounts[owner] = account
	}
	return result
}

func add64(left, right uint64) (uint64, bool) {
	result, carry := bits.Add64(left, right, 0)
	return result, carry == 0
}

func mul64(left, right uint64) (uint64, bool) {
	high, low := bits.Mul64(left, right)
	return low, high == 0
}
