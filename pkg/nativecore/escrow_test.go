package nativecore

import (
	"encoding/base64"
	"math/big"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

func escrowDataWithRuntime(t *testing.T, original *cell.Cell, status uint8, funded, settled uint64, receipt []byte, pending uint64) *cell.Cell {
	t.Helper()
	s := original.BeginParse()
	s.MustLoadUInt(32)
	s.MustLoadUInt(16)
	s.MustLoadUInt(8)
	quoteHash := s.MustLoadSlice(256)
	termsHash := s.MustLoadSlice(256)
	authHash := s.MustLoadSlice(256)
	quote, _ := s.LoadRefCell()
	terms, _ := s.LoadRefCell()
	authorization, _ := s.LoadRefCell()
	oldRuntime, _ := s.LoadRefCell()
	r := oldRuntime.BeginParse()
	r.MustLoadUInt(32)
	r.MustLoadUInt(16)
	r.MustLoadBigUInt(128)
	r.MustLoadBigUInt(128)
	r.MustLoadSlice(256)
	r.MustLoadUInt(64)
	route, _ := r.LoadRefCell()
	transport, _ := r.LoadRefCell()
	dispute, _ := r.LoadRefCell()
	runtime := cell.BeginCell().MustStoreUInt(escrowRuntimeMagic, 32).MustStoreUInt(escrowSchema, 16).
		MustStoreBigUInt(new(big.Int).SetUint64(funded), 128).
		MustStoreBigUInt(new(big.Int).SetUint64(settled), 128).
		MustStoreSlice(receipt, 256).MustStoreUInt(pending, 64).MustStoreRef(route).
		MustStoreRef(transport).MustStoreRef(dispute).EndCell()
	return cell.BeginCell().MustStoreUInt(escrowDataMagic, 32).MustStoreUInt(escrowSchema, 16).
		MustStoreUInt(uint64(status), 8).MustStoreSlice(quoteHash, 256).MustStoreSlice(termsHash, 256).
		MustStoreSlice(authHash, 256).MustStoreRef(quote).MustStoreRef(terms).
		MustStoreRef(authorization).MustStoreRef(runtime).EndCell()
}

func testRawAddress(t *testing.T, friendly string) string {
	t.Helper()
	value, err := address.ParseAddr(friendly)
	if err != nil {
		t.Fatal(err)
	}
	return value.StringRaw()
}

func testEscrowQuote(t *testing.T, terms EscrowTermsV1, signer []byte, walletCode *cell.Cell) (*cell.Cell, string) {
	t.Helper()
	termsCell, err := BuildEscrowTermsCellV1(terms)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := BuildEscrowAuthorizationCellV1(signer)
	if err != nil {
		t.Fatal(err)
	}
	transport := testEscrowTransport()
	_, transportDigest, err := BuildTransportBindingCellV1(transport)
	if err != nil {
		t.Fatal(err)
	}
	_, disputeDigest := BuildObjectiveDisputePolicyCellV1()
	network := &nativev1.NetworkDomain{
		NetworkId: "tos-escrow-test", GenesisRootHash: "sha256:" + strings.Repeat("11", 32),
		GenesisFileHash: "sha256:" + strings.Repeat("22", 32),
	}
	proposal := &nativev1.QuoteProposalV1{
		CapabilityId: "cap_" + strings.Repeat("33", 32), CapabilityVersion: "1.0.0",
		ProviderAgentId: "agent_" + strings.Repeat("44", 32), ManifestDigest: "sha256:" + strings.Repeat("55", 32),
		TransportBindingDigest: transportDigest, ExpiresAtUnixSeconds: terms.FundingDeadline,
		EscrowTermsDigest:   "sha256:" + strings.TrimPrefix(digestString(termsCell.Hash()), "tvm-cell-sha256:"),
		DisputePolicyDigest: disputeDigest,
		MaximumPrice: &nativev1.MoneyV1{AtomicAmount: "25000000", Asset: &nativev1.TOSAssetIdentityV1{
			Master:         &nativev1.TOSContractIdentityV1{Workchain: 0, AccountId: []byte(strings.Repeat("m", 32)), CodeHash: "tvm-cell-sha256:" + strings.Repeat("88", 32)},
			WalletCodeHash: digestString(walletCode.Hash()), Decimals: 6,
		}},
	}
	quote, _, err := BuildAcceptedQuoteCommitment(network, proposal,
		"sha256:"+strings.TrimPrefix(digestString(authorization.Hash()), "tvm-cell-sha256:"))
	if err != nil {
		t.Fatal(err)
	}
	return quote, address.NewAddress(0, 0, []byte(strings.Repeat("m", 32))).StringRaw()
}

func testEscrowTransport() TransportBindingV1 {
	return TransportBindingV1{SecurityMode: TransportLoopbackHTTP, MaxRequestBytes: 16 << 20, BaseURL: "http://127.0.0.1:8080"}
}

func TestEscrowStateInitRoundTrip(t *testing.T) {
	terms := EscrowTermsV1{
		BuyerAddress:    testRawAddress(t, "EQBjK7o8stJ-pMAnTBApq9i0fBQOdXmZCvZNAdI5x55ime5W"),
		ProviderAddress: testRawAddress(t, "EQCjpcsMfVKfcm1eCOZ0F28f_db-jUire_GuCGyLzKp1qCrW"),
		FundingDeadline: 1786752000, RefundAvailableAt: 1786755600,
	}
	signer := []byte(strings.Repeat("s", 32))
	walletCode := cell.BeginCell().MustStoreUInt(0x12345678, 32).EndCell()
	quote, master := testEscrowQuote(t, terms, signer, walletCode)
	code := cell.BeginCell().MustStoreUInt(0xabcdef01, 32).EndCell()

	identity, err := BuildEscrowStateInitV1(0, code, EscrowInitV1{
		AcceptedQuote: quote, Terms: terms, ExecutionSignerEd25519: signer,
		TransportBinding:   testEscrowTransport(),
		AssetMasterAddress: master, AssetWalletCode: walletCode,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(identity.Address, "0:") || identity.QuoteCommitment != digestString(quote.Hash()) {
		t.Fatalf("unexpected identity: %+v", identity)
	}
	if _, err := base64.StdEncoding.DecodeString(identity.StateInitBOC); err != nil {
		t.Fatalf("invalid StateInit BOC: %v", err)
	}
	decoded, err := DecodeEscrowDataV1(identity.Data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Status != EscrowStatusAwaitingFunding || decoded.BuyerAddress != terms.BuyerAddress ||
		decoded.ProviderAddress != terms.ProviderAddress || decoded.AssetMasterAddress != master ||
		decoded.AssetWalletCodeHash != digestString(walletCode.Hash()) ||
		decoded.FundedAtomicAmount != "0" || decoded.SettledAtomicAmount != "0" ||
		string(decoded.ExecutionSignerEd25519) != string(signer) {
		t.Fatalf("unexpected decoded escrow: %+v", decoded)
	}
	walletAddress, err := DeriveEscrowAssetWalletV1(identity.Address, decoded)
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := address.ParseRawAddr(identity.Address)
	masterAddress, _ := address.ParseRawAddr(master)
	walletData := cell.BeginCell().MustStoreUInt(0, 4).MustStoreCoins(0).
		MustStoreAddr(owner).MustStoreAddr(masterAddress).EndCell()
	walletInit := cell.BeginCell().MustStoreBoolBit(false).MustStoreBoolBit(false).
		MustStoreBoolBit(true).MustStoreRef(walletCode).MustStoreBoolBit(true).
		MustStoreRef(walletData).MustStoreBoolBit(false).EndCell()
	expectedWallet := address.NewAddress(0, 0, walletInit.Hash()).StringRaw()
	if walletAddress != expectedWallet {
		t.Fatalf("derived escrow wallet = %s, want %s", walletAddress, expectedWallet)
	}
}

func TestEscrowStateInitRejectsOpaqueQuoteDigests(t *testing.T) {
	terms := EscrowTermsV1{
		BuyerAddress:    testRawAddress(t, "EQBjK7o8stJ-pMAnTBApq9i0fBQOdXmZCvZNAdI5x55ime5W"),
		ProviderAddress: testRawAddress(t, "EQCjpcsMfVKfcm1eCOZ0F28f_db-jUire_GuCGyLzKp1qCrW"),
		FundingDeadline: 1786752000, RefundAvailableAt: 1786755600,
	}
	signer := []byte(strings.Repeat("s", 32))
	walletCode := cell.BeginCell().MustStoreUInt(0x12345678, 32).EndCell()
	quote, master := testEscrowQuote(t, terms, signer, walletCode)
	changed := terms
	changed.RefundAvailableAt++
	_, err := BuildEscrowStateInitV1(0, cell.BeginCell().EndCell(), EscrowInitV1{
		AcceptedQuote: quote, Terms: changed, ExecutionSignerEd25519: signer,
		TransportBinding:   testEscrowTransport(),
		AssetMasterAddress: master, AssetWalletCode: walletCode,
	})
	if err == nil || !strings.Contains(err.Error(), "terms do not match") {
		t.Fatalf("expected terms mismatch, got %v", err)
	}
}

func TestEscrowDecoderAcceptsOnlyCoherentTerminalAndPendingStates(t *testing.T) {
	terms := EscrowTermsV1{
		BuyerAddress:    testRawAddress(t, "EQBjK7o8stJ-pMAnTBApq9i0fBQOdXmZCvZNAdI5x55ime5W"),
		ProviderAddress: testRawAddress(t, "EQCjpcsMfVKfcm1eCOZ0F28f_db-jUire_GuCGyLzKp1qCrW"),
		FundingDeadline: 1786752000, RefundAvailableAt: 1786755600,
	}
	signer := []byte(strings.Repeat("s", 32))
	walletCode := cell.BeginCell().MustStoreUInt(0x12345678, 32).EndCell()
	quote, master := testEscrowQuote(t, terms, signer, walletCode)
	identity, err := BuildEscrowStateInitV1(0, cell.BeginCell().EndCell(), EscrowInitV1{
		AcceptedQuote: quote, Terms: terms, ExecutionSignerEd25519: signer,
		TransportBinding:   testEscrowTransport(),
		AssetMasterAddress: master, AssetWalletCode: walletCode,
	})
	if err != nil {
		t.Fatal(err)
	}
	zero, receipt := make([]byte, 32), []byte(strings.Repeat("r", 32))
	for _, test := range []struct {
		name        string
		status      uint8
		settled     uint64
		receipt     []byte
		pending     uint64
		wantReceipt bool
	}{
		{"funded", EscrowStatusFunded, 0, zero, 0, false},
		{"release pending", EscrowStatusReleasePending, 25_000_000, receipt, 9, true},
		{"refund pending", EscrowStatusRefundPending, 0, zero, 11, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := escrowDataWithRuntime(t, identity.Data, test.status, 25_000_000, test.settled, test.receipt, test.pending)
			state, err := DecodeEscrowDataV1(data)
			if err != nil {
				t.Fatal(err)
			}
			if state.Status != test.status || state.PendingQueryID != test.pending ||
				(test.wantReceipt && state.ReceiptCommitment != digestString(receipt)) {
				t.Fatalf("unexpected state: %+v", state)
			}
		})
	}
	invalid := escrowDataWithRuntime(t, identity.Data, EscrowStatusFunded, 25_000_000, 0, zero, 1)
	if _, err := DecodeEscrowDataV1(invalid); err == nil {
		t.Fatal("accepted funded state with a pending query")
	}
}

func TestEscrowDecoderRejectsForgedRootCommitment(t *testing.T) {
	terms := EscrowTermsV1{
		BuyerAddress:    testRawAddress(t, "EQBjK7o8stJ-pMAnTBApq9i0fBQOdXmZCvZNAdI5x55ime5W"),
		ProviderAddress: testRawAddress(t, "EQCjpcsMfVKfcm1eCOZ0F28f_db-jUire_GuCGyLzKp1qCrW"),
		FundingDeadline: 1786752000, RefundAvailableAt: 1786755600,
	}
	signer := []byte(strings.Repeat("s", 32))
	walletCode := cell.BeginCell().MustStoreUInt(0x12345678, 32).EndCell()
	quote, master := testEscrowQuote(t, terms, signer, walletCode)
	identity, err := BuildEscrowStateInitV1(0, cell.BeginCell().EndCell(), EscrowInitV1{
		AcceptedQuote: quote, Terms: terms, ExecutionSignerEd25519: signer,
		TransportBinding:   testEscrowTransport(),
		AssetMasterAddress: master, AssetWalletCode: walletCode,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := identity.Data.BeginParse()
	s.MustLoadUInt(32)
	s.MustLoadUInt(16)
	status := s.MustLoadUInt(8)
	s.MustLoadSlice(256)
	termsHash := s.MustLoadSlice(256)
	authHash := s.MustLoadSlice(256)
	quoteRef, _ := s.LoadRefCell()
	termsRef, _ := s.LoadRefCell()
	authRef, _ := s.LoadRefCell()
	runtimeRef, _ := s.LoadRefCell()
	forged := cell.BeginCell().MustStoreUInt(escrowDataMagic, 32).MustStoreUInt(escrowSchema, 16).
		MustStoreUInt(status, 8).MustStoreSlice([]byte(strings.Repeat("x", 32)), 256).
		MustStoreSlice(termsHash, 256).MustStoreSlice(authHash, 256).MustStoreRef(quoteRef).
		MustStoreRef(termsRef).MustStoreRef(authRef).MustStoreRef(runtimeRef).EndCell()
	if _, err := DecodeEscrowDataV1(forged); err == nil || !strings.Contains(err.Error(), "commitment mismatch") {
		t.Fatalf("expected commitment mismatch, got %v", err)
	}
}
