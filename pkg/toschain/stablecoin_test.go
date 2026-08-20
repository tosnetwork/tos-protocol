package toschain

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func TestStablecoinStateDerivesAndDecodesExactBuyerWallet(t *testing.T) {
	owner := address.NewAddress(0, 0, bytesOf(0x11))
	master := address.NewAddress(0, 0, bytesOf(0x22))
	admin := address.NewAddress(0, 0xff, bytesOf(0x33))
	walletCode := cell.BeginCell().MustStoreUInt(0xfeed, 16).EndCell()
	metadata := cell.BeginCell().MustStoreBinarySnake([]byte("data:application/json,%7B%22decimals%22%3A6%7D")).EndCell()
	masterData := cell.BeginCell().MustStoreBigCoins(stringsToBig(t, "1000000000")).
		MustStoreAddr(admin).MustStoreAddr(nil).MustStoreRef(walletCode).MustStoreRef(metadata).EndCell()
	walletHash := "tvm-cell-sha256:" + hex.EncodeToString(walletCode.Hash())
	decodedCode, err := decodeStablecoinMasterWalletCode(masterData, walletHash)
	if err != nil || !bytes.Equal(decodedCode.Hash(), walletCode.Hash()) {
		t.Fatalf("decode master wallet code: %v", err)
	}
	walletAddress, err := deriveStablecoinWalletAddress(owner, master, decodedCode)
	if err != nil || walletAddress == "" {
		t.Fatalf("derive buyer stablecoin wallet: %v", err)
	}
	walletData := cell.BeginCell().MustStoreUInt(0, 4).MustStoreBigCoins(stringsToBig(t, "75000000")).
		MustStoreAddr(owner).MustStoreAddr(master).EndCell()
	balance, err := decodeStablecoinWallet(walletData, owner.StringRaw(), master.StringRaw())
	if err != nil || balance != "75000000" {
		t.Fatalf("decode buyer balance=%s err=%v", balance, err)
	}
}

func TestStablecoinStateRejectsWrongCodeOwnerAndFrozenWallet(t *testing.T) {
	owner := address.NewAddress(0, 0, bytesOf(0x11))
	other := address.NewAddress(0, 0, bytesOf(0x12))
	master := address.NewAddress(0, 0, bytesOf(0x22))
	admin := address.NewAddress(0, 0xff, bytesOf(0x33))
	walletCode := cell.BeginCell().MustStoreUInt(1, 1).EndCell()
	masterData := cell.BeginCell().MustStoreCoins(1).MustStoreAddr(admin).MustStoreAddr(nil).
		MustStoreRef(walletCode).MustStoreRef(cell.BeginCell().EndCell()).EndCell()
	if _, err := decodeStablecoinMasterWalletCode(masterData, "tvm-cell-sha256:"+strings.Repeat("44", 32)); err == nil {
		t.Fatal("accepted a conflicting wallet code hash")
	}
	wrongOwner := cell.BeginCell().MustStoreUInt(0, 4).MustStoreCoins(1).
		MustStoreAddr(other).MustStoreAddr(master).EndCell()
	if _, err := decodeStablecoinWallet(wrongOwner, owner.StringRaw(), master.StringRaw()); err == nil {
		t.Fatal("accepted a stablecoin wallet owned by another account")
	}
	frozen := cell.BeginCell().MustStoreUInt(1, 4).MustStoreCoins(1).
		MustStoreAddr(owner).MustStoreAddr(master).EndCell()
	if _, err := decodeStablecoinWallet(frozen, owner.StringRaw(), master.StringRaw()); err == nil {
		t.Fatal("accepted a frozen buyer stablecoin wallet")
	}
}

func TestStablecoinResolverConfigurationAndIdentityFailClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	chain := &Adapter{network: "tos-test"}
	network := &nativev1.NetworkDomain{NetworkId: "tos-test"}
	if _, err := NewStablecoinResolver(chain, network, dir+"/stablecoin.checkpoint"); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStablecoinResolver(chain, &nativev1.NetworkDomain{NetworkId: "other"}, dir+"/wrong.checkpoint"); err == nil {
		t.Fatal("accepted a stablecoin resolver on the wrong network")
	}
	resolver := &StablecoinResolver{}
	if _, err := resolver.ResolveBuyerAsset(t.Context(), nil, "not-an-address"); err == nil {
		t.Fatal("accepted an invalid stablecoin identity")
	}
}

func bytesOf(value byte) []byte { return []byte(strings.Repeat(string([]byte{value}), 32)) }

func stringsToBig(t *testing.T, value string) *big.Int {
	t.Helper()
	result, ok := new(big.Int).SetString(value, 10)
	if !ok {
		t.Fatal("invalid test integer")
	}
	return result
}
