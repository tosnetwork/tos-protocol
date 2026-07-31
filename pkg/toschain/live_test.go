package toschain

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
)

// TestLiveThreeNodeAdapters is opt-in because it requires a running TOS
// network and a deployed Agent Account. CI keeps deterministic unit coverage;
// local/testnet launch gates supply these environment variables.
func TestLiveThreeNodeAdapters(t *testing.T) {
	endpointsValue := os.Getenv("TOS_CHAIN_RPC_ENDPOINTS")
	account := os.Getenv("TOS_CHAIN_AGENT_ACCOUNT")
	if endpointsValue == "" || account == "" {
		t.Skip("live TOS chain adapter environment is not configured")
	}
	serviceID := os.Getenv("TOS_CHAIN_SERVICE_ID")
	if serviceID == "" {
		serviceID = "tos-protocol-live-e2e"
	}
	network := os.Getenv("TOS_CHAIN_NETWORK")
	if network == "" {
		network = "tos-local"
	}
	endpoints := strings.Split(endpointsValue, ",")
	adapter, err := New(Config{
		Network: network, Endpoints: endpoints, Quorum: len(endpoints)/2 + 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	service, err := adapter.ResolveService(ctx, chain.ServiceReference{
		Network: network, Address: account, ServiceID: serviceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !service.Active || !service.Finalized || service.Controller == "" ||
		len(service.ControllerPublicKey) != 32 || service.ManifestDigest == "" ||
		service.CodeHash == "" || service.ObservedMasterSeqno == 0 || service.ObservedAt.IsZero() {
		t.Fatalf("incomplete live service authority: %#v", service)
	}
	authorityResolver, err := authorization.NewChainResolver(
		adapter,
		authorization.DefaultChainResolverPolicy([]string{service.CodeHash}),
	)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := authorityResolver.ResolveAuthority(ctx, authorization.Reference{
		Network: network, Address: account, ServiceID: serviceID,
		MinimumMasterSeqno: service.ObservedMasterSeqno,
	})
	if err != nil {
		t.Fatal(err)
	}
	if authority.Controller != service.Controller ||
		!bytes.Equal(authority.ControllerPublicKey, service.ControllerPublicKey) {
		t.Fatalf("live authority wrapper changed chain state: %#v", authority)
	}
	clientKeyID, err := FormatAgentClientKeyID(account, service.ControllerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := adapter.ResolveClientKey(ctx, authorization.ClientKeyReference{
		Network: network, ServiceID: serviceID, KeyID: clientKeyID,
		MinimumMasterSeqno: service.ObservedMasterSeqno,
	})
	if err != nil {
		t.Fatal(err)
	}
	if clientKey.Principal != account || !bytes.Equal(clientKey.PublicKey, service.ControllerPublicKey) ||
		clientKey.ObservedMasterSeqno < service.ObservedMasterSeqno {
		t.Fatalf("live client key does not match authority: %#v", clientKey)
	}

	paymentReference := os.Getenv("TOS_CHAIN_PAYMENT_REFERENCE")
	if paymentReference == "" {
		return
	}
	payment, err := adapter.ObservePayment(ctx, chain.PaymentReference{
		Network: network, AuthorizationID: "authorization-live-e2e",
		QuoteID: "quote-live-e2e", RequestID: "request-live-e2e",
		Reference: paymentReference, Payer: os.Getenv("TOS_CHAIN_PAYMENT_PAYER"),
		Payee: os.Getenv("TOS_CHAIN_PAYMENT_PAYEE"), AmountNanoTOS: 1_000_000_000,
		MinimumMasterSeqno: service.ObservedMasterSeqno,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !payment.Confirmed || !payment.Finalized || payment.Reorganized ||
		payment.AmountNanoTOS != 1_000_000_000 {
		t.Fatalf("invalid live payment observation: %#v", payment)
	}
}
