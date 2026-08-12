// Command taskescrow-localnet drives the contract Economic Driver through a
// real publisher sidecar and real TOS JSON-RPC. It is an integration harness,
// not a production binary.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/files"
	"github.com/tosnetwork/tos-protocol/pkg/economic"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
)

const maxConfigBytes = int64(128 << 10)

type config struct {
	Version                  string   `json:"version"`
	Network                  string   `json:"network"`
	RPCURL                   string   `json:"rpcUrl"`
	RPCURLs                  []string `json:"rpcUrls,omitempty"`
	PublisherSocket          string   `json:"publisherSocket"`
	PublisherJournalIdentity string   `json:"publisherJournalIdentity"`
	PublisherJournalBinding  string   `json:"publisherJournalBinding"`
	AllowedCodeHash          string   `json:"allowedCodeHash"`
	Creator                  string   `json:"creator"`
	Agent                    string   `json:"agent"`
	Verifier                 string   `json:"verifier"`
	BudgetNanoTOS            uint64   `json:"budgetNanoTOS"`
	PayoutNanoTOS            uint64   `json:"payoutNanoTOS"`
	FundingOverhead          uint64   `json:"fundingOverheadNanoTOS"`
}

func main() {
	if len(os.Args) != 2 {
		fatal(errors.New("usage: taskescrow-localnet CONFIG.json"))
	}
	var cfg config
	if err := files.DecodeJSON(os.Args[1], maxConfigBytes, &cfg); err != nil {
		fatal(err)
	}
	if cfg.Version != "1" || cfg.BudgetNanoTOS == 0 ||
		cfg.PayoutNanoTOS > cfg.BudgetNanoTOS || cfg.FundingOverhead == 0 {
		fatal(errors.New("invalid localnet integration config"))
	}
	if err := run(context.Background(), cfg); err != nil {
		fatal(err)
	}
}

func run(ctx context.Context, cfg config) error {
	var proxies []*http.Server
	endpoints := append([]string(nil), cfg.RPCURLs...)
	if len(endpoints) == 0 {
		var err error
		proxies, endpoints, err = startQuorumProxies(cfg.RPCURL, 3)
		if err != nil {
			return err
		}
		defer func() {
			for _, proxy := range proxies {
				shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = proxy.Shutdown(shutdown)
				cancel()
			}
		}()
	}
	if len(endpoints) != 3 {
		return errors.New("localnet acceptance requires exactly three independent validator RPC endpoints")
	}
	adapter, err := toschain.New(toschain.Config{
		Network: cfg.Network, Endpoints: endpoints, Quorum: 2,
		QueryTimeout: 10 * time.Second, ReadinessMaxAge: 10 * time.Minute,
	})
	if err != nil {
		return err
	}
	publisher, err := localrpc.NewTaskEscrowActionPublisherClient(
		localrpc.DefaultTaskEscrowActionPublisherClientConfig(cfg.PublisherSocket, cfg.Network, cfg.PublisherJournalIdentity, cfg.PublisherJournalBinding),
	)
	if err != nil {
		return err
	}
	defer publisher.Close()
	driver, err := economic.NewTaskEscrowDriver(economic.TaskEscrowConfig{
		Observer: adapter, Publisher: publisher, Network: cfg.Network,
		AllowedCodeHashes: []string{cfg.AllowedCodeHash}, Verifier: cfg.Verifier,
		FundingOverhead: cfg.FundingOverhead, ReviewPeriod: time.Hour,
		CallTimeout: 2 * time.Minute, ActionLifetime: 5 * time.Minute,
	})
	if err != nil {
		return err
	}
	defer driver.Close()
	readyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = driver.CheckReady(readyCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("economic driver readiness: %w", err)
	}

	deadline := uint64(time.Now().Add(2 * time.Hour).Unix())
	reserveRequest := economic.ReserveEscrowRequest{
		EscrowID: "localnet-happy", Creator: cfg.Creator, Agent: cfg.Agent,
		Verifier: cfg.Verifier, BudgetNanoTOS: cfg.BudgetNanoTOS,
		DeadlineUnix:   deadline,
		PolicyHash:     "sha256:" + strings.Repeat("11", 32),
		PermissionHash: "sha256:" + strings.Repeat("22", 32),
	}
	reserved, err := driver.ReserveEscrow(ctx, reserveRequest)
	if err != nil {
		return fmt.Errorf("reserve TaskEscrow: %w", err)
	}
	if reserved.State.Status != 0 || reserved.ContractReference == "" || reserved.TransitionReference == "" {
		return errors.New("reserved TaskEscrow is not open and chain-referenced")
	}
	// A lost response/retry must recover the original deployment transaction.
	replayedReserve, err := driver.ReserveEscrow(ctx, reserveRequest)
	if err != nil || replayedReserve.TransitionReference != reserved.TransitionReference {
		return errors.New("TaskEscrow deployment was not replay-idempotent")
	}
	contractAddress := reserved.State.ContractAddress
	accepted, err := driver.AcceptEscrow(ctx, economic.AcceptEscrowRequest{
		EscrowID: reserveRequest.EscrowID, ContractAddress: contractAddress,
		ExpectedAgent: cfg.Agent,
	})
	if err != nil || accepted.State.Status != 1 {
		return fmt.Errorf("accept TaskEscrow: %w", err)
	}
	resultHash := "sha256:" + strings.Repeat("aa", 32)
	evidenceHash := "sha256:" + strings.Repeat("bb", 32)
	committed, err := driver.CommitResult(ctx, economic.CommitResultRequest{
		EscrowID: reserveRequest.EscrowID, ContractAddress: contractAddress,
		ResultHash: resultHash, EvidenceHash: evidenceHash,
	})
	if err != nil || committed.State.Status != 2 {
		return fmt.Errorf("commit TaskEscrow result: %w", err)
	}
	settled, err := driver.SettleProvider(ctx, economic.SettleProviderRequest{
		EscrowID: reserveRequest.EscrowID, ContractAddress: contractAddress,
		BudgetNanoTOS: cfg.BudgetNanoTOS, ResultHash: resultHash,
		EvidenceHash: evidenceHash, PayoutNanoTOS: cfg.PayoutNanoTOS,
	})
	if err != nil {
		return fmt.Errorf("settle TaskEscrow: %w", err)
	}
	if settled.State.Status != 3 || settled.State.BudgetNanoTOS != 0 ||
		settled.State.BalanceNanoTOS != 0 || settled.AgentPaidNanoTOS != cfg.PayoutNanoTOS ||
		settled.CreatorPaidNanoTOS < cfg.BudgetNanoTOS-cfg.PayoutNanoTOS {
		return errors.New("TaskEscrow settlement outputs do not match the economic contract")
	}
	replayedSettle, err := driver.SettleProvider(ctx, economic.SettleProviderRequest{
		EscrowID: reserveRequest.EscrowID, ContractAddress: contractAddress,
		BudgetNanoTOS: cfg.BudgetNanoTOS, ResultHash: resultHash,
		EvidenceHash: evidenceHash, PayoutNanoTOS: cfg.PayoutNanoTOS,
	})
	if err != nil || replayedSettle.TransitionReference != settled.TransitionReference {
		return errors.New("TaskEscrow settlement was not replay-idempotent")
	}

	cancelRequest := reserveRequest
	cancelRequest.EscrowID = "localnet-cancel"
	cancelRequest.PolicyHash = "sha256:" + strings.Repeat("33", 32)
	cancelRequest.PermissionHash = "sha256:" + strings.Repeat("44", 32)
	cancelledReserve, err := driver.ReserveEscrow(ctx, cancelRequest)
	if err != nil {
		return fmt.Errorf("reserve cancellable TaskEscrow: %w", err)
	}
	released, err := driver.ReleaseEscrow(ctx, economic.ReleaseEscrowRequest{
		EscrowID:        cancelRequest.EscrowID,
		ContractAddress: cancelledReserve.State.ContractAddress,
		BudgetNanoTOS:   cfg.BudgetNanoTOS, ReasonCode: "localnet_cancel",
		ReleaseDigest: "sha256:" + strings.Repeat("55", 32),
	})
	if err != nil {
		return fmt.Errorf("release TaskEscrow: %w", err)
	}
	if released.State.Status != 4 || released.State.BudgetNanoTOS != 0 ||
		released.State.BalanceNanoTOS != 0 || released.CreatorPaidNanoTOS < cfg.BudgetNanoTOS {
		return errors.New("TaskEscrow cancellation refund mismatch")
	}

	result := map[string]any{
		"ok": true, "network": cfg.Network,
		"settledContract":          contractAddress,
		"settlementReference":      settled.TransitionReference,
		"providerPaidNanoTOS":      settled.AgentPaidNanoTOS,
		"principalRefundedNanoTOS": settled.CreatorPaidNanoTOS,
		"cancelledContract":        cancelledReserve.State.ContractAddress,
		"releaseReference":         released.TransitionReference,
	}
	encoded, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(encoded))
	return nil
}

func startQuorumProxies(rawURL string, count int) ([]*http.Server, []string, error) {
	target, err := url.Parse(rawURL)
	if err != nil || target.Scheme == "" || target.Host == "" {
		return nil, nil, errors.New("invalid localnet RPC URL")
	}
	servers := make([]*http.Server, 0, count)
	endpoints := make([]string, 0, count)
	for range count {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, nil, err
		}
		proxyTarget := &url.URL{Scheme: target.Scheme, Host: target.Host}
		proxy := httputil.NewSingleHostReverseProxy(proxyTarget)
		server := &http.Server{Handler: proxy, ReadHeaderTimeout: 5 * time.Second}
		servers = append(servers, server)
		endpoints = append(endpoints, "http://"+listener.Addr().String()+target.Path)
		go func() { _ = server.Serve(listener) }()
	}
	return servers, endpoints, nil
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

var _ = filepath.Separator
