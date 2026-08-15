# Native buyer SDK

`pkg/buyersdk` is the Gate E buyer-side safety boundary for one canonical
software-work purchase. It reviews a non-canonical Quote Proposal, verifies its
manifest and finalized Capability, derives the exact Accepted Quote and escrow,
and funds only that already-deployed, finalized, awaiting-funding escrow.

The SDK does not trust a gateway response as commercial authority and does not
hold a private key. Applications supply four narrow adapters: finalized Native
resolution, finalized TOS stablecoin observation, finalized escrow resolution,
and a custody-controlled stablecoin sender.

## Prepare and review

Construct a `buyersdk.Buyer` with the exact network domain, Registry code hash,
reviewed escrow and asset-wallet code cells, buyer address, an owner-private
absolute budget-journal directory, and explicit limits:

```go
journal, err := buyersdk.NewFileBudgetJournal("/var/lib/atos-buyer/budget")
if err != nil { /* fail closed */ }

buyer, err := buyersdk.New(buyersdk.Config{
    NativeClient: nativeResolver,
    AssetResolver: stablecoinResolver,
    EscrowResolver: escrowResolver,
    FundingSender: custodySender,
    BudgetJournal: journal,
    BudgetLimits: buyersdk.BudgetLimits{
        Window: 24 * time.Hour,
        MaxPurchases: 20,
        MaxPerPurchaseAtomic: "50000000",
        MaxTotalAtomic: "250000000",
    },
    Network: networkDomain,
    RegistryCodeHash: registryCodeHash,
    BuyerAddress: buyerAddress,
    EscrowCode: reviewedEscrowCode,
    AssetWalletCode: reviewedStablecoinWalletCode,
    CallerID: buyerAgentID,
})
```

The directory must already exist, be owned by the process user, and have mode
`0700`. Journal records are owner-only regular files. The limits use exact
base-10 atomic units and are enforced per exact TOS stablecoin identity.

Prepare the purchase from the received Quote Proposal and independently
retrieved manifest:

```go
prepared, err := buyer.PreparePurchase(ctx, buyersdk.PurchaseInput{
    Proposal: proposal,
    ManifestJSON: manifestJSON,
    EscrowTerms: reviewedTerms,
    ExecutionSignerEd25519: executionSigner,
    TransportBinding: reviewedTransport,
})
if err != nil { /* reject the proposal */ }
```

Show the operator at least `ManifestDigest`, `QuoteCommitment`, escrow address,
stablecoin master, buyer wallet, and `AmountAtomic`. Deploy
`prepared.Escrow.StateInitBOC` through the normal custody boundary and wait
until the exact escrow is finalized in `awaiting_funding` state. Deployment and
funding are intentionally separate review steps.

## Fund once

After deployment, fund with a durable request retry key:

```go
funded, err := buyer.FundPurchase(ctx, prepared, idempotencyKey)
if err != nil { /* do not infer payment success from the sender result */ }
```

Immediately before spending, the SDK reconstructs the Quote and escrow,
rechecks the finalized Capability owner/version, stablecoin contract and wallet
code, finalized buyer balance, deadline, escrow state, and every immutable
commitment. The sender receives one exact `FundingIntent`, including a
deterministic nonzero query ID. Success is returned only after finalized escrow
state contains the exact funded amount.

The journal atomically reserves the time-window budget and moves through
`prepared`, `broadcasting`, and `complete`. A crash in `prepared` is safely
recoverable. Once `broadcasting` has been recorded, an uncertain result is
resolved read-only and never rebroadcast automatically. Operators must
reconcile an ambiguous payment from finalized chain state; deleting or editing
journal files is not a recovery procedure.

The first production integration must keep wallet signing in the existing
`tosctl` custody boundary. A gateway, Quote service, index, or relayer may
transport bytes, but none may override the SDK's finalized-state checks or
budget journal.
