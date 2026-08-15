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
journal, err := buyersdk.NewFileBudgetJournal("/var/lib/tos-service-buyer/budget")
if err != nil { /* fail closed */ }

chain, err := toschain.New(toschain.Config{
    Network: networkDomain.NetworkId,
    Endpoints: []string{nodeA, nodeB, nodeC},
    Quorum: 2,
})
if err != nil { /* fail closed */ }
locator, err := nativecore.NewLocator(
    networkDomain,
    0,
    reviewedRegistryCodeBOCBase64,
    registryCodeHash,
)
if err != nil { /* fail closed */ }
nativeResolver, err := toschain.NewSimplifiedNativeResolver(
    chain,
    locator,
    "/var/lib/tos-service-buyer/native.checkpoint",
)
if err != nil { /* fail closed */ }
nativeClient, err := toschain.NewDirectNativeClient(nativeResolver)
if err != nil { /* fail closed */ }
assetResolver, err := toschain.NewStablecoinResolver(
    chain,
    networkDomain,
    "/var/lib/tos-service-buyer/stablecoin.checkpoint",
)
if err != nil { /* fail closed */ }

buyer, err := buyersdk.New(buyersdk.Config{
    NativeClient: nativeClient,
    AssetResolver: assetResolver,
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

`DirectNativeClient` is an in-process interface adapter, not another resolver.
The authoritative result still comes from `SimplifiedNativeResolver` reading
typed Registry state at a strict-majority finalized TOS checkpoint. Deployments
may instead supply the authenticated Connect client when process separation is
required; both paths apply the same SDK verification and neither makes the
gateway authoritative.

For local `tosctl` custody, construct the production sender with pinned,
owner-controlled absolute paths:

```go
custodySender, err := buyersdk.NewTOSCTLFundingSender(
    buyersdk.TOSCTLFundingSenderConfig{
        BinaryPath: "/opt/tos/bin/tosctl",
        ConfigPath: "/var/lib/tos-service-buyer/tosctl.json",
        WalletName: "buyer",
        AttachedNanoTOS: 100_000_000,
        ForwardNanoTOS: 50_000_000,
    },
)
if err != nil { /* fail closed */ }
```

The executable must be a non-writable regular executable owned by root or the
current user. The config must be an owner-only regular file owned by the
current user. The sender never receives mnemonic or private-key material.

The directory must already exist, be owned by the process user, and have mode
`0700`. Journal records are owner-only regular files. The limits use exact
base-10 atomic units and are enforced per exact TOS stablecoin identity.
The stablecoin resolver reads the authenticated master and the buyer's
deterministically derived wallet at one quorum-finalized checkpoint. It obtains
the wallet-code preimage from the reviewed master contract, checks both code
hashes, owner, master, unlocked status, exact balance, network genesis, and a
durable monotonic checkpoint. It does not resolve assets by ticker or trust a
gateway-projected balance.

Prepare the purchase from the received Quote Proposal and independently
retrieved manifest. `ManifestJSON` is accepted for a locally authored strict
projection; use `ManifestCBOR` for the exact bytes returned by
`GetSoftwareWorkManifest` (set exactly one of them):

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

`TOSCTLFundingSender` builds the exact stablecoin transfer body and asks
`tosctl wallet send --build-only` to construct and sign one external message.
It verifies the payer, stablecoin wallet, attached nanoTOS, body hash, absence
of StateInit, and complete signed-message BOC before the journal grants its
one-way broadcast lease. It then submits those exact bytes with
`tosctl wallet broadcast-prepared`; it does not rebuild or re-sign after the
lease. A gateway, Quote service, index, or relayer may transport bytes, but
none may override the SDK's finalized-state checks or budget journal.
