# Non-canonical Quote Proposal exchange

`RequestQuoteProposal` asks a provider-facing Gateway for terms covering one
exact Capability version and buyer address. Its response is a transport object,
not an acceptance record.

`pkg/quoteexchange` requires the response package to carry the complete
canonical manifest CBOR and canonical single-root BOCs for escrow terms,
transport binding, and objective dispute policy. It hashes and decodes every
preimage, checks the requested Capability/version/buyer identity, bounds expiry
and package size, and proves the proposal can be encoded by the canonical
Accepted Quote builder.

The execution-signer authorization is deliberately absent: the buyer chooses
it while constructing the Accepted Quote. A Gateway cannot choose custody for
the buyer, accept terms, or make a proposal canonical. The buyer must still
resolve the Capability and asset from finalized TOS state and only recognizes
acceptance after the deterministic escrow is finalized.
