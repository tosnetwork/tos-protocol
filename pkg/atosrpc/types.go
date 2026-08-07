package atosrpc

import atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"

type TrustMode = atostosv1.TrustMode
type NetworkReference = atostosv1.NetworkReference

const (
	TrustModeManaged  = atostosv1.TrustMode_TRUST_MODE_MANAGED
	TrustModeVerified = atostosv1.TrustMode_TRUST_MODE_VERIFIED
	TrustModeNative   = atostosv1.TrustMode_TRUST_MODE_NATIVE
)
