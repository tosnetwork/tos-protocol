package predictionmarket

import (
	"testing"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func FuzzPredictionDecoders(f *testing.F) {
	order, err := BuildPredictionOrderCell(testOrder())
	if err != nil {
		f.Fatal(err)
	}
	signed, _, err := SignPredictionOrder(testOrder(), testPrivateKey())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(order.ToBOC())
	f.Add(signed.ToBOC())
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			t.Skip()
		}
		root, err := cell.FromBOC(raw)
		if err != nil {
			return
		}
		_, _ = DecodePredictionOrderV1(root)
		_, _ = DecodeAndVerifySignedPredictionOrder(root)
		_, _ = DecodePredictionEvidenceManifestV1(root)
		_, _ = DecodePredictionChallengeEvidenceManifestV1(root)
		_, _ = DecodePredictionNormalContextV1(root)
		_, _ = DecodePredictionReviewBaseContextV1(root)
		_, _ = DecodePredictionReviewVoteContextV1(root)
		_, _ = DecodePredictionResolutionStatementV1(root)
	})
}
