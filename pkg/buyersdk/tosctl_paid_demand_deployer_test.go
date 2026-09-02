package buyersdk

import (
	"slices"
	"testing"
)

func TestPaidDemandDeployerManualBroadcastAcknowledgementIsExplicit(t *testing.T) {
	deployer := &TOSCTLPaidDemandEscrowDeployer{config: "/private/config.json"}
	arguments := deployer.broadcastArguments("message-boc")
	if slices.Contains(arguments, "--acknowledge-unpinned-manual-broadcast") {
		t.Fatal("default Paid Demand deployment acknowledged an unpinned manual broadcast")
	}

	deployer.acknowledgeUnpinnedManualBroadcast = true
	arguments = deployer.broadcastArguments("message-boc")
	if !slices.Contains(arguments, "--acknowledge-unpinned-manual-broadcast") {
		t.Fatal("explicit test/operator acknowledgement was not forwarded to tosctl")
	}
}
