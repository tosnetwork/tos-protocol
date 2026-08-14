package toschain

import (
	"testing"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
)

func TestRawTransactionAcceptsNodeFeeMetadata(t *testing.T) {
	const response = `{
		"@type":"raw.transaction",
		"block_id":{"@type":"tos.blockIdExt","workchain":0,"shard":"0","seqno":1,"root_hash":"root","file_hash":"file"},
		"data":"boc",
		"fee":"123",
		"in_msg_hash":"message",
		"utime":1,
		"transaction_id":{"@type":"internal.transactionId","lt":"2","hash":"hash"},
		"account":"account"
	}`
	var transaction rawTransaction
	if err := jsonstrict.Decode([]byte(response), &transaction); err != nil {
		t.Fatalf("decode live-node raw transaction shape: %v", err)
	}
	if transaction.Fee != "123" || transaction.InMsgHash != "message" {
		t.Fatalf("fee metadata was not preserved: %+v", transaction)
	}
}
