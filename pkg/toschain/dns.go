package toschain

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/dnsalias"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type DNSResolver struct{ chain *Adapter }

func NewDNSResolver(chain *Adapter) (*DNSResolver, error) {
	if chain == nil {
		return nil, errors.New("TOS DNS chain adapter is required")
	}
	return &DNSResolver{chain: chain}, nil
}

type dnsConfigResult struct {
	Type   string `json:"@type"`
	Config struct {
		Type  string `json:"@type"`
		Bytes string `json:"bytes"`
	} `json:"config"`
}

// The legacy stack form is used deliberately because it can represent nil and
// slices without accepting the typed endpoint's unsupported-value ambiguity.
type dnsRunResult struct {
	Type              string            `json:"@type"`
	GasUsed           int64             `json:"gas_used"`
	Stack             []json.RawMessage `json:"stack"`
	ExitCode          int32             `json:"exit_code"`
	LastTransactionID json.RawMessage   `json:"last_transaction_id"`
	BlockID           blockID           `json:"block_id"`
}

type dnsStackInput [2]any

func (r *DNSResolver) ResolveDNSAtFinalizedCheckpoint(ctx context.Context, name, categoryHash string) (*dnsalias.ChainResult, error) {
	if r == nil || ctx == nil {
		return nil, errors.New("TOS DNS resolver is not configured")
	}
	encoded, err := dnsalias.EncodeName(name)
	if err != nil {
		return nil, err
	}
	categoryBytes, err := hex.DecodeString(categoryHash)
	if err != nil || len(categoryBytes) != 32 {
		return nil, errors.New("invalid DNS category hash")
	}
	observation, nodes, err := r.chain.consensus(ctx)
	if err != nil {
		return nil, err
	}
	if err := r.chain.validateObservationTime(observation, time.Now()); err != nil {
		return nil, err
	}
	root, err := dnsRootAt(ctx, nodes, r.chain.quorum, observation.seqno)
	if err != nil {
		return nil, err
	}
	category := new(big.Int).SetBytes(categoryBytes).String()
	remaining := encoded
	current := root
	path := make([]string, 0, dnsalias.MaxResolverHops)
	seen := map[string]struct{}{}
	var checkpoint *nativev1.DNSCheckpointV1
	var record *cell.Cell
	for len(path) < dnsalias.MaxResolverHops {
		if _, duplicate := seen[current]; duplicate {
			return nil, errors.New("DNS resolver cycle")
		}
		seen[current] = struct{}{}
		path = append(path, current)
		nameCell := cell.BeginCell().MustStoreSlice(remaining, uint(len(remaining)*8)).EndCell()
		result, err := runDNSGetter(ctx, nodes, r.chain.quorum, current, observation.seqno, "dnsresolve",
			[]dnsStackInput{{"slice", map[string]string{"bytes": base64.StdEncoding.EncodeToString(nameCell.ToBOC())}}, {"num", category}})
		if err != nil {
			return nil, err
		}
		if checkpoint == nil {
			checkpoint, err = checkpointFromBlock(result.BlockID, uint64(observation.observedAt.Unix()))
			if err != nil {
				return nil, err
			}
		} else if !sameDNSBlock(checkpoint, result.BlockID) {
			return nil, errors.New("DNS getter checkpoint changed")
		}
		bits, err := stackInt(result.Stack, 0)
		if err != nil || !bits.IsUint64() {
			return nil, errors.New("invalid DNS consumed-bit count")
		}
		consumed := bits.Uint64()
		if consumed == 0 || consumed%8 != 0 || consumed > uint64(len(remaining)*8) {
			return nil, errors.New("invalid DNS consumed-bit boundary")
		}
		consumedBytes := int(consumed / 8)
		if consumedBytes < len(remaining) && remaining[consumedBytes-1] != 0 {
			return nil, errors.New("DNS resolver stopped inside a component")
		}
		data, nilValue, err := stackCell(result.Stack, 1)
		if err != nil || nilValue {
			return nil, errors.New("DNS record not found")
		}
		if consumedBytes == len(remaining) {
			record = data
			break
		}
		next, err := parseNextResolver(data)
		if err != nil {
			return nil, err
		}
		current, remaining = next, remaining[consumedBytes:]
	}
	if record == nil {
		return nil, errors.New("DNS resolver hop limit exhausted")
	}
	resolved, err := parseSMCRecord(record)
	if err != nil {
		return nil, err
	}
	if len(path) < 3 {
		return nil, errors.New("DNS path lacks canonical Domain Item")
	}
	label := secondLevelLabel(name)
	auctionEnd, lastFill, err := verifyDomainItem(ctx, nodes, r.chain.quorum, observation.seqno, checkpoint, path[2], path[1], label)
	if err != nil {
		return nil, err
	}
	if lastFill <= 0 || uint64(lastFill) > ^uint64(0)-dnsalias.LeaseSeconds {
		return nil, errors.New("invalid DNS renewal clock")
	}
	deadline := uint64(lastFill) + dnsalias.LeaseSeconds
	return &dnsalias.ChainResult{CanonicalName: name, CategoryHash: categoryHash, Resolved: resolved,
		Checkpoint: checkpoint, Lifecycle: &nativev1.DNSLifecycleV1{AuctionEndUnixSeconds: uint64(auctionEnd), LastFillUpUnixSeconds: uint64(lastFill), RenewalDeadlineUnixSeconds: deadline}, ResolverPath: path}, nil
}

func dnsRootAt(ctx context.Context, nodes []*rpcNode, quorum int, seqno uint64) (string, error) {
	value, _, err := quorumRead(ctx, nodes, quorum, func(ctx context.Context, node *rpcNode) (string, error) {
		var result dnsConfigResult
		if err := node.client.Call(ctx, "getConfigParam", struct {
			Param int    `json:"param"`
			Seqno uint64 `json:"seqno"`
		}{4, seqno}, &result); err != nil {
			return "", err
		}
		if result.Type != "configInfo" || result.Config.Type != "tvm.cell" {
			return "", errors.New("invalid ConfigParam 4 response")
		}
		raw, err := base64.StdEncoding.DecodeString(result.Config.Bytes)
		if err != nil {
			return "", err
		}
		root, err := cell.FromBOC(raw)
		if err != nil {
			return "", err
		}
		s, err := root.BeginParse()
		if err != nil || s.BitsLeft() != 256 || s.RefsNum() != 0 {
			return "", errors.New("invalid ConfigParam 4 cell")
		}
		id, err := s.LoadSlice(256)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("-1:%s", hex.EncodeToString(id)), nil
	})
	return value, err
}

func runDNSGetter(ctx context.Context, nodes []*rpcNode, quorum int, account string, seqno uint64, method string, stack []dnsStackInput) (dnsRunResult, error) {
	returnValue, _, err := quorumRead(ctx, nodes, quorum, func(ctx context.Context, node *rpcNode) (dnsRunResult, error) {
		var result dnsRunResult
		params := struct {
			Address string          `json:"address"`
			Method  string          `json:"method"`
			Stack   []dnsStackInput `json:"stack"`
			Seqno   uint64          `json:"seqno"`
		}{Address: account, Method: method, Stack: stack, Seqno: seqno}
		if err := node.client.Call(ctx, "runGetMethod", params, &result); err != nil {
			return result, err
		}
		if result.Type != "smc.runResult" || result.ExitCode != 0 || result.BlockID.Type != "tos.blockIdExt" || result.BlockID.Seqno != seqno {
			return result, errors.New("invalid DNS getter result")
		}
		return result, nil
	})
	return returnValue, err
}

func stackPair(stack []json.RawMessage, index int) (string, json.RawMessage, error) {
	if index < 0 || index >= len(stack) {
		return "", nil, errors.New("DNS getter stack is too short")
	}
	var pair []json.RawMessage
	if err := json.Unmarshal(stack[index], &pair); err != nil || len(pair) < 1 || len(pair) > 2 {
		return "", nil, errors.New("invalid DNS stack entry")
	}
	var kind string
	if err := json.Unmarshal(pair[0], &kind); err != nil {
		return "", nil, err
	}
	if len(pair) == 1 {
		if kind != "null" {
			return "", nil, errors.New("DNS stack value is missing")
		}
		return kind, nil, nil
	}
	if kind == "null" {
		return "", nil, errors.New("DNS null stack entry has a value")
	}
	return kind, pair[1], nil
}

func stackInt(stack []json.RawMessage, index int) (*big.Int, error) {
	kind, raw, err := stackPair(stack, index)
	if err != nil || kind != "num" {
		return nil, errors.New("DNS stack entry is not a number")
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return nil, err
	}
	value, ok := new(big.Int).SetString(text, 10)
	if !ok || value.Sign() < 0 {
		return nil, errors.New("invalid DNS stack number")
	}
	return value, nil
}

func stackCell(stack []json.RawMessage, index int) (*cell.Cell, bool, error) {
	kind, raw, err := stackPair(stack, index)
	if err != nil {
		return nil, false, err
	}
	if kind == "null" {
		return nil, true, nil
	}
	if kind != "cell" && kind != "slice" {
		return nil, false, errors.New("DNS stack entry is not a cell")
	}
	var value struct {
		Bytes string `json:"bytes"`
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, false, err
	}
	decoded, err := base64.StdEncoding.DecodeString(value.Bytes)
	if err != nil {
		return nil, false, err
	}
	root, err := cell.FromBOC(decoded)
	return root, false, err
}

func parseNextResolver(value *cell.Cell) (string, error) {
	s, err := value.BeginParse()
	if err != nil {
		return "", err
	}
	tag, err := s.LoadUInt(16)
	if err != nil || tag != 0xba93 {
		return "", errors.New("partial DNS result is not dns_next_resolver")
	}
	addr, err := s.LoadAddr()
	if err != nil || addr == nil || s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return "", errors.New("invalid dns_next_resolver record")
	}
	return addr.StringRaw(), nil
}

func parseSMCRecord(value *cell.Cell) (string, error) {
	s, err := value.BeginParse()
	if err != nil {
		return "", err
	}
	tag, err := s.LoadUInt(16)
	if err != nil || tag != 0x9fd3 {
		return "", errors.New("DNS alias record is not dns_smc_address")
	}
	addr, err := s.LoadAddr()
	if err != nil || addr == nil {
		return "", errors.New("invalid DNS smart-contract address")
	}
	flags, err := s.LoadUInt(8)
	if err != nil || flags > 1 {
		return "", errors.New("invalid DNS smart-contract flags")
	}
	if flags == 1 {
		if _, err := s.LoadRefCell(); err != nil {
			return "", errors.New("missing DNS capability list")
		}
	}
	if s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return "", errors.New("trailing DNS smart-contract record data")
	}
	return addr.StringRaw(), nil
}

func verifyDomainItem(ctx context.Context, nodes []*rpcNode, quorum int, seqno uint64, checkpoint *nativev1.DNSCheckpointV1, item, collection, label string) (int64, int64, error) {
	identity, err := runDNSGetter(ctx, nodes, quorum, item, seqno, "get_nft_data", nil)
	if err != nil || !sameDNSBlock(checkpoint, identity.BlockID) || len(identity.Stack) != 5 {
		return 0, 0, errors.New("cannot verify DNS Domain Item identity")
	}
	index, err := stackInt(identity.Stack, 1)
	if err != nil {
		return 0, 0, err
	}
	collectionCell, _, err := stackCell(identity.Stack, 2)
	if err != nil {
		return 0, 0, err
	}
	cs, err := collectionCell.BeginParse()
	if err != nil {
		return 0, 0, err
	}
	gotCollection, err := cs.LoadAddr()
	if err != nil || gotCollection == nil || gotCollection.StringRaw() != collection || cs.BitsLeft() != 0 || cs.RefsNum() != 0 {
		return 0, 0, errors.New("DNS item belongs to another Collection")
	}
	labelHash := cell.BeginCell().MustStoreSlice([]byte(label), uint(len(label)*8)).EndCell().Hash()
	if index.Cmp(new(big.Int).SetBytes(labelHash)) != 0 {
		return 0, 0, errors.New("DNS item index differs from label slice hash")
	}
	auction, err := runDNSGetter(ctx, nodes, quorum, item, seqno, "get_auction_info", nil)
	if err != nil || !sameDNSBlock(checkpoint, auction.BlockID) || len(auction.Stack) != 3 {
		return 0, 0, errors.New("cannot read DNS auction")
	}
	end, err := stackInt(auction.Stack, 2)
	if err != nil || !end.IsInt64() {
		return 0, 0, errors.New("invalid DNS auction end")
	}
	fill, err := runDNSGetter(ctx, nodes, quorum, item, seqno, "get_last_fill_up_time", nil)
	if err != nil || !sameDNSBlock(checkpoint, fill.BlockID) || len(fill.Stack) != 1 {
		return 0, 0, errors.New("cannot read DNS renewal clock")
	}
	last, err := stackInt(fill.Stack, 0)
	if err != nil || !last.IsInt64() {
		return 0, 0, errors.New("invalid DNS renewal clock")
	}
	return end.Int64(), last.Int64(), nil
}

func checkpointFromBlock(id blockID, unix uint64) (*nativev1.DNSCheckpointV1, error) {
	root, err := decodeBase64Hash(id.RootHash)
	if err != nil {
		return nil, err
	}
	file, err := decodeBase64Hash(id.FileHash)
	if err != nil {
		return nil, err
	}
	shard, err := strconv.ParseInt(id.Shard, 10, 64)
	if err != nil || id.Workchain != -1 || id.Seqno == 0 {
		return nil, errors.New("invalid DNS block identity")
	}
	return &nativev1.DNSCheckpointV1{Workchain: id.Workchain, Shard: shard, Sequence: id.Seqno, RootHash: root, FileHash: file, GenerationUnixSeconds: unix}, nil
}

func sameDNSBlock(checkpoint *nativev1.DNSCheckpointV1, id blockID) bool {
	other, err := checkpointFromBlock(id, checkpoint.GenerationUnixSeconds)
	return err == nil && checkpoint.Workchain == other.Workchain && checkpoint.Shard == other.Shard && checkpoint.Sequence == other.Sequence && string(checkpoint.RootHash) == string(other.RootHash) && string(checkpoint.FileHash) == string(other.FileHash)
}

func secondLevelLabel(name string) string {
	parts := strings.Split(name, ".")
	return parts[len(parts)-2]
}

var _ dnsalias.ChainResolver = (*DNSResolver)(nil)
