// abcdledger — the on-chain half of chain/ledger.py's Ledger interface.
//
// Deliberately a dumb, strict key-value store. The hash chain itself is
// computed off-chain by chain/ledger.py::_entry_hash and stored here as opaque
// hex, for one reason: verify_chain() must recompute exactly the same links
// whether the entries came from InProcessLedger or from Fabric. Recomputing the
// digest in Go would mean two implementations of the same hash that could
// silently disagree, and a disagreement there reads as ledger tampering.
//
// What the chaincode DOES enforce is immutability: Append refuses a key that
// already exists, so append-only is a property of the chain rather than of the
// client's good behaviour. That is the one guarantee an in-process dict could
// never really provide, and it is why this exists.
package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// Entry mirrors chain/ledger.py::LedgerEntry, minus `record` — the typed object
// is reconstructed client-side by decoding `Payload`, which is what
// ledger.py:105 means by "a Fabric adapter reading an entry it did not write
// will need a canonical decoder".
type Entry struct {
	Sequence     int    `json:"sequence"`
	Namespace    string `json:"namespace"`
	Key          string `json:"key"`
	Payload      string `json:"payload"`       // base64
	Domain       string `json:"domain"`        // base64
	TimestampNs  int64  `json:"timestamp_ns"`
	PreviousHash string `json:"previous_hash"` // hex
	EntryHash    string `json:"entry_hash"`    // hex
}

// Meta is the chain head and length, kept in one key so entry_count() and
// chain_head() are single reads rather than a full range scan.
type Meta struct {
	Count int    `json:"count"`
	Head  string `json:"head"` // hex of the most recent entry_hash
}

const metaKey = "__meta__"

type Contract struct {
	contractapi.Contract
}

func compositeKey(namespace, key string) string {
	return namespace + "\x00" + key
}

func (c *Contract) readMeta(ctx contractapi.TransactionContextInterface) (*Meta, error) {
	raw, err := ctx.GetStub().GetState(metaKey)
	if err != nil {
		return nil, err
	}
	meta := &Meta{Count: 0, Head: ""}
	if raw != nil {
		if err := json.Unmarshal(raw, meta); err != nil {
			return nil, err
		}
	}
	return meta, nil
}

// Append commits one entry. Refuses an existing key — this is ImmutabilityError.
func (c *Contract) Append(
	ctx contractapi.TransactionContextInterface,
	namespace, key, payload, domain string,
	timestampNs int64,
	previousHash, entryHash string,
) error {
	ck := compositeKey(namespace, key)
	existing, err := ctx.GetStub().GetState(ck)
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("IMMUTABLE: %s/%s already committed", namespace, key)
	}
	meta, err := c.readMeta(ctx)
	if err != nil {
		return err
	}
	entry := Entry{
		Sequence:     meta.Count,
		Namespace:    namespace,
		Key:          key,
		Payload:      payload,
		Domain:       domain,
		TimestampNs:  timestampNs,
		PreviousHash: previousHash,
		EntryHash:    entryHash,
	}
	blob, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(ck, blob); err != nil {
		return err
	}
	meta.Count++
	meta.Head = entryHash
	metaBlob, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(metaKey, metaBlob)
}

// Get returns one entry as JSON. THIS IS THE CALL EXP. 4 TIMES, once per
// returned record: an Evaluate against the peer, no ordering and no commit.
func (c *Contract) Get(
	ctx contractapi.TransactionContextInterface, namespace, key string,
) (string, error) {
	raw, err := ctx.GetStub().GetState(compositeKey(namespace, key))
	if err != nil {
		return "", err
	}
	if raw == nil {
		return "", fmt.Errorf("NOTFOUND: %s/%s", namespace, key)
	}
	return string(raw), nil
}

// Keys returns the sorted keys of a namespace, optionally prefix-filtered.
func (c *Contract) Keys(
	ctx contractapi.TransactionContextInterface, namespace, prefix string,
) (string, error) {
	start := compositeKey(namespace, prefix)
	end := start + string(rune(0x10FFFF))
	iter, err := ctx.GetStub().GetStateByRange(start, end)
	if err != nil {
		return "", err
	}
	defer iter.Close()
	keys := []string{}
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return "", err
		}
		var entry Entry
		if err := json.Unmarshal(kv.Value, &entry); err != nil {
			continue
		}
		keys = append(keys, entry.Key)
	}
	blob, err := json.Marshal(keys)
	return string(blob), err
}

// All returns every entry in sequence order — what verify_chain() walks.
func (c *Contract) All(ctx contractapi.TransactionContextInterface) (string, error) {
	iter, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return "", err
	}
	defer iter.Close()
	entries := []Entry{}
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return "", err
		}
		if kv.Key == metaKey {
			continue
		}
		var entry Entry
		if err := json.Unmarshal(kv.Value, &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	blob, err := json.Marshal(entries)
	return string(blob), err
}

// MetaJSON returns {count, head} — chain_head() and entry_count() in one read.
func (c *Contract) MetaJSON(ctx contractapi.TransactionContextInterface) (string, error) {
	meta, err := c.readMeta(ctx)
	if err != nil {
		return "", err
	}
	blob, err := json.Marshal(meta)
	return string(blob), err
}

func main() {
	cc, err := contractapi.NewChaincode(&Contract{})
	if err != nil {
		panic(fmt.Sprintf("abcdledger: %v", err))
	}
	if err := cc.Start(); err != nil {
		panic(fmt.Sprintf("abcdledger: %v", err))
	}
}
