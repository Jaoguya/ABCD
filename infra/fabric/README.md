# Fabric + IPFS for the benchmark

Brings up the ledger and off-chain store README §1 specifies (Hyperledger
Fabric v2.5, IPFS). Until 2026-08-28 this directory did not exist, so README
§11's `docker compose -f infra/fabric/docker-compose.yaml up -d` was a broken
instruction and every run silently fell back to `chain/ledger.py`'s
`InProcessLedger`.

```bash
docker compose -f infra/fabric/docker-compose.yaml up -d
docker compose -f infra/fabric/docker-compose.yaml ps
docker compose -f infra/fabric/docker-compose.yaml down -v   # -v also drops ledger state
```

## What this is, and what it is not

**Single organisation, solo orderer.** Not a production topology. What Exp. 4
and Exp. 6 measure is the cost of *anchoring a commitment and reading it back*
— ordering latency, block cut, endorsement round-trip — and this reproduces
those on one `m6i.xlarge` reproducibly.

**A solo orderer has no consensus round, so anchoring latency here is a LOWER
BOUND on a Raft deployment.** State that in §V rather than describing this as
a production network. It is the conservative direction for the proposed scheme
— it does not flatter our anchoring cost relative to a baseline that anchors
less often — but it is still a difference from the stated stack.

**TLS is disabled**, because a handshake would be measured as if it were
anchoring cost on a single-host private-VPC network. Never carry that setting
anywhere the traffic leaves the host.

**LevelDB, not CouchDB**: the scheme stores opaque commitments and issues no
rich queries, so CouchDB would add indexing cost the construction does not
incur.

## Before this clears the reportability blocker

`provenance.reportability()` blocks on `ledger_faithful` because an in-process
hash chain understates Exp. 4's chain-consistency cost. Bringing these
containers up is **necessary but not sufficient** — a `FabricLedger` adapter
implementing `chain/ledger.py`'s `Ledger` interface against this network still
has to exist and be passed `ledger_faithful=True`. That adapter is **not yet
written**; see `chain/ledger.py`'s note that a Fabric adapter "reading an entry
it did not write will need a canonical decoder".

So today this directory makes README §11 executable and unblocks that work.
It does not by itself make Exp. 4 reportable, and no run should claim it does.

## Channel setup

`ORDERER_CHANNELPARTICIPATION_ENABLED=true` means the channel is created via
the admin API (osnadmin) rather than a genesis block baked into the image. The
adapter above should create the channel on first use so the network is
reproducible from this file alone, with no manual crypto material to check in
— checked-in MSP keys would be both a security problem and an unreviewable
binary blob.
