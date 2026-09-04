#!/usr/bin/env bash
# Bring up the Fabric network this directory describes, from nothing.
#
# infra/fabric/README.md said the compose file was "necessary but not
# sufficient". This is the rest of it: crypto material, a channel genesis block,
# channel join, and chaincode deploy. Until 2026-09-04 none of it existed, so
# the network in that compose file had never been started even once -- the
# orderer and peer both had MSP paths configured and nothing mounted at them.
#
#   ./infra/fabric/network.sh up      generate crypto, start, join, deploy
#   ./infra/fabric/network.sh down    stop and delete everything, crypto included
#   ./infra/fabric/network.sh status  what is running
#
# Nothing here is checked in: crypto-config/ and the genesis block are generated
# on every `up`. Checked-in MSP keys would be an unreviewable binary blob and a
# security problem, and regenerating keeps the network reproducible from this
# directory alone.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

CHANNEL="${ABCD_CHANNEL:-abcd}"
CC_NAME="${ABCD_CC_NAME:-abcdledger}"
CC_VERSION="${ABCD_CC_VERSION:-1.0}"
# The orderer speaks TLS (cluster type requires it); the peer does not. Every
# peer->orderer call therefore needs the orderer CA, and peer->peer calls do not.
ORDERER_CA="/work/crypto-config/ordererOrganizations/abcd.local/orderers/orderer.abcd.local/tls/ca.crt"
PEER_CA="/work/crypto-config/peerOrganizations/org1.abcd.local/peers/peer0.org1.abcd.local/tls/ca.crt"
FABRIC_TAG="2.5"
DOCKER="${DOCKER:-sudo docker}"

# Everything below runs the CLI out of the fabric-tools image so the host needs
# no Fabric binaries -- cryptogen, configtxgen, osnadmin and peer all live there.
#
# First argument is the binary, the rest are ITS arguments. Docker options must
# precede the image name, so the entrypoint cannot be passed through "$@" after
# it: doing that made `docker run ... -- config --config=...` read `config` as
# the image and fail with "pull access denied for config".
tools() {
  local entry="$1"; shift
  $DOCKER run --rm \
    -v "$HERE:/work" -w /work \
    -e FABRIC_CFG_PATH=/work \
    --entrypoint "$entry" \
    hyperledger/fabric-tools:$FABRIC_TAG "$@"
}

# Same, but joined to the compose network -- only valid once `up` has created
# it, so cryptogen and configtxgen (which talk to nothing) must not use it.
tools_net() {
  local entry="$1"; shift
  $DOCKER run --rm \
    -v "$HERE:/work" -w /work \
    --network abcd_fabric \
    -e FABRIC_CFG_PATH=/work \
    --entrypoint "$entry" \
    hyperledger/fabric-tools:$FABRIC_TAG "$@"
}

cmd_up() {
  echo "==> 1/6 crypto material (cryptogen)"
  # Root-owned on the host: cryptogen runs as root inside the container and
  # writes through the bind mount, so a plain rm gets "Permission denied" on
  # every key it made. Re-running `up` has to be able to start clean.
  sudo rm -rf crypto-config channel-artifacts
  tools cryptogen generate --config=/work/crypto-config.yaml --output=/work/crypto-config >/dev/null
  # cryptogen writes as root inside the container; the compose mounts are :ro
  # but still need to be readable by the fabric user in the peer/orderer images.
  tools chmod -R a+rX /work/crypto-config >/dev/null 2>&1 || sudo chmod -R a+rX crypto-config
  echo "    $(find crypto-config -name '*.pem' | wc -l | tr -d ' ') certificates"

  echo "==> 2/6 channel genesis block (configtxgen)"
  mkdir -p channel-artifacts
  tools configtxgen -profile AbcdChannel \
    -outputBlock /work/channel-artifacts/$CHANNEL.block -channelID "$CHANNEL" >/dev/null
  echo "    channel-artifacts/$CHANNEL.block"

  echo "==> 3/6 starting orderer, peer, ipfs"
  $DOCKER compose -f docker-compose.yaml up -d
  # The orderer needs its admin endpoint listening before osnadmin can join.
  for _ in $(seq 1 30); do
    $DOCKER compose -f docker-compose.yaml exec -T orderer sh -c 'true' 2>/dev/null && break
    sleep 2
  done
  sleep 5

  echo "==> 4/6 joining the channel (osnadmin)"
  tools_net osnadmin channel join \
    --channelID "$CHANNEL" \
    --config-block /work/channel-artifacts/$CHANNEL.block \
    -o orderer:7053 >/dev/null
  sleep 3
  peer_cli channel join -b /work/channel-artifacts/$CHANNEL.block >/dev/null
  sleep 3
  echo "    peer joined: $(peer_cli channel list 2>/dev/null | tail -n +2 | tr -d '\r' | paste -sd, -)"

  echo "==> 5/6 packaging and installing chaincode"
  deploy_chaincode

  echo "==> 6/6 python bindings"
  gen_pyproto

  echo "==> ready"
  cmd_status
}

# peer CLI as the Org1 admin, against the running peer.
peer_cli() {
  $DOCKER run --rm \
    -v "$HERE:/work" -w /work \
    --network abcd_fabric \
    -e FABRIC_CFG_PATH=/etc/hyperledger/fabric \
    -e CORE_PEER_TLS_ENABLED=true \
    -e CORE_PEER_TLS_ROOTCERT_FILE="$PEER_CA" \
    -e CORE_PEER_LOCALMSPID=Org1MSP \
    -e CORE_PEER_ADDRESS=peer:7051 \
    -e CORE_PEER_MSPCONFIGPATH=/work/crypto-config/peerOrganizations/org1.abcd.local/users/Admin@org1.abcd.local/msp \
    --entrypoint peer \
    hyperledger/fabric-tools:$FABRIC_TAG "$@"
}

deploy_chaincode() {
  peer_cli lifecycle chaincode package /work/channel-artifacts/$CC_NAME.tar.gz \
    --path /work/chaincode --lang golang --label ${CC_NAME}_${CC_VERSION} >/dev/null
  peer_cli lifecycle chaincode install /work/channel-artifacts/$CC_NAME.tar.gz >/dev/null 2>&1
  local pkg
  pkg=$(peer_cli lifecycle chaincode queryinstalled 2>/dev/null \
        | sed -n "s/^Package ID: \(${CC_NAME}_${CC_VERSION}:[a-f0-9]*\).*/\1/p" | head -1)
  [ -z "$pkg" ] && { echo "    chaincode install failed"; return 1; }
  echo "    package $pkg"
  peer_cli lifecycle chaincode approveformyorg -o orderer:7050 \
    --tls --cafile "$ORDERER_CA" \
    --channelID "$CHANNEL" --name "$CC_NAME" --version "$CC_VERSION" \
    --package-id "$pkg" --sequence 1 >/dev/null
  peer_cli lifecycle chaincode commit -o orderer:7050 \
    --tls --cafile "$ORDERER_CA" \
    --channelID "$CHANNEL" --name "$CC_NAME" --version "$CC_VERSION" \
    --sequence 1 >/dev/null
  echo "    committed $CC_NAME v$CC_VERSION on $CHANNEL"
}

# Compile the Fabric protobufs the adapter imports. There is no maintained
# Python SDK for v2.5 -- fabric-sdk-py's last release does not build on 3.11
# (pysha3) and predates the Gateway -- so chain/fabric_ledger.py talks to the
# peer's Endorser service directly and needs these bindings. Generated here
# rather than checked in: 56 files of generated code is not reviewable, and the
# protos must match the Fabric version this directory actually runs.
gen_pyproto() {
  local out="$HERE/pyproto"
  if [ -f "$out/peer/peer_pb2_grpc.py" ]; then
    echo "    bindings present"; return 0
  fi
  local py="${ABCD_PY:-$HOME/.venv-malbpq/bin/python}"
  "$py" -c "import grpc_tools" 2>/dev/null || "$py" -m pip install -q grpcio grpcio-tools
  rm -rf "$out" /tmp/fabric-protos
  git clone -q --depth 1 -b main https://github.com/hyperledger/fabric-protos.git /tmp/fabric-protos
  mkdir -p "$out"
  ( cd /tmp/fabric-protos && "$py" -m grpc_tools.protoc -I. \
      --python_out="$out" --grpc_python_out="$out" \
      $(find common msp peer gateway orderer -name "*.proto") )
  # protoc emits implicit-namespace packages; the adapter imports `common.x`
  # and `peer.y`, which resolve without __init__.py on 3.3+, but an explicit
  # marker keeps them importable if anything ever prepends a path.
  find "$out" -type d -exec touch {}/__init__.py \;
  echo "    $(find "$out" -name '*_pb2*.py' | wc -l | tr -d ' ') modules -> infra/fabric/pyproto"
}

cmd_down() {
  $DOCKER compose -f docker-compose.yaml down -v 2>/dev/null || true
  # Chaincode containers are started by the peer, not by compose.
  $DOCKER ps -aq --filter "name=dev-abcd-peer" | xargs -r $DOCKER rm -f >/dev/null 2>&1 || true
  sudo rm -rf crypto-config channel-artifacts
  echo "network down; crypto material and channel artifacts removed"
}

cmd_status() {
  $DOCKER compose -f docker-compose.yaml ps --format 'table {{.Service}}\t{{.Status}}' 2>/dev/null || true
  echo "channel: $(peer_cli channel list 2>/dev/null | tail -n +2 | tr -d '\r' | paste -sd, - || echo 'not joined')"
}

case "${1:-}" in
  up) cmd_up ;;
  down) cmd_down ;;
  status) cmd_status ;;
  *) echo "usage: infra/fabric/network.sh {up|down|status}"; exit 2 ;;
esac
