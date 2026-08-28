#!/usr/bin/env bash
# =============================================================================
# provision.sh — build the benchmark environment on one Ubuntu 22.04 instance
# =============================================================================
# Run this ONCE on a fresh m6i.xlarge, confirm the primitive tests pass, then
# snapshot the instance as an AMI and launch the whole fleet from it.
#
# Building once and cloning is not just faster. It makes README §1's parity
# claim exact: every node is a byte-identical image, which is a stronger
# statement in §V than "we installed the same packages on each host".
#
#   Target : Ubuntu 22.04 LTS, m6i.xlarge (4 vCPU, 16 GiB)
#   Usage  : bash infra/provision.sh
# =============================================================================

set -euo pipefail

PYTHON=python3.11
VENV="$HOME/.venv-malbpq"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# -----------------------------------------------------------------------------
log "Checking the OS is what the benchmark specifies"
# -----------------------------------------------------------------------------
. /etc/os-release
if [[ "${VERSION_ID:-}" != "22.04" ]]; then
    echo "WARNING: this is ${PRETTY_NAME}, but README §1 specifies Ubuntu 22.04 LTS."
    echo "charm-crypto (required for Ref[41]'s Type-I pairing) is fragile and"
    echo "is only expected to build on 22.04 with Python 3.11."
    read -rp "Continue anyway? [y/N] " reply
    [[ "$reply" == "y" ]] || exit 1
fi

# -----------------------------------------------------------------------------
log "System packages"
# -----------------------------------------------------------------------------
sudo apt-get update -qq
sudo apt-get install -y -qq software-properties-common

# Ubuntu 22.04 ships Python 3.10, not 3.11 — deadsnakes provides 3.11.
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt-get update -qq
sudo apt-get install -y -qq \
    "${PYTHON}" "${PYTHON}-venv" "${PYTHON}-dev" \
    build-essential git curl pkg-config cmake \
    libgmp-dev libssl-dev flex bison \
    m4 automake libtool

# -----------------------------------------------------------------------------
log "Python environment"
# -----------------------------------------------------------------------------
"${PYTHON}" -m venv "${VENV}"
# shellcheck disable=SC1091
source "${VENV}/bin/activate"
pip install --quiet --upgrade pip wheel setuptools
pip install --quiet -r "${REPO}/requirements.txt"

# -----------------------------------------------------------------------------
log "ML-KEM-768 backend"
# -----------------------------------------------------------------------------
# requirements.txt attributes ML-KEM to cryptography>=43, which is wrong —
# it landed much later. Common/crypto/kem.py probes several providers; install
# liboqs-python, the usual choice in PQC research code.
pip install --quiet liboqs-python || {
    echo "liboqs-python failed; falling back to pure-Python kyber-py."
    echo "NOTE: kyber-py is DEVELOPMENT ONLY — never report a setup cost from it."
    pip install --quiet kyber-py
}

# -----------------------------------------------------------------------------
log "Pairing backends"
# -----------------------------------------------------------------------------
# Ref[41] publishes a TYPE-I (symmetric) pairing, which only charm-crypto
# provides (SS512). petrelic is Type-III and is development-only — reportable
# Ref[41] runs refuse to use it (see Common/crypto/pairing.py).
pip install --quiet petrelic || echo "petrelic failed (dev fallback only)"

if ! pip install --quiet charm-crypto; then
    log "charm-crypto pip install failed — building from source"
    tmp=$(mktemp -d)

    # PBC is charm's pairing backend and isn't packaged for apt on 22.04/24.04.
    # Non-fatal, like the charm build below it: PBC exists only to serve that
    # build, and under `set -euo pipefail` an unguarded failure here would
    # abort provisioning entirely — skipping the BLAS thread pinning and the
    # primitive-test gate that follow, over a dependency the script already
    # tolerates failing.
    (
        cd "$tmp"
        curl -sLO https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
        tar xzf pbc-0.5.14.tar.gz
        cd pbc-0.5.14
        ./configure --prefix=/usr/local
        make -j"$(nproc)"
        sudo make install
        sudo ldconfig
    ) || echo "WARNING: PBC build FAILED — charm-crypto will not build either"

    # charm's configure.sh probes `which python3-config`, which deadsnakes never
    # installs (only the versioned python3.11-config exists) — it fails with
    # "requires the python development environment" without this symlink.
    # Resolved into a variable first: if ${PYTHON}-config is absent, an inline
    # command substitution yields "" and `ln -sf "" ...` fails pointing at ln
    # rather than at the real cause, the missing ${PYTHON}-dev package.
    python_config="$(command -v "${PYTHON}-config" || true)"
    if [[ -z "$python_config" ]]; then
        echo "WARNING: ${PYTHON}-config not found — install ${PYTHON}-dev."
        echo "         charm-crypto will fail with 'requires the python"
        echo "         development environment'."
    else
        sudo ln -sf "$python_config" /usr/local/bin/python3-config
    fi

    git clone --depth 1 https://github.com/JHUISI/charm.git "$tmp/charm"
    (
        cd "$tmp/charm"
        ./configure.sh --python="${VENV}/bin/python3"
        make
        sudo env PATH="$PATH" make install
        sudo ldconfig
    ) || echo "WARNING: charm-crypto build FAILED — Ref[41] cannot produce reportable results"
fi

# -----------------------------------------------------------------------------
log "Pinning BLAS threads"
# -----------------------------------------------------------------------------
# numpy's BLAS claims every core by default, so Ref[52]'s lattice latency would
# silently depend on core count and could not be reproduced even on identical
# hardware. Pin to the instance's vCPU count and record it in run_meta.json.
# global.yaml is the single source of truth: environment.blas_threads is 1, so
# that Ref[52]'s lattice latency does NOT depend on the host's core count.
# This previously used $(nproc), which both reintroduced that dependency and
# made verify_thread_pinning(require=True) fail on a correctly provisioned
# host — global.yaml expected 1, provision exported 4.
THREADS="$(grep -E '^[[:space:]]*blas_threads:' "${REPO}/Experiment Configuration/global.yaml" | head -1 | sed 's/.*://; s/#.*//; s/[[:space:]]//g')"
THREADS="${THREADS:-1}"
cat <<EOF | sudo tee /etc/profile.d/malbpq-threads.sh > /dev/null
export OMP_NUM_THREADS=${THREADS}
export OPENBLAS_NUM_THREADS=${THREADS}
export MKL_NUM_THREADS=${THREADS}
export NUMEXPR_NUM_THREADS=${THREADS}
EOF
# shellcheck disable=SC1091
source /etc/profile.d/malbpq-threads.sh

# -----------------------------------------------------------------------------
log "Environment report"
# -----------------------------------------------------------------------------
cd "${REPO}"
python -c "
from Common.crypto import environment_report
import json
print(json.dumps(environment_report(), indent=2))
"

# -----------------------------------------------------------------------------
log "Primitive tests — THE GATE"
# -----------------------------------------------------------------------------
# Nothing in Common/crypto has ever executed before this point. If it fails
# here, find out on ONE instance rather than after cloning the AMI nine times.
if python Common/crypto/tests/test_primitives.py; then
    log "PASS — safe to snapshot this instance as an AMI"
else
    log "FAIL — fix before snapshotting. Do NOT launch the fleet from this image."
    exit 1
fi

cat <<'EOF'

Next:
  1. Copy the corpus onto this instance:
       scp -i <key> Dataset/derived/corpus.jsonl ubuntu@<ip>:~/abcd/Dataset/derived/
       scp -i <key> Dataset/dataset_manifest.json ubuntu@<ip>:~/abcd/Dataset/
  2. Freeze it: copy corpus_sha256 from the manifest into
     Experiment Configuration/dataset.yaml -> freeze.expected_corpus_sha256
  3. Create an AMI from this instance.
  4. Launch the fleet from that AMI:
       4x FSN, 1x cloud+Fabric+IPFS, 1x client, 3x baseline runners
     all m6i.xlarge, one cluster placement group, same AZ.

  Activate the venv in every new shell:
       source ~/.venv-malbpq/bin/activate
EOF
