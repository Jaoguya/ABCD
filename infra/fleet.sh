#!/usr/bin/env bash
# Fleet operations: start, deploy, harvest, stop, status.
#
# Exists because the manual procedure has already cost real data. Two traps it
# closes:
#
#   1. Result files are GIT-TRACKED. `git reset --hard` on a node restores the
#      committed versions over fresh results -- silently. That destroyed
#      guo_vdsse's completed Exp. 1, 2 and 4. `deploy` archives first, then
#      restores.
#   2. Results are selected by PROVENANCE, never by mtime. A reset rewrites
#      mtimes, so a stale file can look newer than a real one. `harvest` reads
#      run_meta.json and takes only corpus_type=synthea.
#
# Read-only by default; only `start`, `stop` and `deploy` change anything.
set -uo pipefail

KEY="${OJCOMS_KEY:-$HOME/.ssh/ojcoms.pem}"
SG="${OJCOMS_SG:-sg-0dea7cf940668cddb}"
BRANCH="${OJCOMS_BRANCH:-main}"
TAG_FILTER=(--filters "Name=tag:Project,Values=OJCOMS")
SSH_OPTS=(-i "$KEY" -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=15)

ids()  { aws ec2 describe-instances "${TAG_FILTER[@]}" \
           --query 'Reservations[].Instances[].InstanceId' --output text | tr '\t' '\n'; }
ips()  { aws ec2 describe-instances "${TAG_FILTER[@]}" \
           "Name=instance-state-name,Values=running" \
           --query 'Reservations[].Instances[].PublicIpAddress' --output text | tr '\t' '\n' | grep -v '^None$'; }

allow_my_ip() {
  # The egress IP rotates. When it does, every host times out at once and looks
  # dead; it is only the security group. Adding the current address is
  # idempotent -- a duplicate rule is reported and ignored.
  local me; me=$(curl -s --max-time 8 https://checkip.amazonaws.com)
  [ -z "$me" ] && { echo "  could not determine egress IP"; return; }
  if aws ec2 authorize-security-group-ingress --group-id "$SG" \
       --ip-permissions "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=$me/32,Description=fleet.sh}]" \
       >/dev/null 2>&1; then echo "  authorised $me"; else echo "  $me already allowed"; fi
}

cmd_start() {
  echo "starting fleet..."
  for i in $(ids); do aws ec2 start-instances --instance-ids "$i" >/dev/null 2>&1; done
  echo "waiting for running state..."
  for _ in $(seq 1 40); do
    local n; n=$(aws ec2 describe-instances "${TAG_FILTER[@]}" \
      "Name=instance-state-name,Values=running" \
      --query 'length(Reservations[].Instances[])' --output text)
    [ "$n" = "$(ids | wc -l | tr -d ' ')" ] && break; sleep 10
  done
  allow_my_ip
  echo "waiting for sshd..."
  for ip in $(ips); do
    for _ in $(seq 1 20); do
      ssh "${SSH_OPTS[@]}" "ubuntu@$ip" true 2>/dev/null && break; sleep 8
    done
  done
  cmd_status
}

cmd_deploy() {
  echo "deploying $BRANCH (archiving results first)..."
  for ip in $(ips); do
    ssh -A "${SSH_OPTS[@]}" "ubuntu@$ip" "
      cd ~/abcd || exit 1
      BK=~/results-safe-\$(date -u +%Y%m%dT%H%M%SZ)
      mkdir -p \$BK && cp -a Schemes \$BK/ 2>/dev/null
      git remote set-url origin git@github.com:Jaoguya/ABCD 2>/dev/null
      # reset --hard alone resets whatever branch happens to be checked out; it
      # never switches. Nodes were therefore sitting on a local branch named
      # `final-debug` TRACKING origin/final-debug while their HEAD held
      # exp78-diagnosis's commit -- correct code under a misleading label, and a
      # `git pull` on a node would have silently pulled the other branch and
      # reverted it. checkout -B fixes the name and the upstream together.
      git fetch -q origin && git reset -q --hard origin/$BRANCH \
        && git checkout -q -B $BRANCH origin/$BRANCH
      # Restore any result that the reset just clobbered, but ONLY real ones.
      python3 - <<'PY' \$BK
import json,shutil,sys
from pathlib import Path
# ONLY these three. runner.py and __init__.py live in the SAME directory as the
# results, so copying the whole directory back -- which this did -- reverted
# scheme SOURCE over the tree `git reset --hard` had just made correct. Measured
# on the fleet: four runner.py files came back as blob b18fabc (commit ddc324e),
# not HEAD's 23edee5, silently dropping sweep.select/--points support. Every run
# after such a deploy executed stale code for any scheme that had results here.
ARTIFACTS={'results.csv','raw_runs.csv','run_meta.json','lambda_sweep.csv'}
bk=Path(sys.argv[1])/'Schemes'; live=Path('Schemes'); n=0
for meta in bk.glob('*/*/run_meta.json'):
    try: m=json.loads(meta.read_text())
    except Exception: continue
    # Same nested/top-level split the harvest filter hit: thingom stores
    # corpus_type under `dataset`, everyone else at top level. Reading only the
    # top level here does not merely skip thingom -- this is the RESTORE step
    # after a checkout, so a thingom result that is not restored is DESTROYED.
    ds=m.get('dataset') or {}
    ct=m.get('corpus_type') or (ds.get('corpus_type') if isinstance(ds,dict) else None)
    if ct!='synthea': continue
    dst=live/meta.parent.relative_to(bk); dst.mkdir(parents=True,exist_ok=True)
    for f in meta.parent.iterdir():
        if f.is_file() and f.name in ARTIFACTS: shutil.copy2(f,dst/f.name)
    n+=1
print(f'  restored {n} result dir(s)')
PY
      echo \"  \$(hostname) \$(git log --oneline -1 | cut -c1-8)\"" 2>&1 | tail -2
  done
}

cmd_harvest() {
  local out="${1:-./harvest-$(date -u +%Y%m%dT%H%M%SZ)}"
  # corpus_type alone is NOT enough when a re-run supersedes results that are
  # already committed: `deploy` restores the git-tracked old directories onto
  # every node, so a node that ran ONE variant still carries all four, and the
  # three stale ones are also corpus_type=synthea. Set OJCOMS_COMMIT to the
  # commit the re-run was launched from to take only what that commit produced.
  local COMMIT="${OJCOMS_COMMIT:-}"
  # A `-dirty` stamp means the tree that produced the result had uncommitted
  # changes to something OTHER than the run's own output (provenance.git_commit
  # excludes results.csv/raw_runs.csv/run_meta.json/Plots/output, which every run
  # rewrites). Such a result cannot be reproduced from its commit, so it is NOT
  # harvested by default and the skip is reported rather than silent -- the old
  # filter used startswith(), under which "<sha>-dirty" passed as "<sha>".
  local ALLOW_DIRTY="${OJCOMS_ALLOW_DIRTY:-}"
  mkdir -p "$out"
  echo "harvesting to $out (provenance-selected${COMMIT:+, git_commit ^$COMMIT}\
${ALLOW_DIRTY:+, ALLOWING -dirty})..."
  for ip in $(ips); do
    ssh "${SSH_OPTS[@]}" "ubuntu@$ip" '
      cd ~/abcd
      dirs=$(for m in Schemes/*/*/run_meta.json; do [ -f "$m" ] || continue
        WANT_COMMIT="'"$COMMIT"'" ALLOW_DIRTY="'"$ALLOW_DIRTY"'" python3 -c "
import json,os,sys
m=json.load(open(\"$m\"))
# corpus_type lives top-level for guo/perera but NESTED under dataset for
# thingom. This checked top-level only, so thingom scored None, exited 1, and
# 1 had no branch in the case below -- every thingom result was dropped
# SILENTLY, logged nowhere, on every harvest this repo has ever run. Its exp1
# was never rescuable and nobody could see why. Check both spellings.
ds=m.get(\"dataset\") or {}
ct=m.get(\"corpus_type\") or (ds.get(\"corpus_type\") if isinstance(ds,dict) else None)
if ct!=\"synthea\": sys.exit(4)
c=str(m.get(\"git_commit\",\"\"))
is_dirty=c.endswith(\"-dirty\")
sha=c[:-6] if is_dirty else c
want=os.environ.get(\"WANT_COMMIT\") or \"\"
if want and not sha.startswith(want): sys.exit(1)
sys.exit(3 if is_dirty and os.environ.get(\"ALLOW_DIRTY\")!=\"1\" else 0)" 2>/dev/null
        # EVERY non-zero code gets a branch. The bug above hid behind a
        # missing one: an unmatched status silently vanished. A skip must
        # always be visible in the .skipped manifest, whatever its reason.
        case $? in
          0) dirname "$m";;
          3) echo "DIRTY:$(dirname "$m")" >&2;;
          4) echo "NOTSYNTHEA:$(dirname "$m")" >&2;;
          *) echo "UNREADABLE:$(dirname "$m")" >&2;;
        esac
      done)
      [ -n "$dirs" ] && tar cz $dirs 2>/dev/null' > "$out/$ip.tgz" 2>"$out/$ip.skipped"
    local nd
    # `grep -c` on a missing file yields an empty string, not 0, and the
    # arithmetic tests below then fail with "integer expression expected".
    # Strip to digits and default, so no .skipped file means 0 rather than noise.
    nd=$(grep -c "^DIRTY:" "$out/$ip.skipped" 2>/dev/null || true)
    nd=${nd//[!0-9]/}; nd=${nd:-0}
    [ "$nd" -eq 0 ] && rm -f "$out/$ip.skipped"
    echo "  $ip -> $(tar tzf "$out/$ip.tgz" 2>/dev/null | grep -c run_meta.json) result dir(s)$(
      [ "$nd" -gt 0 ] && echo " -- $nd SKIPPED as -dirty, see $out/$ip.skipped (OJCOMS_ALLOW_DIRTY=1 to override)")"
  done
  # This used to print a blanket `for f in */*.tgz; do tar xzf ...` loop. That
  # recipe destroys data and did: every node's tarball also carries a stale,
  # already-committed baseline copy of every OTHER scheme's directories (from
  # deploy's full checkout), and tar order is not provenance-aware, so a later
  # node's stale copy silently overwrites an earlier node's fresh result for the
  # same path. No error, no warning -- git status then shows the fresh result as
  # "clean", i.e. reverted. Caught 2026-08-30 before anything was committed.
  cat <<UNPACK
unpack PER SCHEME, from the ONE node that produced it, scoped to its path:
  tar xzf $out/<ip>.tgz -C \$(git rev-parse --show-toplevel) Schemes/<scheme>

Do NOT loop over every tarball -- see the comment above this message; it
overwrites fresh results with stale ones silently.

Find the right (ip, scheme) pairs first, and never from mtime (see this
script's header): run \`tar tzf $out/<ip>.tgz\` per node to see what each
holds, then check that scheme's run_meta.json git_commit and reportable
fields on each candidate node before choosing.
UNPACK
}

cmd_stop()   { echo "stopping..."; for i in $(ids); do
                 aws ec2 stop-instances --instance-ids "$i" >/dev/null 2>&1 && echo "  $i"; done; }

cmd_status() {
  local run stop burn
  run=$(aws ec2 describe-instances "${TAG_FILTER[@]}" "Name=instance-state-name,Values=running" \
        --query 'length(Reservations[].Instances[])' --output text | tr -d '[:space:]')
  stop=$(aws ec2 describe-instances "${TAG_FILTER[@]}" "Name=instance-state-name,Values=stopped" \
        --query 'length(Reservations[].Instances[])' --output text | tr -d '[:space:]')
  # Burn is priced PER INSTANCE TYPE, not as running x 0.19. The fleet is no
  # longer uniform: guo_vdsse and yue_ge were resized to m6i.4xlarge after
  # exhausting a 15 GB host mid-Exp. 2 (yue_ge's A_c grows ~9.85 GB per million
  # records and it sweeps to 10^6). A flat rate under-reported the true spend by
  # 3x the moment that happened, and spend decisions were being made on it.
  #
  # python3 rather than awk: the nested quoting needed to get a float out of
  # awk through two levels of shell was what broke this the first time.
  local types
  types=$(aws ec2 describe-instances "${TAG_FILTER[@]}" \
          "Name=instance-state-name,Values=running" \
          --query 'Reservations[].Instances[].InstanceType' --output text | tr '\t' '\n')
  burn=$(python3 - <<'PYRATE' "$types"
import sys
# us-east-1 on-demand, USD/hr. Unknown types fall back to the xlarge rate and
# say so, rather than silently pricing them at zero.
RATES = {"m6i.large": 0.096, "m6i.xlarge": 0.192, "m6i.2xlarge": 0.384,
         "m6i.4xlarge": 0.768, "m6i.8xlarge": 1.536, "m6i.12xlarge": 2.304,
         "m6i.16xlarge": 3.072, "m6i.24xlarge": 4.608, "m6i.32xlarge": 6.144}
total, unknown = 0.0, []
for t in (sys.argv[1] if len(sys.argv) > 1 else "").split():
    if t in RATES:
        total += RATES[t]
    elif t:
        unknown.append(t); total += RATES["m6i.xlarge"]
print(f"{total:.2f}" + (f" (+unpriced: {','.join(sorted(set(unknown)))})" if unknown else ""))
PYRATE
)
  echo "running=$run stopped=$stop  burn=\$$burn/hr"
  if [ -n "$types" ]; then
    echo "  types: $(echo "$types" | sort | uniq -c | awk '{printf "%sx%s ", $1, $2}')"
  fi
  for ip in $(ips); do
    echo "  $ip  $(ssh "${SSH_OPTS[@]}" "ubuntu@$ip" \
      "pgrep -f 'src\.main' >/dev/null && echo BUSY || echo idle; " 2>/dev/null | head -1)"
  done
}

case "${1:-}" in
  start) cmd_start ;;  deploy) cmd_deploy ;;  harvest) shift; cmd_harvest "$@" ;;
  stop) cmd_stop ;;    status) cmd_status ;;
  *) cat <<USAGE
usage: infra/fleet.sh {start|deploy|harvest [dir]|stop|status}

  start    start every Project=OJCOMS instance, authorise your current IP, wait for sshd
  deploy   archive results, update to \$OZ BRANCH (default: main), restore real results
  harvest  pull results selected by provenance (corpus_type=synthea), never by mtime
  stop     stop every instance (STOP, not terminate -- volumes and results survive)
  status   what is running, what is busy, current burn rate

env: OJCOMS_KEY, OJCOMS_SG, OJCOMS_BRANCH, OJCOMS_COMMIT (harvest filter)
USAGE
     exit 1 ;;
esac
