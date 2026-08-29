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
      git fetch -q origin && git reset -q --hard origin/$BRANCH
      # Restore any result that the reset just clobbered, but ONLY real ones.
      python3 - <<'PY' \$BK
import json,shutil,sys
from pathlib import Path
bk=Path(sys.argv[1])/'Schemes'; live=Path('Schemes'); n=0
for meta in bk.glob('*/*/run_meta.json'):
    try: m=json.loads(meta.read_text())
    except Exception: continue
    if m.get('corpus_type')!='synthea': continue
    dst=live/meta.parent.relative_to(bk); dst.mkdir(parents=True,exist_ok=True)
    for f in meta.parent.iterdir():
        if f.is_file(): shutil.copy2(f,dst/f.name)
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
if m.get(\"corpus_type\")!=\"synthea\": sys.exit(1)
c=str(m.get(\"git_commit\",\"\"))
is_dirty=c.endswith(\"-dirty\")
sha=c[:-6] if is_dirty else c
want=os.environ.get(\"WANT_COMMIT\") or \"\"
if want and not sha.startswith(want): sys.exit(1)
sys.exit(3 if is_dirty and os.environ.get(\"ALLOW_DIRTY\")!=\"1\" else 0)" 2>/dev/null
        case $? in 0) dirname "$m";; 3) echo "DIRTY:$(dirname "$m")" >&2;; esac
      done)
      [ -n "$dirs" ] && tar cz $dirs 2>/dev/null' > "$out/$ip.tgz" 2>"$out/$ip.skipped"
    local nd
    nd=$(grep -c "^DIRTY:" "$out/$ip.skipped" 2>/dev/null || echo 0)
    [ "$nd" -eq 0 ] && rm -f "$out/$ip.skipped"
    echo "  $ip -> $(tar tzf "$out/$ip.tgz" 2>/dev/null | grep -c run_meta.json) result dir(s)$(
      [ "$nd" -gt 0 ] && echo " -- $nd SKIPPED as -dirty, see $out/$ip.skipped (OJCOMS_ALLOW_DIRTY=1 to override)")"
  done
  echo "unpack with: for f in $out/*.tgz; do tar xzf \$f -C \$(git rev-parse --show-toplevel); done"
}

cmd_stop()   { echo "stopping..."; for i in $(ids); do
                 aws ec2 stop-instances --instance-ids "$i" >/dev/null 2>&1 && echo "  $i"; done; }

cmd_status() {
  local run stop burn
  run=$(aws ec2 describe-instances "${TAG_FILTER[@]}" "Name=instance-state-name,Values=running" \
        --query 'length(Reservations[].Instances[])' --output text | tr -d '[:space:]')
  stop=$(aws ec2 describe-instances "${TAG_FILTER[@]}" "Name=instance-state-name,Values=stopped" \
        --query 'length(Reservations[].Instances[])' --output text | tr -d '[:space:]')
  # python3 rather than awk: the nested quoting needed to get a float out of
  # awk through two levels of shell was what broke this the first time.
  burn=$(python3 -c "print(f'{${run:-0} * 0.19:.2f}')")
  echo "running=$run stopped=$stop  burn=\$$burn/hr"
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
