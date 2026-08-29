#!/usr/bin/env python3
"""Report AWS spend and current burn rate for the benchmark fleet.

Two sources, deliberately kept separate because they answer different
questions and can legitimately disagree:

  Cost Explorer   what AWS actually billed. Authoritative, lags ~24h, and
                  costs $0.01 per get-cost-and-usage call.
  EC2 describe    what is running right now, hence the burn rate. Free.

SCOPE — THIS PROJECT ONLY (user instruction, 2026-08-28):
"Focus on my project only, don't ever touch other instance that not ours."

The account also hosts unrelated projects (BVCRSA, Blockchain_BVCRSA, SSO,
test-, EKS/ECR). Those are out of scope in every respect and must never be
stopped, started, terminated, tagged or modified -- not even when obviously
wasteful, because that is someone else's call. Project membership is defined
by the tag Project=OJCOMS and by nothing else: not names, not instance types,
not launch times.

This script reports only. It never stops, starts, or terminates anything, so
--all-account is a reporting flag and grants no permission to act on what it
shows.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

# us-east-1 on-demand Linux, USD/hour. FALLBACK ONLY — used when the Pricing
# API is unreachable, and always labelled as an estimate in the output so a
# fallback number is never mistaken for a billed one.
FALLBACK_HOURLY = {
    "m6i.xlarge": 0.192, "m6i.large": 0.096, "m6i.2xlarge": 0.384,
    "c6i.xlarge": 0.170, "t3.micro": 0.0104, "t3.small": 0.0208,
    "t2.small": 0.023, "t3.medium": 0.0416, "m5.xlarge": 0.192,
}
GP3_GB_MONTH = 0.08  # us-east-1 gp3 storage, USD/GB-month


def run(cmd: List[str]) -> Tuple[int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def aws_json(args: List[str]) -> Optional[Any]:
    code, out, err = run(["aws", *args, "--output", "json"])
    if code != 0:
        return {"__error__": (err or out).strip()}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"__error__": f"unparseable response: {out[:200]}"}


def money(value: float) -> str:
    return f"${value:,.2f}"


# ---------------------------------------------------------------------------
# Live state — free
# ---------------------------------------------------------------------------
PROJECT_TAG_KEY = "Project"
PROJECT_TAG_VALUE = "OJCOMS"


def instances(all_account: bool = False) -> List[Dict[str, Any]]:
    """Project instances by default; the whole account only for reporting.

    Filtering happens SERVER-SIDE so out-of-scope instances are not even
    retrieved in the default path -- there is then nothing for a later change
    to accidentally act upon.
    """
    filters = ([] if all_account else
               ["--filters", f"Name=tag:{PROJECT_TAG_KEY},Values={PROJECT_TAG_VALUE}"])
    data = aws_json([
        "ec2", "describe-instances", *filters,
        "--query",
        "Reservations[*].Instances[*].{Id:InstanceId,Type:InstanceType,"
        "State:State.Name,Name:Tags[?Key=='Name']|[0].Value,"
        "Launch:LaunchTime,Vols:BlockDeviceMappings[*].Ebs.VolumeId}",
    ])
    if isinstance(data, dict) and "__error__" in data:
        print(f"  ERROR describe-instances: {data['__error__']}", file=sys.stderr)
        return []
    flat: List[Dict[str, Any]] = []
    for reservation in data or []:
        flat.extend(reservation)
    return flat


def volume_gb(ids: List[str]) -> float:
    if not ids:
        return 0.0
    data = aws_json(["ec2", "describe-volumes", "--volume-ids", *ids,
                     "--query", "Volumes[*].Size"])
    if isinstance(data, dict):
        return 0.0
    return float(sum(data or []))


def hourly_rate(instance_type: str, region: str = "us-east-1") -> Tuple[float, bool]:
    """(rate, is_fallback). Live price first, table second."""
    filters = [
        f"Type=TERM_MATCH,Field=instanceType,Value={instance_type}",
        "Type=TERM_MATCH,Field=operatingSystem,Value=Linux",
        "Type=TERM_MATCH,Field=tenancy,Value=Shared",
        "Type=TERM_MATCH,Field=preInstalledSw,Value=NA",
        "Type=TERM_MATCH,Field=capacitystatus,Value=Used",
        f"Type=TERM_MATCH,Field=regionCode,Value={region}",
    ]
    data = aws_json([
        "pricing", "get-products", "--service-code", "AmazonEC2",
        "--region", "us-east-1", "--filters", *filters, "--max-items", "1",
    ])
    try:
        doc = json.loads(data["PriceList"][0])  # type: ignore[index]
        terms = doc["terms"]["OnDemand"]
        dim = next(iter(next(iter(terms.values()))["priceDimensions"].values()))
        return float(dim["pricePerUnit"]["USD"]), False
    except Exception:
        return FALLBACK_HOURLY.get(instance_type, 0.0), True


def report_running(show_storage: bool = True,
                   all_account: bool = False) -> float:
    rows = instances(all_account=all_account)
    scope = "ENTIRE ACCOUNT (reporting only)" if all_account else (
        f"{PROJECT_TAG_KEY}={PROJECT_TAG_VALUE} only")
    print(f"scope: {scope}\n")
    running = [i for i in rows if i.get("State") == "running"]
    stopped = [i for i in rows if i.get("State") == "stopped"]

    print("RUNNING NOW")
    print("-" * 72)
    if not running:
        print("  (nothing running — no compute charges accruing)")
    burn = 0.0
    any_fallback = False
    now = dt.datetime.now(dt.timezone.utc)
    for inst in sorted(running, key=lambda r: r.get("Name") or ""):
        rate, fallback = hourly_rate(inst["Type"])
        any_fallback |= fallback
        burn += rate
        uptime = ""
        if inst.get("Launch"):
            try:
                started = dt.datetime.fromisoformat(
                    inst["Launch"].replace("Z", "+00:00"))
                hours = (now - started).total_seconds() / 3600
                uptime = f"  up {hours:,.1f}h  (~{money(hours * rate)} this boot)"
            except ValueError:
                pass
        mark = "*" if fallback else " "
        print(f"  {(inst.get('Name') or '-'):<16} {inst['Type']:<12} "
              f"{money(rate)}/hr{mark}{uptime}")

    print(f"\n  BURN RATE  {money(burn)}/hr   {money(burn * 24)}/day   "
          f"{money(burn * 24 * 7)}/week")
    if any_fallback:
        print("  * fallback price table, not the live Pricing API — estimate only")

    if stopped:
        print(f"\nSTOPPED ({len(stopped)}) — no compute charges, but EBS still bills")
        vol_ids = [v for i in stopped for v in (i.get("Vols") or []) if v]
        gb = volume_gb(vol_ids)
        for inst in sorted(stopped, key=lambda r: r.get("Name") or ""):
            print(f"  {(inst.get('Name') or '-'):<16} {inst['Type']:<12} stopped")
        if gb and show_storage:
            print(f"  {gb:,.0f} GB attached  ~{money(gb * GP3_GB_MONTH)}/month storage")
    return burn


# ---------------------------------------------------------------------------
# Cost Explorer — $0.01 per call
# ---------------------------------------------------------------------------
def cost_explorer(days: int, by_instance: bool, all_account: bool = False) -> None:
    """Billed cost. Scoped to this project unless --all-account is passed.

    THIS USED TO BE ACCOUNT-WIDE ALWAYS, under a header that said
    "scope: Project=OJCOMS only". That is how a $42 account-wide total got
    reported as this project's spend when the project had used about $20 --
    the account carries a ~$14/day baseline from unrelated work (BVCRSA, SSO,
    EKS), and days when this project's fleet was entirely stopped still billed
    $12-14. The header is now honest and the query is actually filtered.

    Cost allocation tags must be ACTIVATED in Billing > Cost allocation tags
    before Cost Explorer can group or filter by them, and activation is not
    retroactive -- it applies from the day it is switched on. So a tag-filtered
    query can legitimately return nothing while real spend exists. That case is
    reported as "tag not activated", never as $0.
    """
    end = dt.date.today() + dt.timedelta(days=1)
    start = end - dt.timedelta(days=days + 1)
    args = [
        "ce", "get-cost-and-usage",
        "--time-period", f"Start={start},End={end}",
        "--granularity", "DAILY",
        "--metrics", "UnblendedCost",
    ]
    if not all_account:
        args += ["--filter", json.dumps(
            {"Tags": {"Key": PROJECT_TAG_KEY,
                      "Values": [PROJECT_TAG_VALUE],
                      "MatchOptions": ["EQUALS"]}})]
    if by_instance:
        args += ["--group-by", "Type=DIMENSION,Key=SERVICE"]

    data = aws_json(args)
    if isinstance(data, dict) and "__error__" in data:
        err = data["__error__"]
        print("\nCOST EXPLORER unavailable")
        print("-" * 72)
        if "AccessDenied" in err or "not authorized" in err:
            print("  Access denied. Cost Explorer needs ce:GetCostAndUsage, and")
            print("  must be enabled once in Billing > Cost Explorer.")
        elif "DataUnavailable" in err:
            print("  Enabled but not yet populated — it can take ~24h after first use.")
        else:
            print(f"  {err[:300]}")
        print("  (reporting $0 here would be wrong, so nothing is reported)")
        return

    results = (data or {}).get("ResultsByTime", [])
    if not results:
        print("\nCOST EXPLORER returned no data for the window.")
        return

    # With --group-by, per-day totals live under Groups[], and "Total" is an
    # empty dict. Reading only "Total" therefore sums to zero on a grouped
    # query and fires the "tag not activated" branch on real, non-zero spend --
    # a false negative in exactly the direction this check exists to prevent.
    total_probe = 0.0
    for r in results:
        groups = r.get("Groups") or []
        if groups:
            for g in groups:
                try:
                    total_probe += float(g["Metrics"]["UnblendedCost"]["Amount"])
                except (KeyError, TypeError, ValueError):
                    pass
        else:
            try:
                total_probe += float(r["Total"]["UnblendedCost"]["Amount"])
            except (KeyError, TypeError, ValueError):
                pass
    if not all_account and total_probe == 0.0:
        print(f"\nBILLED — Project={PROJECT_TAG_VALUE}: $0.00 reported")
        print("-" * 72)
        print("  A tag-filtered query returned nothing. Usually this means the")
        print(f"  '{PROJECT_TAG_KEY}' cost allocation tag has not been activated in")
        print("  Billing > Cost allocation tags (activation is NOT retroactive).")
        print("  Re-run with --all-account for the account total, but do not")
        print("  report that as this project's spend.")
        return

    total = 0.0
    per_service: Dict[str, float] = collections.defaultdict(float)
    daily: List[Tuple[str, float]] = []
    for bucket in results:
        day = bucket["TimePeriod"]["Start"]
        if bucket.get("Groups"):
            day_total = 0.0
            for group in bucket["Groups"]:
                amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
                per_service[group["Keys"][0]] += amount
                day_total += amount
        else:
            day_total = float(bucket["Total"]["UnblendedCost"]["Amount"])
        daily.append((day, day_total))
        total += day_total

    print(f"\nBILLED — last {days} day(s), through {results[-1]['TimePeriod']['End']}")
    print("-" * 72)
    for day, amount in daily:
        if amount > 0:
            print(f"  {day}  {money(amount)}")
    print(f"\n  TOTAL  {money(total)}")
    if per_service:
        print("\n  by service:")
        for name, amount in sorted(per_service.items(), key=lambda kv: -kv[1]):
            if amount >= 0.005:
                print(f"    {name:<44} {money(amount)}")
    print("\n  Note: includes EBS, snapshots and transfer, not just instance-hours,")
    print("  so it will exceed (instances x hourly rate). Lags up to ~24h.")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aws_cost.py",
        description="AWS spend and burn rate for the benchmark fleet.",
    )
    parser.add_argument("--days", type=int, default=30,
                        help="days of billed history (default 30)")
    parser.add_argument("--by-instance", action="store_true",
                        help="break billed cost down by service")
    parser.add_argument("--running", action="store_true",
                        help="live state only; makes NO Cost Explorer call "
                             "(free)")
    parser.add_argument("--all-account", action="store_true",
                        help="include instances outside Project=OJCOMS. "
                             "REPORTING ONLY -- they are never to be modified")
    args = parser.parse_args(argv)

    if shutil.which("aws") is None:
        print("aws CLI not found. Install: brew install awscli", file=sys.stderr)
        return 1
    code, out, _ = run(["aws", "sts", "get-caller-identity", "--output", "json"])
    if code != 0:
        print("AWS credentials not configured. Run: aws configure", file=sys.stderr)
        return 1
    print(f"account {json.loads(out).get('Account', '?')}\n")

    burn = report_running(all_account=args.all_account)
    if not args.running:
        cost_explorer(args.days, args.by_instance, args.all_account)
        if burn > 0:
            print(f"\n  At the current burn rate, another 24h adds "
                  f"~{money(burn * 24)} of compute.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
