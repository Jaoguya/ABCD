#!/usr/bin/env python3
"""Report AWS spend and current burn rate for the benchmark fleet.

Two sources, deliberately kept separate because they answer different
questions and can legitimately disagree:

  Cost Explorer   what AWS actually billed. Authoritative, lags ~24h, and
                  costs $0.01 per get-cost-and-usage call.
  EC2 describe    what is running right now, hence the burn rate. Free.

Reports only. Never stops, starts, or terminates anything.
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
def instances() -> List[Dict[str, Any]]:
    data = aws_json([
        "ec2", "describe-instances",
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


def report_running(show_storage: bool = True) -> float:
    rows = instances()
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
def cost_explorer(days: int, by_instance: bool) -> None:
    end = dt.date.today() + dt.timedelta(days=1)
    start = end - dt.timedelta(days=days + 1)
    args = [
        "ce", "get-cost-and-usage",
        "--time-period", f"Start={start},End={end}",
        "--granularity", "DAILY",
        "--metrics", "UnblendedCost",
    ]
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
    args = parser.parse_args(argv)

    if shutil.which("aws") is None:
        print("aws CLI not found. Install: brew install awscli", file=sys.stderr)
        return 1
    code, out, _ = run(["aws", "sts", "get-caller-identity", "--output", "json"])
    if code != 0:
        print("AWS credentials not configured. Run: aws configure", file=sys.stderr)
        return 1
    print(f"account {json.loads(out).get('Account', '?')}\n")

    burn = report_running()
    if not args.running:
        cost_explorer(args.days, args.by_instance)
        if burn > 0:
            print(f"\n  At the current burn rate, another 24h adds "
                  f"~{money(burn * 24)} of compute.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
