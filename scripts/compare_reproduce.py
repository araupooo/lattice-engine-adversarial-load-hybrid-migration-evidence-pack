#!/usr/bin/env python3
"""compare_reproduce.py — compare re-derived (fresh-clone-*) headline numbers
against the shipped ones in pack/outputs/.

Usage: compare_reproduce.py <outputs-dir>
Prints one PASS/FAIL line per check and exits non-zero if any check fails.

Tolerances: KEM encaps/decaps means within 25%; handshake medians within
25% or 5 ms; flood median latency within 50% or 20 ms; exact match for
failure counts, key_share lengths, and slow-loris outcomes.

The ML-KEM-768 keypair mean is NOT compared at 25%: it is outlier-sensitive
(first-call warm-up; the shipped run1 mean of 56.63 us carries a 7474 us
outlier — see docs/methodology.md limitation L4). For keypair the check is:
min within 25% (the stable figure) AND mean within 2x.
"""
import csv
import re
import sys

OUT = sys.argv[1]
fails = []


def check(name, ok, detail=""):
    print(("PASS" if ok else "FAIL"), name, detail)
    if not ok:
        fails.append(name)


def read(p):
    with open(f"{OUT}/{p}", errors="ignore") as f:
        return f.read()


def bench_numbers(fn):
    t = read(fn)
    m = {}
    for label in ("keypair", "encaps", "decaps"):
        mm = re.search(rf"ML-KEM-768 {label}\s+n=\d+\s+mean=\s*([\d.]+) us\s+min=\s*([\d.]+) us", t)
        m[label] = (float(mm.group(1)), float(mm.group(2))) if mm else (None, None)
    m["mismatch"] = int(re.search(r"shared-secret mismatches: (\d+)", t).group(1))
    m["sizes_ok"] = t.count(" OK") >= 4
    return m


def baseline_numbers(fn):
    t = read(fn)
    mm = re.search(r"handshake summary \([^)]+\): n=(\d+) mean=([\d.]+) ms median=([\d.]+) ms min=(\d+) ms max=(\d+) ms", t)
    fail = int(re.search(r"handshake failures: (\d+) / (\d+)", t).group(1))
    ks = re.search(r"key_exchange_len=(\d+)", t)
    return {"n": int(mm.group(1)), "mean": float(mm.group(2)), "median": float(mm.group(3)),
            "min": int(mm.group(4)), "max": int(mm.group(5)), "failures": fail,
            "key_exchange_len": int(ks.group(1)) if ks else None}


def flood_numbers(fn):
    rows = list(csv.DictReader(open(f"{OUT}/{fn}")))
    ok = sum(1 for r in rows if r["ok"] == "True")
    lat = sorted(float(r["ms"]) for r in rows)
    return {"n": len(rows), "ok": ok, "median": lat[len(lat) // 2]}


def close(a, b, rel=0.25, abs_tol=5.0):
    return abs(a - b) <= max(rel * abs(b), abs_tol)


# --- bench_kem ---
for run in ("run1", "run2"):
    s, f = bench_numbers(f"bench-kem-{run}.log"), bench_numbers(f"fresh-clone-bench-kem-{run}.log")
    check(f"bench {run} sizes OK (FIPS 203 Table 3)", f["sizes_ok"], "fresh")
    check(f"bench {run} sizes OK (FIPS 203 Table 3)", s["sizes_ok"], "shipped")
    check(f"bench {run} shared-secret mismatches 0", f["mismatch"] == 0 and s["mismatch"] == 0)
    # keypair: min within 25% (stable), mean within 2x (outlier-sensitive, see L4)
    check(f"bench {run} keypair min within 25% and mean within 2x",
          s["keypair"][1] is not None and f["keypair"][1] is not None
          and close(f["keypair"][1], s["keypair"][1])
          and f["keypair"][0] <= 2 * s["keypair"][0] and s["keypair"][0] <= 2 * f["keypair"][0],
          f"shipped mean={s['keypair'][0]} min={s['keypair'][1]} us; fresh mean={f['keypair'][0]} min={f['keypair'][1]} us")
    for label in ("encaps", "decaps"):
        check(f"bench {run} {label} mean within 25%",
              s[label][0] is not None and f[label][0] is not None and close(f[label][0], s[label][0]),
              f"shipped={s[label][0]} us fresh={f[label][0]} us")

# --- baselines ---
for label, kslen in (("hybrid", 1216), ("fallback", 32)):
    for run in ("run1", "run2"):
        s = baseline_numbers(f"baseline-{label}-{run}.log")
        f = baseline_numbers(f"fresh-clone-baseline-{label}-{run}.log")
        check(f"baseline {label} {run} failures 0/30", s["failures"] == 0 and f["failures"] == 0)
        check(f"baseline {label} {run} key_share len {kslen}",
              s["key_exchange_len"] == kslen and f["key_exchange_len"] == kslen,
              f"shipped={s['key_exchange_len']} fresh={f['key_exchange_len']}")
        check(f"baseline {label} {run} median within 25% or 5 ms",
              close(f["median"], s["median"]),
              f"shipped median={s['median']} ms fresh median={f['median']} ms")

# --- adversarial: malformed / truncated (server must stay alive: every probe ok) ---
for run in ("run1", "run2"):
    for kind in ("malformed", "truncated"):
        for prefix in ("", "fresh-clone-"):
            rows = list(csv.DictReader(open(f"{OUT}/{prefix}adversarial-{run}-{kind}.csv")))
            bad = [r for r in rows if r["probe_ok"] != "True"]
            check(f"adversarial {run} {kind} ({'fresh' if prefix else 'shipped'}) server alive after every trial",
                  len(bad) == 0, f"{len(rows)} trials, {len(bad)} probes failed")
        srows = list(csv.DictReader(open(f"{OUT}/adversarial-{run}-{kind}.csv")))
        frows = list(csv.DictReader(open(f"{OUT}/fresh-clone-adversarial-{run}-{kind}.csv")))
        check(f"adversarial {run} {kind} trial counts match", len(srows) == len(frows),
              f"shipped={len(srows)} fresh={len(frows)}")

# --- flood ---
for run in ("run1", "run2"):
    s, f = flood_numbers(f"adversarial-{run}-flood.csv"), flood_numbers(f"fresh-clone-adversarial-{run}-flood.csv")
    check(f"flood {run} success 200/200", s["ok"] == 200 and f["ok"] == 200,
          f"shipped={s['ok']}/200 fresh={f['ok']}/200")
    check(f"flood {run} median latency within 50%", close(f["median"], s["median"], rel=0.5, abs_tol=20.0),
          f"shipped median={s['median']} ms fresh median={f['median']} ms")

# --- slowloris summaries ---
for run in ("run1", "run2"):
    for prefix in ("", "fresh-clone-"):
        t = read(f"{prefix}adversarial-{run}-slowloris-summary.txt")
        during = re.search(r"probe_during_stall ok=(\w+)", t).group(1)
        after = re.search(r"probe_after_release ok=(\w+)", t).group(1)
        check(f"slowloris {run} ({'fresh' if prefix else 'shipped'}) legitimate handshake blocked during stall",
              during == "False", f"probe_during_stall ok={during}")
        check(f"slowloris {run} ({'fresh' if prefix else 'shipped'}) legitimate handshake succeeds after release",
              after == "True", f"probe_after_release ok={after}")

print()
if fails:
    print(f"COMPARISON: {len(fails)} FAILURES: {', '.join(fails)}")
    sys.exit(1)
print("COMPARISON: ALL CHECKS PASSED")
