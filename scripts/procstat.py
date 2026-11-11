#!/usr/bin/env python3
"""procstat.py — print CPU time and RSS of a process from /proc.

Usage: procstat.py <pid>
Output: cpu_total_s=<float> utime_s=<float> stime_s=<float> rss_kb=<int>
CLK_TCK is read from os.sysconf (100 on this VM).
"""
import os
import sys

pid = sys.argv[1]
clk = os.sysconf("SC_CLK_TCK")
with open(f"/proc/{pid}/stat") as f:
    parts = f.read().split()
utime = int(parts[13]) / clk
stime = int(parts[14]) / clk
rss_kb = None
with open(f"/proc/{pid}/status") as f:
    for line in f:
        if line.startswith("VmRSS:"):
            rss_kb = int(line.split()[1])
            break
print(f"cpu_total_s={utime + stime:.3f} utime_s={utime:.3f} stime_s={stime:.3f} rss_kb={rss_kb}")
