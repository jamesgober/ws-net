"""Prints criterion results as Markdown tables.

Usage: python3 bench-compare/summary.py <criterion dir> [<baseline name>]

For every benchmark, the median of the latest run ("new") and, when a
baseline name is given and exists, the median of that baseline and the
change. Groups whose functions include "tungstenite" also get the ratio of
tungstenite's median to ws-net's (above 1.00: ws-net is faster).
"""

import json
import os
import sys


def median_ns(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)["median"]["point_estimate"]
    except (OSError, KeyError, ValueError):
        return None


def fmt(ns):
    if ns is None:
        return "-"
    for unit, scale in (("s", 1e9), ("ms", 1e6), ("µs", 1e3)):
        if ns >= scale:
            return f"{ns / scale:.3g} {unit}"
    return f"{ns:.3g} ns"


def main(root, baseline=None):
    rows = []
    for group in sorted(os.listdir(root)):
        gdir = os.path.join(root, group)
        if not os.path.isdir(gdir) or group == "report":
            continue
        for func in sorted(os.listdir(gdir)):
            fdir = os.path.join(gdir, func)
            new = median_ns(os.path.join(fdir, "new", "estimates.json"))
            if new is None:
                continue
            base = median_ns(os.path.join(fdir, baseline, "estimates.json")) if baseline else None
            rows.append((group, func, new, base))
    print("| Benchmark | Median | " + (f"{baseline} | Change |" if baseline else "") )
    print("|---|---:|" + ("---:|---:|" if baseline else ""))
    for group, func, new, base in rows:
        line = f"| {group}/{func} | {fmt(new)} |"
        if baseline:
            change = f"{(new / base - 1) * 100:+.1f}%" if base else "-"
            line += f" {fmt(base)} | {change} |"
        print(line)
    ratios = {}
    for group, func, new, _ in rows:
        ratios.setdefault(group, {})[func] = new
    lines = []
    for group, funcs in ratios.items():
        t = funcs.get("tungstenite") or funcs.get("tungstenite_accept")
        w = funcs.get("ws_net") or funcs.get("ws_net_accept")
        if t and w:
            lines.append(f"| {group} | {fmt(w)} | {fmt(t)} | {t / w:.2f} |")
    if lines:
        print()
        print("| Workload | ws-net | tungstenite | tungstenite / ws-net |")
        print("|---|---:|---:|---:|")
        print("\n".join(lines))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
