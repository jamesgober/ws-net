"""Fails unless every Autobahn case in a report index is strictly OK.

Usage: python3 autobahn/check.py autobahn/reports/servers/index.json

The pass rule: every case, sections 1 to 13 (12 and 13 are
permessage-deflate, run with the `deflate` feature), has behavior OK and
close behavior OK; INFORMATIONAL results are allowed and listed;
NON-STRICT, FAILED, and UNIMPLEMENTED count as failures.
"""

import json
import sys

ALLOWED = {"OK", "INFORMATIONAL"}


def main(path):
    with open(path, encoding="utf-8") as f:
        index = json.load(f)
    failures = []
    informational = []
    total = 0
    for agent, cases in index.items():
        for case, result in sorted(cases.items()):
            total += 1
            behavior = result.get("behavior")
            close = result.get("behaviorClose")
            if behavior == "INFORMATIONAL":
                informational.append(case)
            if behavior not in ALLOWED or close not in ALLOWED:
                failures.append(f"{agent} {case}: behavior {behavior}, close {close}")
    print(f"{total} cases, {len(failures)} failures, {len(informational)} informational")
    if informational:
        print("informational: " + ", ".join(informational))
    for line in failures:
        print("FAIL " + line)
    if total == 0:
        print("FAIL no cases in the report")
        return 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
