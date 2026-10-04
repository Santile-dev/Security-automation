#!/usr/bin/env python3
import argparse, json, subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
CHECKOV_HIGH = {"CKV_AWS_16", "CKV_AWS_17", "CKV_AWS_20", "CKV_AWS_24", "CKV_AWS_25"}


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if p.returncode > 1:
        raise RuntimeError(p.stderr.strip()[-200:])
    return p.stdout


def sast(path):
    data = json.loads(run(["bandit", "-r", path, "-f", "json", "-q", "-x", "*/.venv/*"]))
    return [(r["issue_severity"], r["test_id"], r["filename"], r["issue_text"]) for r in data["results"]]


def deps(path):
    out = []
    for req in Path(path).rglob("requirements*.txt"): 
        data = json.loads(run(["pip-audit", "-r", str(req), "--no-deps", "--disable-pip", "-f", "json"]))
        out += [("HIGH", v["id"], str(req), f"{d['name']} {d['version']}") for d in data["dependencies"] for v in d.get("vulns", [])]
    return out


def secrets(path):
    with tempfile.NamedTemporaryFile(suffix=".json") as f:  
        run(["gitleaks", "dir", path, "--redact", "--exit-code", "0", "--report-format", "json", "--report-path", f.name])
        return [("CRITICAL", r["RuleID"], r["File"], r["Description"]) for r in json.load(open(f.name))]


def iac(path):
    out = run(["checkov", "-d", path, "-o", "json", "--quiet", "--compact", "--skip-download"]) or "[]"
    reports = json.loads(out)
    reports = reports if isinstance(reports, list) else [reports]
    return [("HIGH" if c["check_id"] in CHECKOV_HIGH else "MEDIUM", c["check_id"], c["file_path"], c["check_name"])
            for r in reports for c in r.get("results", {}).get("failed_checks", [])]


def scan(name, fn, path):
    try:
        return name, "ok", fn(path)
    except Exception as e:  
        return name, f"error: {e}", []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", required=True)
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--fail-on", type=str.upper, choices=SEVERITIES, default="HIGH")
    a = ap.parse_args()

    with ThreadPoolExecutor() as pool:  
        scans = [pool.submit(scan, n, f, a.path) for n, f in
                 [("sast", sast), ("deps", deps), ("secrets", secrets), ("iac", iac)]]
        results = [s.result() for s in scans]

    findings = sorted(({"category": n, "severity": s, "rule": r, "file": f, "message": m}
                       for n, _, items in results for s, r, f, m in items),
                      key=lambda x: -SEVERITIES.index(x["severity"]))
    blocking = [f for f in findings if SEVERITIES.index(f["severity"]) >= SEVERITIES.index(a.fail_on)]
    errors = [n for n, status, _ in results if status != "ok"]
    decision = "FAIL" if blocking or errors else "PASS"  

    report = {"decision": decision, "fail_on": a.fail_on, "blocking": len(blocking), "scanner_errors": errors,
              "scanners": {n: status for n, status, _ in results}, "findings": findings}
    if a.format == "json":
        print(json.dumps(report, indent=2))
    else:
        for n, status, items in results:
            print(f"{n:<8} {status:<8} {len(items)} findings")
        for f in findings:
            print(f"{f['severity']:<8} [{f['category']}] {f['rule']}  {f['file']}  {f['message']}")
        print(f"\nDecision: {decision} ({len(blocking)} at or above {a.fail_on}, scanner errors: {errors or 'none'})")
    return 0 if decision == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
