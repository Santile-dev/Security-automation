# Security Automation Question 1: security scanning script


This is a small script that scans a project for common security issues and tells you if it passed or failed.

It runs four tools at once:

- bandit, for risky Python code
- pip-audit, for libraries with known vulnerabilities
- gitleaks, for passwords and keys left in the code
- checkov, for insecure Terraform

Anything rated HIGH or above fails the scan. If one of the tools crashes, the scan fails too. I didn't want a broken tool to look like a clean result.

# Running it

```bash
./security-scan.py --path ./app
```

Add `--format json` if you need the output for a pipeline, or `--fail-on medium` to be stricter.

It exits with 0 when it passes and 1 when it fails, so you can drop it into CI and it will stop the build.

# Tests

The `app` folder is insecure on purpose, so it should always fail.

There are also three quick tests in `testinghub`. One is clean and should pass, one has a leaked API key, and one has SSH port 22 open to the world. Run them with:

```bash
./testinghub/run-tests.sh
```
