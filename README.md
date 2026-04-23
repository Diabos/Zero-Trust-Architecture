# AZTIH Hardening Runner (CLI)

CLI-only security automation tool that applies Linux hardening controls over SSH and generates verification evidence.

## What It Does

`npm run apply` connects to a target Linux machine and runs `scripts/zero_trust_harden.sh` to apply:

1. SSH hardening baseline
2. UFW default-deny firewall baseline
3. Fail2Ban SSH jail configuration
4. Kernel hardening sysctl parameters
5. auditd identity watch rules
6. Verification and post-run evidence generation

## Quick Start (Fresh Clone)

1. Install dependencies:
- `npm install`

2. Create `.env` from template:
- `npm run setup`

3. Edit `.env` and set target values:
- `TARGET_SERVER_HOST`
- `TARGET_SERVER_USER`
- `TARGET_SERVER_PASSWORD` or `TARGET_SERVER_SSH_KEY`
- `TARGET_SERVER_PORT`

4. Verify configuration:
- `npm run status`

5. Preview actions without changes:
- `npm run demo`

6. Execute real hardening:
- `npm run apply`

## CLI Commands

1. `npm run status` -> validates target readiness
2. `npm run plan` -> prints hardening plan
3. `npm run demo` -> dry run (no remote changes)
4. `npm run apply` -> real hardening + report generation

For machine-readable output:
- `node scripts/cli.js <command> --json`

## Output Artifacts

After `npm run apply`, reports are created in `reports/`:

1. `hardening-verification-<timestamp>.json`
2. `hardening-verification-<timestamp>.md`

These include:

1. Control effectiveness summary (PASS/FAIL/NA)
2. Attack surface delta (pre vs post)
3. Likelihood-impact "So-What" narrative

## Safety Notes

1. Test on a VM snapshot first
2. Keep one console session open while hardening
3. Use demo mode before apply in new environments
