# Veracode Bitbucket Code Insights

Shows Veracode SAST findings that violate policy **inline in Bitbucket pull requests** and on commits (Code Insights). Bitbucket Cloud or Data Center, from Bitbucket Pipelines or Jenkins. Python 3.10+.

- **Set it up:** [docs/SETUP.md](docs/SETUP.md)
- **Use it (developers):** [docs/DEVELOPERS.md](docs/DEVELOPERS.md)
- **Examples:** [`bitbucket-pipelines.yml`](examples/bitbucket-pipelines.yml) (Cloud) · [`Jenkinsfile`](examples/Jenkinsfile) (Data Center or Cloud)
- **Problems:** [Troubleshooting](#troubleshooting)

Clone or import this repository into your organization; CI downloads the script from your copy ([SETUP step 0](docs/SETUP.md#0-get-the-script)).

## What developers see

A **Veracode SAST** report (PASSED/FAILED) on the commit and PR, and an annotation on each affected line:

> **NEW | Very High | CWE-89 SQL Injection**
> This database query contains a SQL injection flaw... Use a parameterized prepared statement...
> Function: com.acme.OrderDao.find · Fix by 2026-12-01 (policy grace period) · Veracode issue ID: 1234 · link to Veracode

| Build | Results from | Report FAILED when |
|---|---|---|
| Default branch | Policy scan | any finding violates policy |
| Other branches, Jenkins PR builds | Sandbox named after the branch (Jenkins fork PRs: `PR-<n>`) | a `NEW` finding (not in the policy scan) violates policy |

Listed: open findings that violate policy, `NEW` first, then by severity. Approved mitigations are left out; proposed or rejected ones are noted. Bitbucket shows annotations only on changed lines; the report lists all.

## How it works

1. The scan step sets the scan version to `<commit SHA>-<build number>` and, on branches, the sandbox name to the branch name.
2. The report step finds the application profile, waits for that scan and its policy evaluation, then replaces the `veracode-sast` report on the commit.
3. Nothing is posted unless the latest scan is from this commit, so lines always match.

- **Profile:** `VERACODE_APP_NAME`, else `<workspace or PROJECT>/<repo>`, else `<repo>` (case ignored).
- **File paths:** Veracode paths are matched to repository files by the longest common ending (`com/acme/Dao.java` → `src/main/java/com/acme/Dao.java`). No or ambiguous match: listed without a line.
- **Severity:** Very High is `CRITICAL` on Cloud, `HIGH` on Data Center; High `HIGH`; Medium `MEDIUM`; lower `LOW`.
- **Commit, branch, repository:** flags first, then CI variables (`BITBUCKET_*`, Jenkins `GIT_COMMIT`, `CHANGE_BRANCH`, `BRANCH_NAME`, `GIT_URL`), then git.

## Compared to the Veracode Integration for Jira

Jira tracks findings as tickets; this gives feedback on the commit and PR. Use both.

| Jira integration | This tool |
|---|---|
| Issues imported on a schedule | Report per scanned commit, from CI |
| App → project by default or custom field | App found by repository name, or `VERACODE_APP_NAME` |
| Filters (all, latest scan, unmitigated, policy) | Open policy violations of this commit's scan, unmitigated |
| Sandbox findings prefixed "Sandbox" | Sandbox in the report title; `NEW` vs the policy scan |
| Closes fixed issues, reopens returning ones | New report per commit: fixed findings disappear, returning ones reappear |
| Severity → priority | Severity → annotation severity |
| Veracode Link, Mitigation Status fields | Link on every annotation; proposed/rejected mitigation noted |
| Import limit, highest severity first | 1000 annotations per report, `NEW` then severity |
| Static, dynamic, manual, SCA | Static only (others have no line) |
| Results API + Mitigation API roles | Results API (+ Upload and Scan API to scan) |

## Configuration

| Name | Where | Needed for |
|---|---|---|
| `VERACODE_API_ID`, `VERACODE_API_KEY` | CI secrets | Always. HMAC credentials of an API account with **Results API** (+ **Upload and Scan API** for the scan step) |
| `BITBUCKET_TOKEN` | Jenkins credentials | Jenkins. Repository read (Cloud repository access token, Data Center HTTP access token). Not needed in Pipelines |
| `BITBUCKET_URL` | Environment | Data Center only, e.g. `https://bitbucket.example.com` (`http://` works with a warning) |
| `VERACODE_APP_NAME` | Environment | Profile name when it isn't the repository name |
| `BITBUCKET_USER` | Environment | Cloud, when `BITBUCKET_TOKEN` is an Atlassian API token: the account email |
| `BITBUCKET_DEFAULT_BRANCH` | Environment | Same as `--default-branch` |
| `BITBUCKET_PROXY` | Environment | Pipelines proxy (default `http://localhost:29418`; inside a pipe `http://host.docker.internal:29418`) |
| `VERACODE_API_BASE` | Environment | Override the API host (`https://` only); default from the API ID region |

Also accepted: `VERACODE_API_KEY_ID` / `VERACODE_API_KEY_SECRET`, `~/.veracode/credentials`.

| Flag | Default | Purpose |
|---|---|---|
| `--default-branch` | from Bitbucket | Set it in Pipelines (the proxy may refuse the lookup) |
| `--wait` | `20` | Minutes to wait for the scan |
| `--fail-build` | off | Exit 2 when FAILED, 3 when the scan has no usable results |
| `--dry-run` | off | Print the requests instead of posting |
| `--app-name`, `--sandbox-name` | see above | Override profile or sandbox |
| `--commit`, `--branch`, `--repo`, `--server-url` | CI variables | Other CI systems, local runs |
| `--repo-dir` | `.` | Checkout used to match file paths |

| Exit | Meaning |
|---|---|
| `0` | Posted, or nothing to post (reason printed) |
| `1` | Configuration or API error (`ERROR: ...`) |
| `2` | Report FAILED (`--fail-build`) |
| `3` | Scan failed, timed out, or has no matching sandbox (`--fail-build`) |

## Run locally

From a checkout of your application at the scanned commit:

```bash
git clone <your copy of this repository> ~/vbi
pip install --no-deps -r ~/vbi/requirements.txt   # --no-deps skips httpie, which is never used
export VERACODE_API_ID=... VERACODE_API_KEY=...
python ~/vbi/veracode_bb_insights.py --commit <sha> --branch feature/PAY-12 --repo acme/payments-api \
  --default-branch main --dry-run
```

To post: drop `--dry-run`, set `BITBUCKET_TOKEN` (and `BITBUCKET_URL` for Data Center).

## Troubleshooting

| What you see | Why | Fix |
|---|---|---|
| `Nothing posted: latest scan '...' is not named after a commit` | Scan version doesn't start with the SHA | Scan version `<sha>-<build number>` |
| `Nothing posted: latest scan '...' is for another commit` | A newer push started a newer scan | Expected |
| `Nothing posted: No sandbox named '...'` | Scan step used another sandbox name | Use the branch name, or `--sandbox-name` |
| `Nothing posted: Several sandboxes match '...'` | Names differ only by case | Rename/delete one, or `--sandbox-name` |
| `scan '...' did not complete: Pre-Scan Failed` / `No Modules` | The scan failed | Fix packaging or module selection, rerun |
| `stopped waiting after N min` | Scan still running | Raise `--wait`, or post later: Pipelines **Run pipeline > custom: veracode-report**; Jenkins rerun |
| `waiting for the policy evaluation` | Policy still being evaluated | Wait, usually a minute |
| `ERROR: getbuildinfo.do: Access denied` | API account can't read the profile | Results API role and the profile's team |
| `ERROR: no application profile named ...` | Profile name differs | Set `VERACODE_APP_NAME` |
| `ERROR: more than one application profile is named ...` | Two names match ignoring case | Set the exact `VERACODE_APP_NAME` |
| `ERROR: Veracode credentials not found` / `unknown region prefix` | Missing or mistyped API ID | Set `VERACODE_API_ID`, `VERACODE_API_KEY` |
| HTTP 401 from Veracode | Expired, OAuth instead of HMAC, or wrong region | New HMAC credentials; `VERACODE_API_BASE` for region |
| `ERROR: set BITBUCKET_TOKEN` | Outside Pipelines without a token | Add the token |
| `ERROR: could not read the default branch` | Token can't read the repository, or the proxy refused | Pass `--default-branch` |
| `ERROR: repository ... not found on ...` | Wrong Data Center project/slug, or no access | Check `GIT_URL` / `--repo`; personal repos use `~user` |
| Jenkins fork PR report on the fork / `not found` | Fork's `GIT_URL` | Set `VBI_REPO` in the Jenkinsfile |
| `WARNING: BITBUCKET_URL uses http://` | Token sent unencrypted | Use https |
| `ERROR: detached HEAD` / `could not detect ...` | No branch or repo in CI variables | `--branch` / `--repo` |
| `ERROR: ... needs the full 40-character commit SHA` | Short `--commit` on Data Center | Full SHA |
| `ERROR: Bitbucket add annotations failed: HTTP 400` (Data Center) | Server allows fewer than 1000 annotations | Raise the server limit |
| `ERROR: Bitbucket ... HTTP 401/403` | Token scope, or (Data Center) another token created the report | Repository-read token; always the same one |
| Report but no inline annotations | Annotations show on changed lines only | Open the report |
| "not matched to a file" | Generated code, other module, duplicate names, no git | See "Veracode location"; check `--repo-dir` |
| `curl: (22) ... 404` or `401` in the report step | Wrong `VBI_URL`, or the download needs a token | Check the URL; set `VBI_TOKEN` (Pipelines) or `VBI_TOKEN_CREDENTIAL` (Jenkins) |
| `sha256sum: ... did NOT match` (scan steps) | `CLI_SHA256`/`WRAPPER_SHA256` don't match their versions | Update version and checksum together |
| Default branch scan step fails while a policy scan runs | A running policy scan is never deleted | Rerun when it finishes, or let the next merge scan |
| Can't create a sandbox | Sandbox limit reached | Delete sandboxes of merged branches |
| Data Center merge check: report missing | Key isn't `veracode-sast`, or commit not scanned | Fix the key; rerun |

## Limits

- 1000 annotations per report (Data Center: configurable); the rest are counted.
- SAST only.
- Sandboxes of merged branches aren't deleted.
- `--wait` holds the CI runner.
- One report per commit, last run wins (a branch with no new commits replaces the default branch's report on that commit).

## Files

| File | Purpose |
|---|---|
| `veracode_bb_insights.py` | The report step |
| `requirements.txt` | Python packages (install with `--no-deps`) |
| `examples/` | Pipelines and Jenkins examples |
| `docs/` | Setup and developer guides |
