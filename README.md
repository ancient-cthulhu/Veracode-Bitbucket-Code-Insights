# Veracode Bitbucket Code Insights

Shows Veracode SAST findings that violate policy **inline in Bitbucket pull requests** and on commits, as a Code Insights report. Works with Bitbucket Cloud and Bitbucket Data Center, from Bitbucket Pipelines or Jenkins. Python 3.10+.

Start here: [`examples/bitbucket-pipelines.yml`](examples/bitbucket-pipelines.yml) (Pipelines, Cloud) · [`examples/Jenkinsfile`](examples/Jenkinsfile) (Jenkins, Data Center or Cloud)

## What developers see

On the pull request, a **Veracode SAST** report card (PASSED/FAILED) and an annotation on each affected line:

> **NEW | Very High | CWE-89 SQL Injection**
> This database query contains a SQL injection flaw... Use a parameterized prepared statement...
> Function: com.acme.OrderDao.find · Veracode issue ID: 1234 · link to the scan results in Veracode

| Build | Results from | Annotated | Report FAILED when |
|---|---|---|---|
| Default branch | Policy scan | Open findings that violate policy | any finding violates policy |
| Any other branch, and every Jenkins PR build | Sandbox named after the branch (Jenkins fork PRs: `PR-<n>`) | Open findings that violate policy; `NEW` = never in the policy scan | a `NEW` finding violates policy |

Findings are sorted NEW first, then by severity. Closed findings and approved mitigations are left out. Bitbucket shows annotations only on lines the pull request changed; the report lists all of them.

## How it works

1. The scan step uploads to Veracode with the **scan version** set to `<commit SHA>-<build number>` (for example `1a2b3c4d5e6f-87`). On branches it uses the **branch name as the sandbox name**.
2. The report step finds the application profile, waits for that scan's results and policy evaluation, then replaces the `veracode-sast` report on that commit.
3. Results are only posted when the latest scan was made from this commit, so annotations never land on the wrong lines.

**Application profile:** `VERACODE_APP_NAME` if set, otherwise the first exact match (case-insensitive) of `<workspace>/<repo>` (Cloud) or `<PROJECT>/<repo>` (Data Center), then `<repo>`.

**File paths:** Veracode paths (for example `com/acme/OrderDao.java`) are matched to repository files by the longest common ending (`src/main/java/com/acme/OrderDao.java`). A match on the file name alone is only used when the Veracode path is just a file name or the repository file is at the root. Findings with no match or an ambiguous match are listed in the report without a line.

**Detection order:** commit `--commit`, `BITBUCKET_COMMIT`, `GIT_COMMIT`, `git rev-parse HEAD`. Branch `--branch`, `BITBUCKET_BRANCH`, `CHANGE_BRANCH`, `BRANCH_NAME` (used as given), then `GIT_BRANCH` or git with `origin/` removed. Repository `--repo`, `BITBUCKET_WORKSPACE` + `BITBUCKET_REPO_SLUG`, `GIT_URL`, `git remote get-url origin`. In Jenkins PR builds (`CHANGE_ID`), a merge commit that exists only on the agent ("merge with target" strategy) is replaced by its first parent, the PR head; this needs the PR head fetched as a remote branch, which is the Branch Source default. Merge builds scan the merged code, so line numbers can be off in files changed on both sides; "current pull request revision" avoids that.

## Setup

1. Make the scan step follow the naming above (both examples do).
2. Add the report step after the scan step. Pin the script to a release tag and check its SHA-256 (listed in the release notes), as the examples do, or copy the file into your repository. macOS agents: `shasum -a 256 -c` instead of `sha256sum -c`.
3. Add the credentials:

| Name | Where | Needed for |
|---|---|---|
| `VERACODE_API_ID`, `VERACODE_API_KEY` | Pipelines secured variables / Jenkins credentials | Always. API service account: **Upload and Scan API** (scan step) + **Results API** (report step). The report step alone only needs Results API |
| `BITBUCKET_TOKEN` | Jenkins credentials | Jenkins (Cloud or Data Center). Not needed in Bitbucket Pipelines |
| `BITBUCKET_URL` | Environment | Data Center only, e.g. `https://bitbucket.example.com` |

Bitbucket tokens need **repository read**: a Cloud repository access token, or a Data Center HTTP access token. On Data Center only the user that created a report can replace it, so always use the same token.

Other environment variables:

| Name | Purpose |
|---|---|
| `VERACODE_APP_NAME` | Profile name when it does not follow the repo name |
| `BITBUCKET_USER` | Cloud: account email when `BITBUCKET_TOKEN` is an Atlassian API token (Basic auth) |
| `BITBUCKET_DEFAULT_BRANCH` | Same as `--default-branch` |
| `BITBUCKET_PROXY` | Pipelines proxy (default `http://localhost:29418`; use `http://host.docker.internal:29418` inside a pipe) |
| `VERACODE_API_BASE` | Veracode API host. Default: chosen from the API ID region (US, EU, FedRAMP) |

The older names `VERACODE_API_KEY_ID` / `VERACODE_API_KEY_SECRET` and `~/.veracode/credentials` also work.

## Options

| Flag | Default | Purpose |
|---|---|---|
| `--default-branch` | read from Bitbucket | Default branch name. Set it in Pipelines, where the proxy may not allow the repository lookup |
| `--wait` | `20` | Minutes to wait for scan results (approximate) |
| `--fail-build` | off | Exit 2 when the report is FAILED, 3 when the scan has no usable results |
| `--dry-run` | off | Print the Bitbucket request bodies instead of posting |
| `--app-name`, `--sandbox-name` | see above | Override the profile or sandbox name |
| `--commit`, `--branch`, `--repo`, `--server-url` | from CI variables | For other CI systems or local runs |
| `--repo-dir` | `.` | Checkout used to match file paths |

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Report posted, or nothing to post (reason printed): a newer commit's scan replaced this one, tag build, or no usable scan without `--fail-build` |
| `1` | Configuration, argument or API error (`ERROR: ...`) |
| `2` | Report FAILED, with `--fail-build` |
| `3` | With `--fail-build`: the scan failed or timed out, its sandbox is missing or ambiguous, or it is not named after a commit |

## Run locally

```bash
pip install -r requirements.txt
export VERACODE_API_ID=... VERACODE_API_KEY=...
python veracode_bb_insights.py --commit <sha> --branch feature/PAY-12 --repo acme/payments-api \
  --default-branch main --dry-run
```

Drop `--dry-run` and set `BITBUCKET_TOKEN` (and `BITBUCKET_URL` for Data Center) to post.

## Troubleshooting

| What you see | Why | Fix |
|---|---|---|
| `Nothing posted: latest scan '...' is not named after a commit` | Scan version does not start with the SHA | Set the scan version to `<sha>-<build number>` |
| `Nothing posted: latest scan '...' is for another commit` | A newer push started a newer scan | Expected; the newer build posts its own report |
| `Nothing posted: No sandbox named '...'` | Scan step used a different sandbox name | Use the branch name, or pass `--sandbox-name` |
| `Nothing posted: Several sandboxes match '...'` | Sandbox names differ only by case | Rename or delete one, or pass `--sandbox-name` |
| `scan '...' did not complete: Pre-Scan Failed` (or `No Modules`) | The scan itself failed | Fix packaging or module selection in Veracode, then rerun |
| `stopped waiting after N min` | Scan still running | Raise `--wait`, or rerun the report step later with `--commit` and `--branch` |
| `waiting for the policy evaluation` | Results are ready, policy is still being evaluated | Usually a minute; keep waiting |
| `ERROR: getbuildinfo.do: Access denied` (or another message) | The API account cannot read this profile or sandbox | Give the account the Results API role and access to the profile's team |
| `ERROR: no application profile named ...` | Profile name differs from the repo name | Set `VERACODE_APP_NAME` |
| `ERROR: more than one application profile is named ...` | Two profiles match when case is ignored | Set `VERACODE_APP_NAME` to the exact name |
| `ERROR: Veracode credentials not found` / `unknown region prefix` | Missing or mistyped API ID | Set `VERACODE_API_ID` and `VERACODE_API_KEY` |
| `ERROR: set BITBUCKET_TOKEN` | Running outside Pipelines without a token | Add the token credential |
| `ERROR: could not read the default branch` | Token cannot read the repository, or the proxy refuses the lookup | Pass `--default-branch` |
| `ERROR: repository ... not found on ...` | Wrong Data Center project key or slug, or the token lacks access | Check `GIT_URL` / `--repo`; personal repos use `~user` |
| `ERROR: detached HEAD` / `could not detect ...` | No branch or repo in the CI variables | Pass `--branch` / `--repo` |
| `ERROR: Bitbucket Data Center needs the full 40-character commit SHA` | Short `--commit` that the checkout cannot expand | Pass the full SHA |
| `ERROR: Bitbucket add annotations failed: HTTP 400` (Data Center) | The instance allows fewer than 1000 annotations per report | Raise the server limit; the report says the annotations are incomplete |
| `ERROR: Bitbucket ... HTTP 401/403` | Token scope, or (Data Center) another user created the report | Use a repository-read token, and the same token every time |
| Report shows, but no inline annotations | Bitbucket shows annotations only on lines changed in the PR | Open the report to see all findings |
| Findings listed as "not matched to a file" | Path is not in the repo (generated code, other module), matches two files, or git is missing | See "Veracode location" in the annotation; check `--repo-dir` |
| `sha256sum: WARNING: 1 computed checksum did NOT match` | `VBI_REF` and `VBI_SHA256` are from different releases | Use the pair from the release notes |
| HTTP 401 from Veracode | Wrong region or credentials | The region comes from the API ID; set `VERACODE_API_BASE` to override |

## Limits

- Bitbucket stores up to 1000 annotations per report (Data Center: configurable); the rest are counted in the report.
- SAST only (SCA findings have no line number).
- Sandboxes of merged branches are not deleted; clean them up to stay under the sandbox limit.
- Long scans hold the CI runner while `--wait` runs.

## Files

| File | Purpose |
|---|---|
| `veracode_bb_insights.py` | The report step |
| `requirements.txt` | `requests` and its TLS dependencies, `veracode-api-signing`, with safe minimum versions |
| `examples/` | Bitbucket Pipelines and Jenkins examples |
