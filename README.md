# Veracode Bitbucket Code Insights

Shows Veracode SAST findings that violate policy **inline in Bitbucket pull requests** and on commits, as a Code Insights report. Works with Bitbucket Cloud and Bitbucket Data Center, from Bitbucket Pipelines or Jenkins.

Start here: [`examples/bitbucket-pipelines.yml`](examples/bitbucket-pipelines.yml) (Pipelines, Cloud) · [`examples/Jenkinsfile`](examples/Jenkinsfile) (Jenkins, Data Center or Cloud)

## What developers see

On the pull request, a **Veracode SAST** report card (PASSED/FAILED) and an annotation on each affected line:

> **NEW | Very High | CWE-89 SQL Injection**
> This database query contains a SQL injection flaw... Use a parameterized prepared statement...
> Function: com.acme.OrderDao.find · Veracode issue ID: 1234 · link to the scan results in Veracode

| Branch | Results from | Annotated | Report FAILED when |
|---|---|---|---|
| Default branch | Policy scan | Open findings that violate policy | any finding violates policy |
| Any other branch | Sandbox named after the branch | Open findings that violate policy; `NEW` = not in the policy scan | a `NEW` finding violates policy |

Findings are sorted NEW first, then by severity. Closed findings and approved mitigations are left out.

## How it works

1. The scan step uploads to Veracode with the **scan version** set to `<commit SHA>-<build number>` (for example `1a2b3c4d5e6f-87`). On branches it uses the **branch name as the sandbox name**.
2. The report step finds the application profile, waits for that scan's results and policy evaluation, then replaces the `veracode-sast` report on that commit.
3. Results are only posted when the latest scan was made from this commit, so annotations never land on the wrong lines.

**Application profile:** `VERACODE_APP_NAME` if set, otherwise the first exact match (case-insensitive) of `<workspace>/<repo>` (Cloud) or `<PROJECT>/<repo>` (Data Center), then `<repo>`.

**File paths:** Veracode paths (for example `com/acme/OrderDao.java`) are matched to repository files by the longest common ending (`src/main/java/com/acme/OrderDao.java`). Findings with no match or an ambiguous match are listed in the report without a line.

## Setup

1. Make the scan step follow the naming above (both examples do).
2. Add the report step after the scan step.
3. Add the credentials:

| Name | Where | Needed for |
|---|---|---|
| `VERACODE_API_ID`, `VERACODE_API_KEY` | Pipelines secured variables / Jenkins credentials | Always. API service account with the Results API role |
| `BITBUCKET_TOKEN` | Jenkins credentials | Jenkins (Cloud or Data Center). Not needed in Bitbucket Pipelines |
| `BITBUCKET_URL` | Environment | Data Center only, e.g. `https://bitbucket.example.com` |
| `BITBUCKET_USER` | Environment | Optional, Cloud: account email when `BITBUCKET_TOKEN` is an Atlassian API token |
| `VERACODE_APP_NAME` | Environment | Optional: profile name when it does not follow the repo name |

Bitbucket tokens: Cloud repository access token with **Repositories: Read**; Data Center HTTP access token with **Repository read** (use write if the server refuses). On Data Center only the user that created a report can replace it, so always use the same token.

## Options

| Flag | Default | Purpose |
|---|---|---|
| `--default-branch` | read from Bitbucket | Default branch name. Set it in Pipelines (also `BITBUCKET_DEFAULT_BRANCH`) |
| `--wait` | `20` | Minutes to wait for scan results |
| `--fail-build` | off | Exit 2 when the report is FAILED |
| `--dry-run` | off | Print the report and annotations instead of posting |
| `--app-name`, `--sandbox-name` | see above | Override the profile or sandbox name |
| `--commit`, `--branch`, `--repo`, `--server-url` | from CI variables | For other CI systems or local runs |
| `--repo-dir` | `.` | Checkout used to match file paths |

Exit codes: `0` posted or nothing to post (the reason is printed), `1` configuration or API error, `2` report FAILED with `--fail-build`.

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
| `stopped waiting after N min` | Scan still running | Raise `--wait` |
| `no application profile named ...` | Profile name differs from the repo name | Set `VERACODE_APP_NAME` |
| Report shows, but no inline annotations | Bitbucket shows annotations only on lines changed in the PR | Open the report to see all findings |
| Findings listed as "not matched to a file" | Path is not in the repo (generated code, other module) or matches two files | See "Veracode location" in the annotation |
| Jenkins PR build posts nothing | "Merge with target" builds a local merge commit | Both the example and the script use its first parent; or use the "current pull request revision" strategy |
| HTTP 401 from Veracode | Wrong region or credentials | The region comes from the API ID; set `VERACODE_API_BASE` to override |

## Limits

- Bitbucket stores up to 1000 annotations per report; the rest are counted in the report.
- SAST only (SCA findings have no line number).
- Sandboxes of merged branches are not deleted; clean them up to stay under the sandbox limit.

## Files

| File | Purpose |
|---|---|
| `veracode_bb_insights.py` | The report step |
| `requirements.txt` | `requests`, `veracode-api-signing` |
| `examples/` | Bitbucket Pipelines and Jenkins examples |
