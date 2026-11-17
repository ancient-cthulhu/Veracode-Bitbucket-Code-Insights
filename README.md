# Veracode Bitbucket Code Insights

Shows Veracode SAST findings that violate policy **inline in Bitbucket pull requests** and on commits, as a Code Insights report. Works with Bitbucket Cloud and Bitbucket Data Center, from Bitbucket Pipelines or Jenkins. Python 3.10+.

Start here: [Get started](#get-started) · [`examples/bitbucket-pipelines.yml`](examples/bitbucket-pipelines.yml) (Pipelines, Cloud) · [`examples/Jenkinsfile`](examples/Jenkinsfile) (Jenkins, Data Center or Cloud) · [Troubleshooting](#troubleshooting)

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

## Get started

You don't need to clone or fork this repository. The report step downloads a released version of `veracode_bb_insights.py` and checks its SHA-256, so you only copy one example file into your repository. Clone it only to [run it locally](#run-locally) or to [host your own copy](#no-github-access-from-ci).

### Before you start

| Need | Details |
|---|---|
| Veracode API service account | Roles **Upload and Scan API** and **Results API**, with access to the application profile's team |
| Veracode application profile | Must already exist (the examples don't create profiles). Name it `<workspace>/<repo>`, `<PROJECT>/<repo>` or `<repo>`, or set `VERACODE_APP_NAME` |
| Network access from CI | `raw.githubusercontent.com` (script), `pypi.org` (Python packages), `tools.veracode.com` and `repo1.maven.org` (Veracode CLI and API wrapper), the Veracode API (`api.veracode.com`, `.eu` or `.us`), and Bitbucket |
| Bitbucket | Cloud, or Data Center with Code Insights (5.15 or later) |

### Bitbucket Pipelines (Cloud)

1. Copy [`examples/bitbucket-pipelines.yml`](examples/bitbucket-pipelines.yml) to the root of your repository as `bitbucket-pipelines.yml` (or copy its three steps into your existing file).
2. Edit the **Package** step for your application: it uses a Maven/Java 17 image and the Veracode CLI autopackager (`veracode package`). Use an image that can build your language, or replace the step with your own build that puts the files to scan in `verascan/`.
3. If your default branch isn't `main`, change `main` in the three places marked in the file.
4. Enable Pipelines (**Repository settings > Pipelines > Settings**).
5. Add the repository variables (**Repository settings > Pipelines > Repository variables**): `VERACODE_API_ID` and `VERACODE_API_KEY`, both **Secured**. Add `VERACODE_APP_NAME` if the profile name differs from the repository name. No Bitbucket token is needed.
6. Push a branch and open a pull request. When the pipeline finishes, the **Veracode SAST** report is on the commit and in the PR's **Reports**, with annotations on changed lines.

### Jenkins (Data Center or Cloud)

1. Install the **Veracode Scan** and **Bitbucket Branch Source** plugins. Agents need Linux or macOS with `git`, `curl`, `sha256sum` and Python 3.10+ with `venv`.
2. Add two credentials (**Manage Jenkins > Credentials**):
   - Username with password: Veracode API ID / API key.
   - Secret text: a Bitbucket token with **repository read** (Data Center HTTP access token, or Cloud repository access token).
3. Copy [`examples/Jenkinsfile`](examples/Jenkinsfile) to the root of your repository and edit:
   - `BITBUCKET_URL`: your Data Center URL, or `''` for Bitbucket Cloud.
   - `DEFAULT_BRANCH` and `VERACODE_APP_NAME`.
   - `<veracode-api>` and `<bitbucket-token>`: your credential IDs.
   - The **Build** stage and `uploadIncludesPattern`: your build and the files to scan.
   - `VBI_REPO`: only if you build fork PRs.
4. Create a **Multibranch Pipeline** job with a Bitbucket branch source for the repository, discovering branches and pull requests.
5. Push a branch and open a pull request. When the build finishes, the report is on the commit and the PR.

Leave `VBI_REF` and `VBI_SHA256` as they are; they select the release of the script. To upgrade, copy both from the newer release's notes. The examples pin the Veracode CLI and API wrapper the same way: change a version and its checksum together. macOS agents: `shasum -a 256 -c` instead of `sha256sum -c`.

### No GitHub access from CI

Host the script yourself and keep the checksum check:

```bash
git clone https://github.com/ancient-cthulhu/Veracode-Bitbucket-Code-Insights.git
cd Veracode-Bitbucket-Code-Insights
git checkout v1.0.0
sha256sum veracode_bb_insights.py   # must equal VBI_SHA256 in the examples (Linux/macOS checkout; Windows may change line endings)
```

Publish `veracode_bb_insights.py` to an internal location your CI can read (for example Artifactory, or a tools repository in your Bitbucket) and replace the `raw.githubusercontent.com` URL in the `curl` line of the example. For a PyPI mirror, add `--index-url https://<mirror>/simple` to the `pip install` commands.

### Credentials and variables

| Name | Where | Needed for |
|---|---|---|
| `VERACODE_API_ID`, `VERACODE_API_KEY` | Pipelines secured variables / Jenkins credentials | Always. API service account: **Upload and Scan API** (scan step) + **Results API** (report step). The report step alone only needs Results API |
| `BITBUCKET_TOKEN` | Jenkins credentials | Jenkins (Cloud or Data Center). Not needed in Bitbucket Pipelines |
| `BITBUCKET_URL` | Environment | Data Center only, e.g. `https://bitbucket.example.com` (plain `http://` works but prints a warning: the token is sent unencrypted) |

Bitbucket tokens need **repository read**: a Cloud repository access token, or a Data Center HTTP access token. On Data Center only the user that created a report can replace it, so always use the same token.

Other environment variables:

| Name | Purpose |
|---|---|
| `VERACODE_APP_NAME` | Profile name when it does not follow the repo name |
| `BITBUCKET_USER` | Cloud: account email when `BITBUCKET_TOKEN` is an Atlassian API token (Basic auth) |
| `BITBUCKET_DEFAULT_BRANCH` | Same as `--default-branch` |
| `BITBUCKET_PROXY` | Pipelines proxy (default `http://localhost:29418`; use `http://host.docker.internal:29418` inside a pipe) |
| `VERACODE_API_BASE` | Veracode API host, `https://` only. Default: chosen from the API ID region (US, EU, FedRAMP) |

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
| `0` | Report posted, or nothing to post (reason printed): the latest scan is for another commit, tag build, or no usable scan without `--fail-build` |
| `1` | Configuration, argument or API error (`ERROR: ...`) |
| `2` | Report FAILED, with `--fail-build` |
| `3` | With `--fail-build`: the scan failed or timed out, its sandbox is missing or ambiguous, or it is not named after a commit |

## Run locally

Useful to check the profile, sandbox and file matching before setting up CI. Run it from a checkout of your application repository, at the commit that was scanned.

```bash
git clone https://github.com/ancient-cthulhu/Veracode-Bitbucket-Code-Insights.git ~/vbi
pip install --no-deps -r ~/vbi/requirements.txt   # skips httpie, which veracode-api-signing declares but this tool never uses
export VERACODE_API_ID=... VERACODE_API_KEY=...
python ~/vbi/veracode_bb_insights.py --commit <sha> --branch feature/PAY-12 --repo acme/payments-api \
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
| `stopped waiting after N min` | Scan still running | Raise `--wait`, or post later: Pipelines **Run pipeline > custom: veracode-report** on the commit; Jenkins rerun the build or run the script with `--commit` and `--branch` |
| `waiting for the policy evaluation` | Results are ready, policy is still being evaluated | Usually a minute; keep waiting |
| `ERROR: getbuildinfo.do: Access denied` (or another message) | The API account cannot read this profile or sandbox | Give the account the Results API role and access to the profile's team |
| `ERROR: no application profile named ...` | Profile name differs from the repo name | Set `VERACODE_APP_NAME` |
| `ERROR: more than one application profile is named ...` | Two profiles match when case is ignored | Set `VERACODE_APP_NAME` to the exact name |
| `ERROR: Veracode credentials not found` / `unknown region prefix` | Missing or mistyped API ID | Set `VERACODE_API_ID` and `VERACODE_API_KEY` |
| `ERROR: set BITBUCKET_TOKEN` | Running outside Pipelines without a token | Add the token credential |
| `ERROR: could not read the default branch` | Token cannot read the repository, or the proxy refuses the lookup | Pass `--default-branch` |
| `ERROR: repository ... not found on ...` | Wrong Data Center project key or slug, or the token lacks access | Check `GIT_URL` / `--repo`; personal repos use `~user` |
| Jenkins fork PR report goes to the fork, or `repository ... not found` | The fork checkout's `GIT_URL` points at the fork | Set `VBI_REPO` in the Jenkinsfile (passes `--repo`) |
| `WARNING: BITBUCKET_URL uses http://` | Data Center URL is not https | Use the server's https URL |
| `ERROR: detached HEAD` / `could not detect ...` | No branch or repo in the CI variables | Pass `--branch` / `--repo` |
| `ERROR: Bitbucket Data Center needs the full 40-character commit SHA` | Short `--commit` that the checkout cannot expand | Pass the full SHA |
| `ERROR: Bitbucket add annotations failed: HTTP 400` (Data Center) | The instance allows fewer than 1000 annotations per report | Raise the server limit; the report says the annotations are incomplete |
| `ERROR: Bitbucket ... HTTP 401/403` | Token scope, or (Data Center) another user created the report | Use a repository-read token, and the same token every time |
| Report shows, but no inline annotations | Bitbucket shows annotations only on lines changed in the PR | Open the report to see all findings |
| Findings listed as "not matched to a file" | Path is not in the repo (generated code, other module), matches two files, or git is missing | See "Veracode location" in the annotation; check `--repo-dir` |
| `curl: (22) ... 404` in the report step | `VBI_REF` is not a published tag or commit | Use a release tag from the repository's releases |
| `sha256sum: WARNING: 1 computed checksum did NOT match` | A pinned version and its checksum don't belong together (`VBI_REF`/`VBI_SHA256`, `CLI_VERSION`/`CLI_SHA256`, `WRAPPER`/`WRAPPER_SHA256`) | Use the pair from the release notes, or the `sha256sum` of the downloaded file |
| Scan step fails on the default branch while a policy scan is running | `deleteincompletescan 1` never deletes a running policy scan, so a new one can't start | Expected on busy branches; rerun the step when the running scan finishes, or let the next merge scan the newer code |
| Scan step can't create a sandbox | The application reached its sandbox limit | Delete sandboxes of merged branches (Veracode UI or Sandbox API) |
| HTTP 401 from Veracode | Wrong region or credentials | The region comes from the API ID; set `VERACODE_API_BASE` to override |

## Limits

- Bitbucket stores up to 1000 annotations per report (Data Center: configurable); the rest are counted in the report.
- SAST only (SCA findings have no line number).
- Sandboxes of merged branches are not deleted; clean them up to stay under the sandbox limit.
- Long scans hold the CI runner while `--wait` runs.
- One report per commit: the last run wins, so a branch pushed with no new commits replaces the default branch's report on that commit.
- With a token, the report step reads the repository once before waiting, so a bad token or repository fails early. In Pipelines (proxy) that check happens only when results are posted.

## Files

| File | Purpose |
|---|---|
| `veracode_bb_insights.py` | The report step |
| `requirements.txt` | Every package the script imports, with safe minimum versions and major-version caps; install with `--no-deps` |
| `examples/` | Bitbucket Pipelines and Jenkins examples |
