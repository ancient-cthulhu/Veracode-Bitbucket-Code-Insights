# Setup guide

From the Veracode account to the first report. Developers: [DEVELOPERS.md](DEVELOPERS.md). Back to the [README](../README.md).

0. [Get the script](#0-get-the-script) (once)
1. [Veracode](#1-veracode) (once)
2. [Bitbucket Pipelines](#2a-bitbucket-pipelines-cloud) or [Jenkins](#2b-jenkins-data-center-or-cloud) (per repository)
3. [Check the first run](#3-check-the-first-run)
4. [Merge gate](#4-optional-merge-gate) (optional)

## 0. Get the script

Import this repository into your Bitbucket (**Import repository**), or clone it and push it to your own Git server:

```bash
git clone https://github.com/ancient-cthulhu/Veracode-Bitbucket-Code-Insights.git
```

Then in the CI file (step 2) set:

- `VBI_URL`: **raw** URL of `veracode_bb_insights.py` in your copy (not the page that shows the file):
  - Bitbucket Cloud: `https://api.bitbucket.org/2.0/repositories/<workspace>/<repo>/src/main/veracode_bb_insights.py`
  - Bitbucket Data Center: `https://<server>/rest/api/latest/projects/<KEY>/repos/<repo>/raw/veracode_bb_insights.py?at=refs/heads/main`
  - GitHub: `https://raw.githubusercontent.com/<owner>/<repo>/main/veracode_bb_insights.py`
- `VBI_TOKEN` (Pipelines secured variable) or `VBI_TOKEN_CREDENTIAL` (Jenkins): only if that URL needs a token

## 1. Veracode

1. **Application profile per repository.** It must exist (the examples don't create profiles).
   - Pipelines: name it `<workspace>/<repo>` exactly as in the repository URL, or set `VERACODE_APP_NAME`.
   - Jenkins: any name; set `VERACODE_APP_NAME` (the Veracode plugin requires it).
2. **Policy** on the profile. Its rules decide what is annotated; its grace periods become the **Fix by** dates.
3. **API service account** (API user, not a person) with roles **Upload and Scan API** and **Results API**. If it's in teams, add it to every team that owns a scanned profile.
4. **HMAC credentials** (API ID + key) for it on the **API Credentials** page ([docs](https://docs.veracode.com/r/c_api_credentials3)).

> [!IMPORTANT]
> OAuth client credentials don't work: this tool and the API wrapper sign with HMAC. Credentials expire; update the CI secrets when Veracode sends the reminder.

## 2a. Bitbucket Pipelines (Cloud)

1. Copy [`examples/bitbucket-pipelines.yml`](../examples/bitbucket-pipelines.yml) to the repository root as `bitbucket-pipelines.yml` (or merge its steps into yours).
2. Adapt the **Package for Veracode** step to your language (it uses a Maven/Java 17 image), or replace it with your build writing the files to scan into `verascan/` ([packaging guide](https://docs.veracode.com/r/compilation_packaging)).
3. Default branch isn't `main`? Change `main` in the two `triggers` at the end of the file and add the repository variable `DEFAULT_BRANCH` (step 5).
4. **Repository settings > Pipelines > Settings**: enable Pipelines.
5. **Repository settings > Pipelines > Repository variables**: add `VERACODE_API_ID` and `VERACODE_API_KEY` (both **Secured**), and `VERACODE_APP_NAME` / `DEFAULT_BRANCH` if needed.
   For the scheduled sync also add `BITBUCKET_TOKEN` (**Secured**): **Repository settings > Access tokens > Create**, scope **Repositories: Read**. The sync posts on the commits that were scanned, and the Pipelines proxy may refuse commits other than the pipeline's own. Inline mode works without it.
6. Set `VBI_URL` in `bitbucket-pipelines.yml` (step 0).
7. Push to the default branch.
8. Schedule the sync on the default branch:
   - Hourly: **Pipelines > Schedules > New schedule**, pipeline **custom: veracode-sync**, **Hourly**.
   - Every 20 minutes (API only), with a token that has **Pipelines: Write**:

     ```bash
     curl -X POST -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
       https://api.bitbucket.org/2.0/repositories/<workspace>/<repo>/pipelines_config/schedules/ \
       -d '{"type": "pipeline_schedule", "enabled": true, "cron_pattern": "0 0/20 * * * ? *",
            "target": {"type": "pipeline_ref_target", "ref_type": "branch", "ref_name": "main",
                       "selector": {"type": "custom", "pattern": "veracode-sync"}}}'
     ```

   Inline mode instead: add `- step: *code-insights` after `- step: *scan`.

## 2b. Jenkins (Data Center or Cloud)

1. **Plugins:** Veracode Scan, Bitbucket Branch Source.
2. **Agents:** Linux/macOS with `git`, `curl` and Python 3.10+ with `venv`.
3. **Bitbucket token, repository read:**
   - Data Center: **Repository settings > HTTP access tokens > Create token**, **Repository read** (or a project token under **Project settings** for all repositories).
   - Cloud: **Repository settings > Security > Access tokens**, **Repositories: Read**.
4. **Manage Jenkins > Credentials:** a *Username with password* (Veracode API ID / key) and a *Secret text* (the token).
5. Copy [`examples/Jenkinsfile`](../examples/Jenkinsfile) to the repository root and set:

   | Setting | Value |
   |---|---|
   | `BITBUCKET_URL` | Data Center URL, or `''` for Cloud |
   | `defaultBranch` (top of the file), `VERACODE_APP_NAME` | Your values. The default branch gets the policy scan and runs the sync every 20 minutes |
   | `VBI_REPO` | Only when building fork PRs: `<PROJECT or workspace>/<repo>` |
   | `VBI_URL` | From step 0 |
   | `VBI_TOKEN_CREDENTIAL` | Secret text credential ID of the download token, or `''` if none |
   | `VBI_INLINE` | `'true'` to also wait and post at the end of each build; default `'false'` (sync only) |
   | `<veracode-api>`, `<bitbucket-token>` | Your credential IDs |
   | Build stage, `uploadIncludesPattern` | Your build and the files to scan |
6. **New Item > Multibranch Pipeline**, branch source **Bitbucket** (Data Center: add the server first under **Manage Jenkins > System > Bitbucket Endpoints**), with branch and pull request discovery.
7. Push the Jenkinsfile to the default branch.

> [!IMPORTANT]
> On Data Center only the token that created a report can replace it: always post with the same token.

## 3. Check the first run

1. **Default branch** (policy scan). After the scan finishes, the next sync run (or the inline step) logs:

   ```text
   policy scan: scan '1a2b3c4d...-87' is ready
   Report: FAILED - 12 finding(s) violate the Veracode policy. ...
   Posted 12 annotation(s): https://bitbucket.org/acme/payments-api/commits/1a2b3c4d...
   sandbox 'feature/x': skipped, scan '...' in progress: Scan In Process
   ```

   The link opens the commit with the **Veracode SAST (policy scan)** report.
2. **Pull request:** push a branch with a change and open a PR. Its reports show **Veracode SAST (sandbox _branch_)**, the diff shows annotations.
3. `Nothing posted: ...` or `ERROR: ...`: see [Troubleshooting](../README.md#troubleshooting).

To post one commit right away: Pipelines **Run pipeline > custom: veracode-report** on it (waits up to 60 minutes).

## 4. Optional: merge gate

A branch report is FAILED only for `NEW` violations, so the gate blocks new problems, not existing ones.

- **Data Center:** **Repository settings > Code Insights** (or **Project settings** for all repositories): report key `veracode-sast`, required status pass, no annotation requirement (that would also block on inherited findings).
- **Cloud:** needs inline mode. Add `--fail-build` to the inline report command, then require **no failed builds** in the branch's merge checks. Blocking needs Premium with **Prevent a merge with unresolved merge checks**; otherwise it only warns.

> [!NOTE]
> `--fail-build` also fails the step when the scan has no usable result (failed, timed out) and turns default-branch builds red while it has violations. To gate only PRs, use a copy of the step with the flag for `default:` branches.

## Rollout and maintenance

| Task | How |
|---|---|
| More repositories | Repeat 1.1 and step 2. One API account serves all |
| Shared secrets | Pipelines: **Workspace settings > Pipelines > Workspace variables**. Jenkins: folder credentials |
| Upgrade the script | Pull the new version into your copy, then update `VBI_URL` if it changed |
| Upgrade CLI / wrapper | Change version and checksum together (see the top of `bitbucket-pipelines.yml`) |
| Rotate credentials | New HMAC credentials, update CI secrets, revoke the old ones |
| Sandbox limit | Delete sandboxes of merged branches in Veracode |
