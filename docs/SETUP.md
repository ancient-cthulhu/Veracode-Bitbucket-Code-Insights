# Setup guide

From the Veracode account to the first report. Developers: [DEVELOPERS.md](DEVELOPERS.md). Back to the [README](../README.md).

1. [Veracode](#1-veracode) (once)
2. [Bitbucket Pipelines](#2a-bitbucket-pipelines-cloud) or [Jenkins](#2b-jenkins-data-center-or-cloud) (per repository)
3. [Check the first run](#3-check-the-first-run)
4. [Merge gate](#4-optional-merge-gate) (optional)

No clone needed: you copy one example file into each repository, and CI downloads a pinned, checksum-verified copy of the script. CI without GitHub access: [Host your own copy](#host-your-own-copy).

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

1. Copy [`examples/bitbucket-pipelines.yml`](../examples/bitbucket-pipelines.yml) to the repository root as `bitbucket-pipelines.yml` (or merge its three steps into yours).
2. Adapt the **Package for Veracode** step to your language (it uses a Maven/Java 17 image), or replace it with your build writing the files to scan into `verascan/` ([packaging guide](https://docs.veracode.com/r/compilation_packaging)).
3. Default branch isn't `main`? Change `main` in the three places listed at the top of the file.
4. **Repository settings > Pipelines > Settings**: enable Pipelines.
5. **Repository settings > Pipelines > Repository variables**: add `VERACODE_API_ID` and `VERACODE_API_KEY` (both **Secured**), and `VERACODE_APP_NAME` if needed. No Bitbucket token needed.
6. Push to the default branch.

## 2b. Jenkins (Data Center or Cloud)

1. **Plugins:** Veracode Scan, Bitbucket Branch Source.
2. **Agents:** Linux/macOS with `git`, `curl`, `sha256sum` and Python 3.10+ with `venv`.
3. **Bitbucket token, repository read:**
   - Data Center: **Repository settings > HTTP access tokens > Create token**, **Repository read** (or a project token under **Project settings** for all repositories).
   - Cloud: **Repository settings > Security > Access tokens**, **Repositories: Read**.
4. **Manage Jenkins > Credentials:** a *Username with password* (Veracode API ID / key) and a *Secret text* (the token).
5. Copy [`examples/Jenkinsfile`](../examples/Jenkinsfile) to the repository root and set:

   | Setting | Value |
   |---|---|
   | `BITBUCKET_URL` | Data Center URL, or `''` for Cloud |
   | `DEFAULT_BRANCH`, `VERACODE_APP_NAME` | Your values |
   | `VBI_REPO` | Only when building fork PRs: `<PROJECT or workspace>/<repo>` |
   | `<veracode-api>`, `<bitbucket-token>` | Your credential IDs |
   | Build stage, `uploadIncludesPattern` | Your build and the files to scan |

   Leave `VBI_REF` and `VBI_SHA256` as they are.
6. **New Item > Multibranch Pipeline**, branch source **Bitbucket** (Data Center: add the server first under **Manage Jenkins > System > Bitbucket Endpoints**), with branch and pull request discovery.
7. Push the Jenkinsfile to the default branch.

> [!IMPORTANT]
> On Data Center only the token that created a report can replace it: always post with the same token.

## 3. Check the first run

1. **Default branch** (policy scan). The report step log ends with:

   ```text
   Veracode: application 'acme/payments-api', policy scan
   Veracode: scan '1a2b3c4d5e6f-87' is ready
   Report: FAILED - 12 finding(s) violate the Veracode policy. ...
   Posted 12 annotation(s): https://bitbucket.org/acme/payments-api/commits/1a2b3c4d...
   ```

   The link opens the commit with the **Veracode SAST (policy scan)** report.
2. **Pull request:** push a branch with a change and open a PR. Its reports show **Veracode SAST (sandbox _branch_)**, the diff shows annotations.
3. `Nothing posted: ...` or `ERROR: ...`: see [Troubleshooting](../README.md#troubleshooting).

The report step waits up to 60 minutes (`--wait 60`). Longer scans: raise it, or post later with Pipelines **Run pipeline > custom: veracode-report** on the commit (Jenkins: rerun the build).

## 4. Optional: merge gate

A branch report is FAILED only for `NEW` violations, so the gate blocks new problems, not existing ones.

- **Data Center:** **Repository settings > Code Insights** (or **Project settings** for all repositories): report key `veracode-sast`, required status pass, no annotation requirement (that would also block on inherited findings).
- **Cloud:** add `--fail-build` to the report command, then require **no failed builds** in the branch's merge checks. Blocking needs Premium with **Prevent a merge with unresolved merge checks**; otherwise it only warns.

> [!NOTE]
> `--fail-build` also fails the step when the scan has no usable result (failed, timed out) and turns default-branch builds red while it has violations. To gate only PRs, use a copy of the step with the flag for `default:` branches.

## Rollout and maintenance

| Task | How |
|---|---|
| More repositories | Repeat 1.1 and step 2. One API account serves all |
| Shared secrets | Pipelines: **Workspace settings > Pipelines > Workspace variables**. Jenkins: folder credentials |
| Upgrade the script | Copy `VBI_REF` + `VBI_SHA256` from the release notes |
| Upgrade CLI / wrapper | Change version and checksum together (see the top of `bitbucket-pipelines.yml`) |
| Rotate credentials | New HMAC credentials, update CI secrets, revoke the old ones |
| Sandbox limit | Delete sandboxes of merged branches in Veracode |

## Host your own copy

```bash
git clone https://github.com/ancient-cthulhu/Veracode-Bitbucket-Code-Insights.git
cd Veracode-Bitbucket-Code-Insights && git checkout v1.0.0
sha256sum veracode_bb_insights.py   # must equal VBI_SHA256 (Linux/macOS checkout)
```

Publish the file internally (Artifactory, a tools repository) and change the `curl` URL in the example. Internal PyPI mirror: add `--index-url https://<mirror>/simple` to `pip install`.
