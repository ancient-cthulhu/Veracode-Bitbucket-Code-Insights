# Developer guide

Setup is in [SETUP.md](SETUP.md). Back to the [README](../README.md).

## Where to find it

- **Pull request:** the **Reports** card on the right (or **Reports** in the left sidebar) opens **Veracode SAST + SCA (sandbox _branch_)** with every finding; the diff shows an annotation on each changed line with a finding.
- **Commit page** (**Commits** > the commit): the same report in the right sidebar. On the default branch this is where the policy scan results are.
- **Pipeline run** (Pipelines example): the **reports** link at the bottom of the run.

It appears after the scan finishes (scheduled setups: at the next sync, every 20-60 minutes). Each commit has its own report.

## Reading an annotation

```text
NEW: SQL Injection (CWE-89) in OrderDao.find
Very High severity · exploit likely · fix by 2026-12-01 ▸ Problem: This database query contains a SQL injection
flaw. The first argument to executeQuery() contains tainted data from the variable sql... ▸ Fix: Use parameterized
prepared statements... ▸ Where: OrderDao.find calls java.sql.Statement.executeQuery ▸ Mitigation proposed in
Veracode, waiting for approval. ▸ Veracode issue 1234 · first found 2026-09-02 · CWE-89: https://cwe.mitre.org/...
```

| Part | Meaning |
|---|---|
| `NEW` | Your branch adds it (not in the default branch). Fix these first |
| No `NEW` | Already on the default branch |
| Exploit | Veracode's estimate of how likely an attacker can use it |
| Where | The function, and the call that receives the unsafe data |
| fix by | Policy deadline; `OVERDUE` after it |
| Veracode issue ID | Search it in Veracode **Triage Flaws** (the link opens the scan's results) |
| Mitigation line | Proposed (waiting for approval) or rejected |
| Library (SCA) | A vulnerable third-party library. On the line that declares it; if another dependency brings it in, on the manifest with the command that shows which |
| Veracode location | Shown instead of a line when the file isn't in this repository as-is |
| Issue ID + link | Find the finding in Veracode |

Only policy-violating findings are listed; approved mitigations are left out.

## PASSED or FAILED

| Report | Means |
|---|---|
| Branch PASSED | No `NEW` policy violations (inherited ones may be listed) |
| Branch FAILED | At least one `NEW` policy violation. Blocks the merge if your team set a merge gate |
| Default branch FAILED | The application has open policy violations |

## Fix it

Fix the code and push. The new commit gets a new report without the finding.

**False positive or safe by design?** Open the link, find the issue ID, and propose a mitigation with the reason. The next report says it's waiting for approval; once approved it's gone.

## FAQ

| Question | Answer |
|---|---|
| No annotation on my line | Bitbucket annotates changed lines only. Open the report for all findings |
| No report | Scan still running, or the build log says why (`Nothing posted: ...`). See [Troubleshooting](../README.md#troubleshooting) |
| Fixed, but the default branch still lists it | It updates after the merge is scanned |
