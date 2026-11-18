# Developer guide

Setup is in [SETUP.md](SETUP.md). Back to the [README](../README.md).

## Where to find it

- **PR diff:** an annotation on each changed line with a finding.
- **PR reports:** **Veracode SAST (sandbox _branch_)** with PASSED/FAILED and every finding, including lines you didn't change. Cloud: **Reports** in the left sidebar or the card on the right.
- **Commit page:** the same report.

It appears when the scan finishes, some minutes after the push. Each commit has its own report.

## Reading an annotation

```text
NEW | Very High | CWE-89 SQL Injection
This database query contains a SQL injection flaw... Use a parameterized prepared statement...
Function: com.acme.OrderDao.find
Fix by 2026-12-01 (policy grace period)
Mitigation proposed in Veracode, waiting for approval.
Veracode issue ID: 1234
```

| Part | Meaning |
|---|---|
| `NEW` | Your branch adds it (not in the default branch). Fix these first |
| No `NEW` | Already on the default branch |
| Fix by | Policy deadline; `overdue` after it |
| Mitigation line | Proposed (waiting for approval) or rejected |
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
