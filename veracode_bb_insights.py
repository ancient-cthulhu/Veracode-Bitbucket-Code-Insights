#!/usr/bin/env python3
"""
veracode_bb_insights.py

Posts Veracode Static Analysis findings that violate policy to Bitbucket as a
Code Insights report, with inline annotations on the scanned commit.

  Default branch  -> findings of the policy scan
  Other branches  -> findings of the sandbox named after the branch,
                     marked NEW when they are not in the policy scan

Runs as a CI step (Bitbucket Pipelines or Jenkins) after the Veracode scan.
Works with Bitbucket Cloud (default) and Bitbucket Data Center (set BITBUCKET_URL).

The scan step must name the scan version "<commit SHA>-<anything>", for example
"1a2b3c4d5e6f-87". Results are only posted when the latest scan was made from
this commit, so annotations never point at the wrong lines.

Errors: configuration and API problems exit 1 with a one-line "ERROR: ..." message.
Skip means there is nothing to post for this commit (exit 0, or 3 with --fail-build
when the scan itself has no usable results).

Requirements: Python 3.10+, pip install -r requirements.txt
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from veracode_api_signing.credentials import get_credentials
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
from veracode_api_signing.regions import get_region_for_api_credential

REPORT_KEY = "veracode-sast"
REPORTER = "Veracode"
TIMEOUT = (10, 60)          # connect, read (seconds)
RETRIES = 5
RETRY_STATUS = (429, 502, 503, 504)
POLL_SECONDS = 30
MAX_ANNOTATIONS = 1000      # Bitbucket limit per report
CLOUD_BATCH = 100           # Bitbucket Cloud limit per annotations request
MAX_TITLE = 450             # Bitbucket title / summary limit
MAX_TEXT = 2000             # Bitbucket details / message limit
PAGE_SIZE = 100
FINDINGS_PAGE_SIZE = 500    # Findings API maximum

# Scan version must start with the commit SHA (7-40 hex), then "-" or the end.
SHA_IN_VERSION = re.compile(r"^([0-9a-fA-F]{7,40})(?:-|$)")
SCAN_FAILED_WORDS = ("failed", "error", "cancel", "no modules")
# getbuildinfo.do <error> texts that only mean "no scan yet" (wording: verify)
NO_BUILD_ERROR = re.compile(r"\b(no|not find|cannot find|could not find|does not have any)\b.*\bbuilds?\b", re.I)

SEVERITY_NAMES = {5: "Very High", 4: "High", 3: "Medium", 2: "Low", 1: "Very Low", 0: "Info"}
CLOUD_SEVERITY = {5: "CRITICAL", 4: "HIGH", 3: "MEDIUM"}   # anything lower -> LOW
DC_SEVERITY = {5: "HIGH", 4: "HIGH", 3: "MEDIUM"}          # Data Center has no CRITICAL

PLATFORM_HOSTS = {
    "global": ("https://api.veracode.com", "https://analysiscenter.veracode.com"),
    "eu": ("https://api.veracode.eu", "https://analysiscenter.veracode.eu"),
    "fedramp": ("https://api.veracode.us", "https://analysiscenter.veracode.us"),
}

# CI variables, in order of precedence. Branch names are used exactly as given.
COMMIT_VARS = ("BITBUCKET_COMMIT", "GIT_COMMIT")
BRANCH_VARS = ("BITBUCKET_BRANCH", "CHANGE_BRANCH", "BRANCH_NAME")
GIT_BRANCH_PREFIXES = ("refs/remotes/origin/", "remotes/origin/", "origin/", "refs/heads/")
WALK_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "target", "build", "dist"}


class Skip(Exception):
    """Nothing to post for this commit. blocking=True means the scan has no usable
    results (failed, timed out, missing sandbox): --fail-build then exits 3."""

    def __init__(self, reason, *, blocking=False):
        super().__init__(reason)
        self.blocking = blocking


def log(msg=""):
    print(msg, flush=True)


def http_session(*, retry_post=False):
    """requests session that retries rate limits and gateway errors. POST is only
    retried when the endpoint is idempotent (Bitbucket Cloud upserts annotations)."""
    session = requests.Session()
    methods = None if retry_post else Retry.DEFAULT_ALLOWED_METHODS
    retry = Retry(total=RETRIES, backoff_factor=2, status_forcelist=RETRY_STATUS,
                  allowed_methods=methods, respect_retry_after_header=True)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers["User-Agent"] = "veracode-bitbucket-code-insights"
    return session


def check(response, what):
    """Raise a short, readable error (no headers, no secrets) for a failed call."""
    if response.status_code >= 400:
        body = " ".join((response.text or "").split())[:300]
        raise SystemExit(f"ERROR: {what} failed: HTTP {response.status_code} {body}")
    return response


def retry_after(response, default):
    value = response.headers.get("Retry-After", "")
    return min(int(value), 120) if value.isdigit() else default


# =============================================================================
# 1. CI CONTEXT: commit, branch, repository
# =============================================================================
def git(args, cwd=".", timeout=60):
    """Run git; return its output, or None when git fails or is missing."""
    try:
        out = subprocess.run(["git", "-c", "core.quotepath=off", *args], cwd=cwd, capture_output=True,
                             encoding="utf-8", errors="replace", timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def clean_branch(name):
    """Strip remote/ref prefixes from git-style names (GIT_BRANCH, git output)."""
    for prefix in GIT_BRANCH_PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def parse_repo_url(url):
    """Return (owner, slug) from a git remote URL.
    Cloud:       https://bitbucket.org/<workspace>/<repo>.git, git@bitbucket.org:<ws>/<repo>.git
    Data Center: https://host/scm/<PROJECT>/<repo>.git, ssh://git@host:7999/<project>/<repo>.git"""
    if not url:
        return None, None
    if "://" not in url and ":" in url:              # scp-like: git@host:ws/repo.git
        url = "ssh://" + url.replace(":", "/", 1)
    parts = [p for p in urlparse(url).path.split("/") if p]
    if parts and parts[-1].endswith(".git"):
        parts[-1] = parts[-1][:-4]
    if "scm" in parts:
        parts = parts[parts.index("scm") + 1:]
    if len(parts) < 2:
        return None, None
    return parts[-2], parts[-1]


def first(env, names):
    return next((env[n] for n in names if env.get(n)), "")


def jenkins_merge_parent(repo_dir):
    """Jenkins "merge with target branch" PR builds check out a merge commit that
    exists only on the agent; its first parent is the PR head. A merge commit that
    is on a remote branch (e.g. the developer merged main into the PR) is kept."""
    parents = (git(["rev-list", "--parents", "-n", "1", "HEAD"], repo_dir) or "").split()
    if len(parents) != 3:
        return ""
    on_remote = git(["branch", "-r", "--contains", "HEAD"], repo_dir)
    return parents[1] if on_remote == "" else ""


def ci_commit(args, env):
    if args.commit:
        commit = args.commit
    else:
        commit = first(env, COMMIT_VARS) or git(["rev-parse", "HEAD"], args.repo_dir) or ""
        if env.get("CHANGE_ID") and not env.get("BITBUCKET_COMMIT"):
            commit = jenkins_merge_parent(args.repo_dir) or commit
    commit = commit.lower()
    if re.fullmatch(r"[0-9a-f]{7,39}", commit):      # expand a short SHA when the checkout has it
        commit = (git(["rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}"], args.repo_dir) or commit).lower()
    return commit


def ci_branch(args, env):
    if args.branch:
        return args.branch
    return first(env, BRANCH_VARS) or clean_branch(
        env.get("GIT_BRANCH") or git(["rev-parse", "--abbrev-ref", "HEAD"], args.repo_dir) or "")


def ci_repo(args, env, server_url):
    if args.repo:
        owner, _, slug = args.repo.partition("/")
    elif env.get("BITBUCKET_WORKSPACE") and env.get("BITBUCKET_REPO_SLUG"):
        owner, slug = env["BITBUCKET_WORKSPACE"], env["BITBUCKET_REPO_SLUG"]
    else:
        owner, slug = parse_repo_url(env.get("GIT_URL") or git(["remote", "get-url", "origin"], args.repo_dir))
    if server_url and owner and not owner.startswith("~"):
        owner = owner.upper()                          # Data Center project keys are upper case
    return owner, slug


def detect_context(args, env=None):
    """Commit, branch and repository from flags, then CI variables, then git.
    Precedence: COMMIT_VARS, BRANCH_VARS (then GIT_BRANCH / git), BITBUCKET_WORKSPACE +
    BITBUCKET_REPO_SLUG (then GIT_URL / origin)."""
    env = os.environ if env is None else env
    server_url = (args.server_url or env.get("BITBUCKET_URL", "")).rstrip("/")
    commit, branch = ci_commit(args, env), ci_branch(args, env)
    if branch in ("", "HEAD") and (env.get("BITBUCKET_TAG") or env.get("TAG_NAME")):
        raise Skip("tag build, no branch to report on")
    owner, slug = ci_repo(args, env, server_url)
    fork_pr = bool(env.get("CHANGE_FORK") and env.get("CHANGE_ID") and env.get("BRANCH_NAME")) and not args.branch
    ctx = {"server_url": server_url, "commit": commit, "branch": branch, "owner": owner, "slug": slug,
           "pr_build": bool(env.get("CHANGE_ID")) and not args.branch,     # Jenkins PRs are never the policy scan
           # Fork PRs get their own sandbox (Jenkins BRANCH_NAME, e.g. PR-12): fork branch names can clash.
           "sandbox": env["BRANCH_NAME"] if fork_pr else branch}

    missing = [k for k in ("commit", "branch", "owner", "slug") if not ctx.get(k)]
    if missing:
        raise SystemExit(f"ERROR: could not detect {', '.join(missing)}. "
                         "Pass --commit, --branch and --repo <owner>/<repo>.")
    if branch == "HEAD":
        raise SystemExit("ERROR: detached HEAD, pass --branch <branch name>.")
    if not re.fullmatch(r"[0-9a-f]{7,40}", commit):
        raise SystemExit(f"ERROR: '{commit}' is not a commit SHA.")
    if server_url and len(commit) != 40:
        raise SystemExit("ERROR: Bitbucket Data Center needs the full 40-character commit SHA.")
    return ctx


# =============================================================================
# 2. VERACODE
# =============================================================================
def veracode_credentials():
    """VERACODE_API_ID / VERACODE_API_KEY, else the signing library's sources
    (VERACODE_API_KEY_ID / VERACODE_API_KEY_SECRET, ~/.veracode/credentials)."""
    api_id, secret = os.getenv("VERACODE_API_ID", ""), os.getenv("VERACODE_API_KEY", "")
    if not (api_id and secret):
        try:
            api_id, secret = get_credentials()
        except Exception:  # noqa: BLE001 - the library raises several types
            raise SystemExit("ERROR: Veracode credentials not found. Set VERACODE_API_ID and VERACODE_API_KEY.") from None
    try:
        region = get_region_for_api_credential(api_id)
    except Exception:  # noqa: BLE001
        raise SystemExit("ERROR: the Veracode API ID has an unknown region prefix.") from None
    return api_id, secret, region


class Veracode:
    def __init__(self):
        api_id, secret, region = veracode_credentials()
        self.rest, self.platform = PLATFORM_HOSTS[region]
        if os.getenv("VERACODE_API_BASE"):
            self.rest = os.environ["VERACODE_API_BASE"].rstrip("/")
            self.platform = self.rest.replace("://api.", "://analysiscenter.")
        self.auth = RequestsAuthPluginVeracodeHMAC(api_id, secret)
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "veracode-bitbucket-code-insights"

    def _get(self, url, params, what):
        """GET with retries. Every attempt is signed again (fresh HMAC nonce and timestamp)."""
        for attempt in range(RETRIES + 1):
            delay = min(2 ** (attempt + 1), 30)
            try:
                r = self.session.get(url, params=params, auth=self.auth, timeout=TIMEOUT)
            except (requests.ConnectionError, requests.Timeout):
                if attempt == RETRIES:
                    raise
            else:
                if r.status_code not in RETRY_STATUS or attempt == RETRIES:
                    return check(r, what)
                delay = retry_after(r, delay)
            time.sleep(delay)
        raise AssertionError("unreachable")

    def _pages(self, path, params, key, what):
        page = 0
        while True:
            data = self._get(f"{self.rest}{path}", {**params, "page": page}, what).json()
            yield from data.get("_embedded", {}).get(key, [])
            page += 1
            if page >= data.get("page", {}).get("total_pages", 1):
                return

    def find_application(self, candidates, search):
        """First candidate name that exactly matches a profile (case-insensitive)."""
        apps = list(self._pages("/appsec/v1/applications", {"name": search, "size": PAGE_SIZE},
                                "applications", "Applications API"))
        for name in candidates:
            hits = [a for a in apps if a.get("profile", {}).get("name", "").lower() == name.lower()]
            if len(hits) == 1:
                return hits[0]
            if len(hits) > 1:
                raise SystemExit(f"ERROR: more than one application profile is named '{name}'. "
                                 "Set VERACODE_APP_NAME to the exact name.")
        raise SystemExit(f"ERROR: no application profile named {' or '.join(repr(c) for c in candidates)}, "
                         "or the API account cannot see it. Set VERACODE_APP_NAME.")

    def find_sandbox(self, app_guid, name):
        sandboxes = list(self._pages(f"/appsec/v1/applications/{app_guid}/sandboxes", {"size": PAGE_SIZE},
                                     "sandboxes", "Sandbox API"))
        exact = [s for s in sandboxes if s.get("name") == name]
        loose = [s for s in sandboxes if s.get("name", "").lower() == name.lower()]
        if exact or len(loose) == 1:
            return (exact or loose)[0]
        if loose:
            raise Skip(f"Several sandboxes match '{name}' when case is ignored; rename them or pass --sandbox-name.",
                       blocking=True)
        raise Skip(f"No sandbox named '{name}'. The scan step must use the branch name as the sandbox name.",
                   blocking=True)

    def latest_build(self, app_id, sandbox_id=None):
        """getbuildinfo.do (XML API): most recent static scan, or None when there is none yet."""
        params = {"app_id": app_id}
        if sandbox_id is not None:
            params["sandbox_id"] = sandbox_id
        r = self._get(f"{self.platform}/api/5.0/getbuildinfo.do", params, "getbuildinfo.do")
        try:
            # Authenticated Veracode response over TLS; expat does not resolve external entities.
            root = ET.fromstring(r.content)  # noqa: S314
        except ET.ParseError:
            raise SystemExit(f"ERROR: getbuildinfo.do did not return XML: {' '.join(r.text.split())[:200]}") from None
        if root.tag.endswith("error"):
            text = " ".join((root.text or "").split())
            if NO_BUILD_ERROR.search(text):
                return None
            raise SystemExit(f"ERROR: getbuildinfo.do: {text}")
        build = next((e for e in root.iter() if e.tag.endswith("build")), None)
        if build is None:
            return None
        unit = next((e for e in build.iter() if e.tag.endswith("analysis_unit")), None)
        return {
            "build_id": build.get("build_id", ""),
            "version": build.get("version", ""),
            "status": unit.get("status", "") if unit is not None else "",
            "results_ready": build.get("results_ready", "").lower() == "true",
            "rules_status": build.get("rules_status", ""),
        }

    def static_findings(self, app_guid, sandbox_guid=None):
        """Open static findings that violate policy, without approved mitigations."""
        params = {"scan_type": "STATIC", "violates_policy": "TRUE", "size": FINDINGS_PAGE_SIZE}
        if sandbox_guid:
            params["context"] = sandbox_guid
        out = []
        for f in self._pages(f"/appsec/v2/applications/{app_guid}/findings", params, "findings", "Findings API"):
            status = f.get("finding_status", {})
            if status.get("status", "").upper() == "CLOSED":
                continue
            if status.get("resolution_status", "").upper() == "APPROVED":
                continue
            out.append(f)
        return out

    def policy_issue_ids(self, app_guid):
        """Issue IDs of every static finding in the policy scan, any status. A sandbox
        finding is NEW only when the policy scan never had it (fixed or mitigated
        findings on the default branch are not new to the branch)."""
        params = {"scan_type": "STATIC", "size": FINDINGS_PAGE_SIZE}
        return {f.get("issue_id") for f in
                self._pages(f"/appsec/v2/applications/{app_guid}/findings", params, "findings", "Findings API")}


def build_state(build, commit):
    """('ready' | 'wait' | 'skip' | 'fail', reason) for the latest scan.
    skip = superseded by another commit; fail = this commit's scan has no usable results."""
    if build is None:
        return "wait", "no scan found yet"
    match = SHA_IN_VERSION.match(build["version"])
    if not match:
        return "fail", (f"latest scan '{build['version']}' is not named after a commit. "
                        "Name the scan version '<commit SHA>-<build number>'.")
    if not commit.startswith(match.group(1).lower()):
        return "skip", (f"latest scan '{build['version']}' is for another commit "
                        "(or is not named '<commit SHA>-<build number>')")
    if not build["results_ready"]:
        if any(w in build["status"].lower() for w in SCAN_FAILED_WORDS):
            return "fail", f"scan '{build['version']}' did not complete: {build['status']}"
        return "wait", f"scan '{build['version']}' in progress: {build['status'] or 'queued'}"
    rules = build["rules_status"].lower()
    if rules in ("", "not assessed") or rules.startswith("calculating"):
        return "wait", "results ready, waiting for the policy evaluation"
    return "ready", f"scan '{build['version']}' is ready"


def wait_for_build(vc, app_id, sandbox_id, commit, wait_minutes):
    deadline = time.monotonic() + wait_minutes * 60
    while True:
        build = vc.latest_build(app_id, sandbox_id)
        state, why = build_state(build, commit)
        if state == "ready":
            log(f"Veracode: {why}")
            return build
        if state in ("skip", "fail"):
            raise Skip(why, blocking=state == "fail")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Skip(f"{why} (stopped waiting after {wait_minutes} min)", blocking=True)
        log(f"Veracode: {why}; checking again in {POLL_SECONDS}s")
        time.sleep(min(POLL_SECONDS, remaining))


# =============================================================================
# 3. FINDINGS -> ANNOTATIONS
# =============================================================================
class RepoFiles:
    """Maps a Veracode file path to a path in the repository by matching the
    longest common ending, e.g. com/acme/Dao.java -> src/main/java/com/acme/Dao.java."""

    def __init__(self, repo_dir):
        listing = git(["ls-files", "-z"], repo_dir, timeout=300)
        if listing is None:
            log("git ls-files failed; matching file paths by walking the folder")
            files = self._walk(repo_dir)
        else:
            files = [f for f in listing.split("\0") if f]
        self.by_name = {}
        for path in files:
            self.by_name.setdefault(path.rsplit("/", 1)[-1].lower(), []).append(path)

    @staticmethod
    def _walk(repo_dir):
        out = []
        for root, dirs, names in os.walk(repo_dir):
            dirs[:] = [d for d in dirs if d not in WALK_SKIP_DIRS]
            rel = os.path.relpath(root, repo_dir).replace(os.sep, "/")
            out += [n if rel == "." else f"{rel}/{n}" for n in names]
        return out

    def resolve(self, vc_path):
        """Best repository path for a Veracode path, or None when there is no match,
        the match is ambiguous, or only the file name matches a deeper Veracode path."""
        parts = [p for p in (vc_path or "").replace("\\", "/").lower().split("/") if p]
        if not parts:
            return None
        best, best_score, tie = None, 0, False
        for candidate in self.by_name.get(parts[-1], []):
            cparts = candidate.lower().split("/")
            score = 0
            while score < min(len(parts), len(cparts)) and parts[-1 - score] == cparts[-1 - score]:
                score += 1
            if len(parts) > 1 and score < 2 and score < len(cparts):
                continue                                   # file name only: probably another module
            if score > best_score:
                best, best_score, tie = candidate, score, False
            elif score == best_score:
                tie = True
        return None if tie else best


class _TextOnly(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)

    def handle_starttag(self, _tag, _attrs):
        self.parts.append(" ")

    def handle_endtag(self, _tag):
        self.parts.append(" ")


def plain_text(description, limit=1200):
    """Veracode descriptions are HTML: what is wrong, how to fix it, references."""
    parser = _TextOnly()
    parser.feed(description or "")
    text = " ".join("".join(parser.parts).split())
    text = text.split("References:")[0].strip()
    return text if len(text) <= limit else text[:limit - 3].rstrip() + "..."


def to_annotation(finding, files, is_new, link):
    """Platform-neutral annotation: external_id, severity (0-5), new, path, line,
    summary, details, link."""
    d = finding.get("finding_details") or {}
    severity = int(d.get("severity", 0) or 0)
    cwe = d.get("cwe") or {}
    category = (d.get("finding_category") or {}).get("name") or cwe.get("name") or "Finding"
    vc_path = d.get("file_path") or d.get("file_name") or ""
    path = files.resolve(vc_path)
    line = d.get("file_line_number") or None

    summary = f"{SEVERITY_NAMES.get(severity, severity)} | CWE-{cwe.get('id', '?')} {category}"
    if is_new:
        summary = "NEW | " + summary
    details = [plain_text(finding.get("description", ""))]
    if d.get("procedure"):
        details.append(f"Function: {d['procedure']}")
    if path is None:
        where = "/".join(x for x in (d.get("module"), vc_path) if x)
        details.append(f"Veracode location: {where}{f':{line}' if line else ''}")
    details.append(f"Veracode issue ID: {finding.get('issue_id')}")
    return {
        "external_id": f"veracode-{finding.get('issue_id')}",
        "severity": severity,
        "new": is_new,
        "path": path,
        "line": line if path else None,
        "summary": summary[:MAX_TITLE],
        "details": "\n".join(x for x in details if x),
        "link": link,
    }


def build_results(findings, policy_ids, files, link):
    """policy_ids is None on the default branch, else the issue IDs in the policy scan."""
    annotations = [to_annotation(f, files, policy_ids is not None and f.get("issue_id") not in policy_ids, link)
                   for f in findings]
    annotations.sort(key=lambda a: (not a["new"], -a["severity"], a["path"] is None, a["path"] or "", a["line"] or 0))
    return annotations


def build_report(ctx, build, annotations, is_branch, link):
    """Platform-neutral report; data is a list of (title, TYPE, value), at most 6 items."""
    total = len(annotations)
    new = sum(a["new"] for a in annotations)
    unmapped = sum(a["path"] is None for a in annotations)
    omitted = max(0, total - MAX_ANNOTATIONS)

    if is_branch:
        failed = new > 0
        lines = [f"{new} finding(s) new in this branch violate the Veracode policy "
                 f"({total} in total, {total - new} already in the policy scan)."]
        title = f"Veracode SAST (sandbox {ctx.get('sandbox', ctx['branch'])})"
    else:
        failed = total > 0
        lines = [f"{total} finding(s) violate the Veracode policy."]
        title = "Veracode SAST (policy scan)"
    if total:
        lines.append("Pull requests show annotations only on changed lines; this report lists them all.")
    if unmapped:
        lines.append(f"{unmapped} finding(s) could not be matched to a file in the repository.")
    if omitted:
        lines.append(f"{omitted} finding(s) not shown: Bitbucket allows {MAX_ANNOTATIONS} per report.")

    data = [("Policy violations", "NUMBER", total)]
    if is_branch:
        data.append(("New in this branch", "NUMBER", new))
    data += [("Scan", "TEXT", build["version"]), ("Veracode results", "LINK", link)]
    if unmapped:
        data.append(("Not matched to a file", "NUMBER", unmapped))
    if omitted:
        data.append(("Not shown (limit)", "NUMBER", omitted))
    return {"title": title[:MAX_TITLE], "details": " ".join(lines)[:MAX_TEXT], "failed": failed,
            "data": data, "link": link}


# =============================================================================
# 4. BITBUCKET (Cloud and Data Center)
# =============================================================================
class Bitbucket:
    """Shared Code Insights client; subclasses define URLs and payload shapes."""
    LINK_TEXT_KEY = "text"
    RESULT = ("PASSED", "FAILED")

    def __init__(self, api, owner, slug, proxies=None, *, retry_post=False):
        self.api, self.owner, self.slug, self.proxies = api, owner, slug, proxies
        self.session = http_session(retry_post=retry_post)

    def _call(self, method, url, what, *, ok404=False, **kwargs):
        r = self.session.request(method, url, proxies=self.proxies, timeout=TIMEOUT, **kwargs)
        if ok404 and r.status_code == 404:
            return r
        return check(r, f"Bitbucket {what}")

    def publish(self, commit, report, annotations):
        """Replace the report on the commit and add its annotations. Returns the commit URL.
        If annotations fail, the report says so before the error is raised."""
        url = self.report_url(commit)
        self._call("DELETE", url, "delete report", ok404=True)
        self._call("PUT", url, "create report", json=self.report_body(report))
        body = [self.annotation_body(a) for a in annotations[:MAX_ANNOTATIONS]]
        try:
            for batch in self.batches(body):
                self._call("POST", f"{url}/annotations", "add annotations", json=batch)
        except (SystemExit, requests.RequestException):
            note = "Annotations could not be uploaded; open the Veracode results for the full list. "
            try:
                self._call("PUT", url, "update report", json=self.report_body(
                    {**report, "details": (note + report["details"])[:MAX_TEXT]}))
            except (SystemExit, requests.RequestException):
                pass
            raise
        return self.commit_url(commit)

    @classmethod
    def report_body(cls, report):
        data = [{"title": title, "type": kind,
                 "value": {cls.LINK_TEXT_KEY: "Open in Veracode", "href": value} if kind == "LINK" else value}
                for title, kind, value in report["data"]]
        return {"title": report["title"], "details": report["details"], "reporter": REPORTER,
                "link": report["link"], "result": cls.RESULT[report["failed"]], "data": data}


class BitbucketCloud(Bitbucket):
    API = "https://api.bitbucket.org/2.0"

    def __init__(self, owner, slug, env=None):
        env = os.environ if env is None else env
        token, user = env.get("BITBUCKET_TOKEN", ""), env.get("BITBUCKET_USER", "")
        if token:
            super().__init__(self.API, owner, slug, retry_post=True)   # Cloud upserts by external_id
            if user:      # Atlassian API token: Basic auth with the account email
                self.session.auth = (user, token)
            else:         # repository / workspace access token
                self.session.headers["Authorization"] = f"Bearer {token}"
        elif env.get("BITBUCKET_BUILD_NUMBER"):
            # Inside Bitbucket Pipelines: the local proxy adds authentication.
            proxy = env.get("BITBUCKET_PROXY", "http://localhost:29418")
            super().__init__("http://api.bitbucket.org/2.0", owner, slug,
                             proxies={"http": proxy, "https": proxy}, retry_post=True)
        else:
            raise SystemExit("ERROR: set BITBUCKET_TOKEN (needed outside Bitbucket Pipelines).")

    def default_branch(self):
        r = self._call("GET", f"{self.api}/repositories/{self.owner}/{self.slug}", "repository")
        return (r.json().get("mainbranch") or {}).get("name", "")

    def report_url(self, commit):
        return f"{self.api}/repositories/{self.owner}/{self.slug}/commit/{commit}/reports/{REPORT_KEY}"

    def commit_url(self, commit):
        return f"https://bitbucket.org/{self.owner}/{self.slug}/commits/{commit}"

    @staticmethod
    def batches(body):
        return [body[i:i + CLOUD_BATCH] for i in range(0, len(body), CLOUD_BATCH)]

    @classmethod
    def report_body(cls, report):
        return {**super().report_body(report), "report_type": "SECURITY"}

    @staticmethod
    def annotation_body(a):
        body = {"external_id": a["external_id"], "annotation_type": "VULNERABILITY",
                "summary": a["summary"], "details": a["details"][:MAX_TEXT],
                "severity": CLOUD_SEVERITY.get(a["severity"], "LOW"), "link": a["link"]}
        if a["path"]:
            body["path"] = a["path"]
            if a["line"]:
                body["line"] = a["line"]
        return body


class BitbucketDataCenter(Bitbucket):
    LINK_TEXT_KEY = "linktext"
    RESULT = ("PASS", "FAIL")

    def __init__(self, server_url, owner, slug, env=None):
        env = os.environ if env is None else env
        token = env.get("BITBUCKET_TOKEN", "")
        if not token:
            raise SystemExit("ERROR: set BITBUCKET_TOKEN (HTTP access token with repository read).")
        super().__init__(f"{server_url}/rest", owner, slug)   # POST is not idempotent on Data Center
        self.server = server_url
        self.session.headers["Authorization"] = f"Bearer {token}"

    def _repo(self):
        return f"projects/{self.owner}/repos/{self.slug}"

    def default_branch(self):
        for path in ("default-branch", "branches/default"):     # newer / older servers
            r = self._call("GET", f"{self.api}/api/latest/{self._repo()}/{path}", "default branch", ok404=True)
            if r.status_code == 404:
                continue
            return r.json().get("displayId", "") if r.content else ""   # 204: empty repository
        raise SystemExit(f"ERROR: repository {self.owner}/{self.slug} not found on {self.server}, "
                         "or the token cannot read it.")

    def report_url(self, commit):
        return f"{self.api}/insights/latest/{self._repo()}/commits/{commit}/reports/{REPORT_KEY}"

    def commit_url(self, commit):
        return f"{self.server}/{self._repo()}/commits/{commit}"

    @staticmethod
    def batches(body):
        return [{"annotations": body}] if body else []      # one request: all or nothing

    @staticmethod
    def annotation_body(a):
        body = {"externalId": a["external_id"], "type": "VULNERABILITY",
                "message": f"{a['summary']}\n{a['details']}"[:MAX_TEXT],
                "severity": DC_SEVERITY.get(a["severity"], "LOW"), "link": a["link"]}
        if a["path"]:
            body["path"] = a["path"]
            if a["line"]:
                body["line"] = a["line"]
        return body


# =============================================================================
# 5. MAIN
# =============================================================================
class _Parser(argparse.ArgumentParser):
    def error(self, message):            # exit 1, not 2 (2 means "report FAILED")
        self.print_usage(sys.stderr)
        raise SystemExit(f"{self.prog}: error: {message}")


def parse_args(argv):
    p = _Parser(description="Post Veracode SAST policy findings to Bitbucket Code Insights.",
                epilog="Exit codes: 0 posted or nothing to post, 1 error, 2 report FAILED (--fail-build), "
                       "3 scan has no usable results (--fail-build).")
    p.add_argument("--commit", help="commit SHA (default: from CI variables)")
    p.add_argument("--branch", help="branch name (default: from CI variables)")
    p.add_argument("--repo", help="<workspace or PROJECT>/<repo slug> (default: from CI variables)")
    p.add_argument("--server-url", help="Bitbucket Data Center URL (or BITBUCKET_URL). Omit for Cloud.")
    p.add_argument("--default-branch", help="default branch (default: asked from Bitbucket)")
    p.add_argument("--app-name", default=os.getenv("VERACODE_APP_NAME", ""),
                   help="Veracode application profile (default: <owner>/<repo>, then <repo>)")
    p.add_argument("--sandbox-name", help="sandbox name (default: the branch name)")
    p.add_argument("--repo-dir", default=".", help="repository checkout used to match file paths")
    p.add_argument("--wait", type=int, default=20, help="minutes to wait for scan results, approximate (default 20)")
    p.add_argument("--fail-build", action="store_true",
                   help="exit 2 when the report is FAILED, 3 when the scan has no usable results")
    p.add_argument("--dry-run", action="store_true", help="print the request bodies instead of posting them")
    return p.parse_args(argv)


def make_bitbucket(ctx, env):
    if ctx["server_url"]:
        return BitbucketDataCenter(ctx["server_url"], ctx["owner"], ctx["slug"], env)
    return BitbucketCloud(ctx["owner"], ctx["slug"], env)


def bitbucket_target(args, ctx, env):
    """(client or None, default branch). A dry run with --default-branch needs no Bitbucket access."""
    default_branch = args.default_branch or env.get("BITBUCKET_DEFAULT_BRANCH", "")
    bb = None
    if not args.dry_run or not default_branch:
        bb = make_bitbucket(ctx, env)
        default_branch = default_branch or bb.default_branch()
    if not default_branch:
        raise SystemExit("ERROR: could not read the default branch. Pass --default-branch.")
    return bb, default_branch


def find_scan(vc, args, ctx, is_branch):
    """(application, sandbox or None, build) for this commit; raises Skip."""
    candidates = [args.app_name] if args.app_name else [f"{ctx['owner']}/{ctx['slug']}", ctx["slug"]]
    app = vc.find_application(candidates, args.app_name or ctx["slug"])
    sandbox = vc.find_sandbox(app["guid"], args.sandbox_name or ctx["sandbox"]) if is_branch else None
    log(f"Veracode: application '{app['profile']['name']}', "
        f"{'sandbox ' + repr(sandbox['name']) if sandbox else 'policy scan'}")
    build = wait_for_build(vc, app["id"], sandbox["id"] if sandbox else None, ctx["commit"], args.wait)
    return app, sandbox, build


def results_link(platform, app, build):
    oid = app.get("oid") or app.get("alt_org_id")
    if oid:
        return f"{platform}/auth/index.jsp#ReviewResultsAllFlaws:{oid}:{app['id']}:{build['build_id']}"
    fragment = app.get("results_url") or ""
    if fragment.startswith("http"):
        return fragment
    return f"{platform}/auth/index.jsp#{fragment}" if fragment else platform


def run(args, env=None):
    env = os.environ if env is None else env
    try:
        ctx = detect_context(args, env)
        log(f"Bitbucket: {ctx['owner']}/{ctx['slug']} branch '{ctx['branch']}' commit {ctx['commit'][:12]}"
            f" ({'Data Center ' + ctx['server_url'] if ctx['server_url'] else 'Cloud'})")
        bb, default_branch = bitbucket_target(args, ctx, env)
        is_branch = ctx["pr_build"] or ctx["branch"] != default_branch
        vc = Veracode()
        app, sandbox, build = find_scan(vc, args, ctx, is_branch)
    except Skip as why:
        log(f"Nothing posted: {why}")
        if why.blocking and args.fail_build:
            log("--fail-build: failing because this commit's scan has no usable results.")
            return 3
        return 0

    findings = vc.static_findings(app["guid"], sandbox["guid"] if sandbox else None)
    policy_ids = (vc.policy_issue_ids(app["guid"]) if findings else set()) if sandbox else None
    link = results_link(vc.platform, app, build)
    annotations = build_results(findings, policy_ids, RepoFiles(args.repo_dir), link)
    report = build_report(ctx, build, annotations, is_branch, link)
    log(f"Report: {'FAILED' if report['failed'] else 'PASSED'} - {report['details']}")

    if args.dry_run:
        cls = BitbucketDataCenter if ctx["server_url"] else BitbucketCloud
        log(json.dumps({"report": cls.report_body(report),
                        "annotations": [cls.annotation_body(a) for a in annotations[:MAX_ANNOTATIONS]]}, indent=2))
    else:
        where = bb.publish(ctx["commit"], report, annotations)
        log(f"Posted {min(len(annotations), MAX_ANNOTATIONS)} annotation(s): {where}")
    return 2 if args.fail_build and report["failed"] else 0


def main(argv=None):
    """Exit codes: 0 posted or nothing to post, 1 error, 2 report FAILED, 3 no usable scan (with --fail-build)."""
    args = parse_args(argv)
    try:
        return run(args)
    except requests.RequestException as exc:
        raise SystemExit(f"ERROR: network call failed: {type(exc).__name__}: {str(exc)[:300]}") from None


if __name__ == "__main__":
    sys.exit(main())
