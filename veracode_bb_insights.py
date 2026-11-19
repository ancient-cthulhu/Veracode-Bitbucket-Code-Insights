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

Posts the latest scan of the branch (the sandbox named after it, or the policy scan on
the default branch) on the commit being built. If that scan was made from another commit
(the scan version starts with the commit SHA, e.g. "<full SHA>-87"), the report says so.
--sync posts each scan on the commit it was made from.

Errors: configuration and API problems exit 1 with a one-line "ERROR: ..." message.
Skip means there is nothing to post for this commit (exit 0, or 3 with --fail-build
when the scan itself has no usable results).

Requirements: Python 3.10+, pip install --no-deps -r requirements.txt
"""

import argparse
import functools
import json
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import quote, urlparse

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
MITIGATION_NOTES = {"PROPOSED": "Mitigation proposed in Veracode, waiting for approval.",
                    "REJECTED": "Mitigation rejected in Veracode: fix the code or propose a new mitigation."}

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
    """Raise a short, readable error (no request headers, no secrets) for a failed call.
    HTML error pages come from a proxy or gateway, not the API: say so, keep their text."""
    if response.status_code >= 400:
        text = response.text or ""
        if "html" in response.headers.get("Content-Type", "").lower():
            text = "HTML page from a proxy or gateway, not the API: " + plain_text(text, 200)
        body = " ".join(text.split())[:300]
        trace = response.headers.get("Atl-Traceid") or response.headers.get("X-Request-Id") or ""
        raise SystemExit(f"ERROR: {what} failed: HTTP {response.status_code} {body}"
                         + (f" (trace ID {trace})" if trace else ""))
    return response


def network_reason(exc):
    """Short reason for a failed request, e.g. 'HTTP 502 on every attempt (6 tries)'."""
    match = re.search(r"too many (\d{3}) error responses", str(exc))
    if match:
        return f"HTTP {match.group(1)} on every attempt ({RETRIES + 1} tries)"
    return f"{type(exc).__name__}: {str(exc)[:300]}"


def retry_after(response, default):
    value = response.headers.get("Retry-After", "")
    return min(int(value), 120) if value.isascii() and value.isdigit() and len(value) <= 6 else default


def require_https(url, name, *, strict=True):
    """Credentials should only travel over https. Plain http is accepted for this machine
    (tests) and, with a warning, for internal Bitbucket Data Center servers (strict=False)."""
    parsed = urlparse(url)
    local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme == "https" or (parsed.scheme == "http" and local):
        return url.rstrip("/")
    if parsed.scheme == "http" and not strict:
        log(f"WARNING: {name} uses http://; the token is sent unencrypted. Use https:// if the server supports it.")
        return url.rstrip("/")
    raise SystemExit(f"ERROR: {name} must be an https:// URL.")


# =============================================================================
# 1. CI CONTEXT: commit, branch, repository
# =============================================================================
# Repository config is untrusted (earlier build steps can edit .git/config): never let it
# run a program (fsmonitor hook, lazy fetch of a partial clone through a configured
# transport) or prompt, don't take locks, and never give git the secrets.
GIT_SAFE_CONFIG = ("-c", "core.quotepath=off", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
                   "-c", "protocol.allow=never")
GIT_ENV = {"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1",
           "GIT_NO_REPLACE_OBJECTS": "1"}
SECRET_ENV = ("VERACODE_API_ID", "VERACODE_API_KEY", "VERACODE_API_KEY_ID", "VERACODE_API_KEY_SECRET",
              "BITBUCKET_TOKEN", "BITBUCKET_USER")


@functools.cache
def git_executable():
    """Absolute path of git from PATH, never from the current folder (on Windows a bare
    "git" would also run a git.exe placed in the checkout)."""
    names = ("git.exe",) if os.name == "nt" else ("git",)
    here = os.path.normcase(os.path.abspath(os.getcwd()))
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        folder = folder.strip('"')
        if not folder or not os.path.isabs(folder) or os.path.normcase(os.path.abspath(folder)) == here:
            continue
        for name in names:
            path = os.path.join(folder, name)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
    return None


def git(args, cwd=".", timeout=60):
    """Run git; return its output, or None when git fails or is missing."""
    exe = git_executable()
    if exe is None:
        return None
    env = {k: v for k, v in os.environ.items() if k not in SECRET_ENV}
    try:
        out = subprocess.run([exe, *GIT_SAFE_CONFIG, *args], cwd=cwd, capture_output=True,
                             encoding="utf-8", errors="replace", timeout=timeout, check=False,
                             env={**env, **GIT_ENV})
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
    return expand_sha(commit, args.repo_dir)


def expand_sha(commit, repo_dir):
    """Full SHA for a short one when it names exactly one commit in the checkout."""
    commit = commit.lower()
    if re.fullmatch(r"[0-9a-f]{7,39}", commit):
        matches = (git(["rev-parse", f"--disambiguate={commit}"], repo_dir) or "").split()
        commits = [m for m in matches if git(["cat-file", "-t", m], repo_dir) == "commit"]
        if len(commits) == 1:
            commit = commits[0].lower()
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
    server_url = args.server_url or env.get("BITBUCKET_URL", "")
    server_url = require_https(server_url, "BITBUCKET_URL", strict=False) if server_url else ""
    commit, branch = ci_commit(args, env), ci_branch(args, env)
    if branch in ("", "HEAD") and (env.get("BITBUCKET_TAG") or env.get("TAG_NAME")):
        raise Skip("tag build, no branch to report on")
    if env.get("TAG_NAME") and branch == env["TAG_NAME"] and not args.branch:
        raise Skip("tag build, no branch to report on")      # Jenkins tag jobs set BRANCH_NAME to the tag
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
            self.rest = require_https(os.environ["VERACODE_API_BASE"], "VERACODE_API_BASE")
            self.platform = self.rest.replace("://api.", "://analysiscenter.")
        self.auth = RequestsAuthPluginVeracodeHMAC(api_id, secret)
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "veracode-bitbucket-code-insights"

    def _get(self, url, params, what):
        """GET with retries (also on 500: every call is a read). Every attempt is signed
        again (fresh HMAC nonce and timestamp)."""
        for attempt in range(RETRIES + 1):
            delay = min(2 ** (attempt + 1), 30)
            try:
                r = self.session.get(url, params=params, auth=self.auth, timeout=TIMEOUT)
            except (requests.ConnectionError, requests.Timeout):
                if attempt == RETRIES:
                    raise
            else:
                if r.status_code not in (*RETRY_STATUS, 500) or attempt == RETRIES:
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
        sandboxes = self.sandboxes(app_guid)
        exact = [s for s in sandboxes if s.get("name") == name]
        loose = [s for s in sandboxes if s.get("name", "").lower() == name.lower()]
        if exact or len(loose) == 1:
            return (exact or loose)[0]
        if loose:
            raise Skip(f"Several sandboxes match '{name}' when case is ignored; rename them or pass --sandbox-name.",
                       blocking=True)
        raise Skip(f"No sandbox named '{name}'. The scan step must use the branch name as the sandbox name.",
                   blocking=True)

    def sandboxes(self, app_guid):
        return list(self._pages(f"/appsec/v1/applications/{app_guid}/sandboxes", {"size": PAGE_SIZE},
                                "sandboxes", "Sandbox API"))

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
            "published": int(unit.get("published_date_sec", 0) or 0) if unit is not None else 0,
            "results_ready": build.get("results_ready", "").lower() == "true",
            "rules_status": build.get("rules_status", ""),
        }

    def static_findings(self, app_guid, sandbox_guid=None):
        """Open static findings that violate policy, without approved mitigations,
        with the policy grace period (fix-by date)."""
        params = {"scan_type": "STATIC", "violates_policy": "TRUE", "include_exp_date": "TRUE",
                  "size": FINDINGS_PAGE_SIZE}
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

    def policy_issue_ids(self, app_guid, min_severity=0):
        """Issue IDs of every static finding in the policy scan, any status. A sandbox
        finding is NEW only when the policy scan never had it (fixed or mitigated
        findings on the default branch are not new to the branch). An issue keeps its
        severity, so only severities the sandbox findings have are fetched."""
        params = {"scan_type": "STATIC", "size": FINDINGS_PAGE_SIZE}
        if min_severity:
            params["severity_gte"] = min_severity
        return {f.get("issue_id") for f in
                self._pages(f"/appsec/v2/applications/{app_guid}/findings", params, "findings", "Findings API")}


def build_state(build):
    """('ready' | 'wait' | 'fail', reason) for the latest scan of a branch."""
    if build is None:
        return "wait", "no scan found yet"
    if not build["results_ready"]:
        if any(w in build["status"].lower() for w in SCAN_FAILED_WORDS):
            return "fail", f"scan '{build['version']}' did not complete: {build['status']}"
        return "wait", f"scan '{build['version']}' in progress: {build['status'] or 'queued'}"
    rules = build["rules_status"].lower()
    if rules in ("", "not assessed") or rules.startswith("calculating"):
        return "wait", "results ready, waiting for the policy evaluation"
    return "ready", f"scan '{build['version']}' is ready"


def scan_commit(build, repo_dir, known=""):
    """Commit a scan was made from: the full SHA at the start of its scan version, or ''
    when the version doesn't start with a SHA. `known` is a full SHA it may abbreviate."""
    match = SHA_IN_VERSION.match(build["version"])
    if not match:
        return ""
    prefix = match.group(1).lower()
    if known and known.startswith(prefix):
        return known
    sha = expand_sha(prefix, repo_dir)
    if len(sha) != 40:
        raise Skip(f"scan '{build['version']}' names commit {prefix}, which is not in this checkout. "
                   "Put the full commit SHA in the scan version.")
    return sha


def wait_for_build(vc, app_id, sandbox_id, wait_minutes):
    deadline = time.monotonic() + wait_minutes * 60
    while True:
        build = vc.latest_build(app_id, sandbox_id)
        state, why = build_state(build)
        if state == "ready":
            log(f"Veracode: {why}")
            return build
        if state == "fail":
            raise Skip(why, blocking=True)
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

    def __init__(self, repo_dir, commit=None):
        """Files of `commit` when the checkout has it (sync), else of the checkout."""
        listing = None
        if commit and git(["cat-file", "-t", commit], repo_dir) == "commit":
            listing = git(["ls-tree", "-r", "-z", "--name-only", commit], repo_dir, timeout=300)
        if listing is None:
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


def fix_by(finding):
    """Policy grace period end as YYYY-MM-DD, or ''."""
    value = finding.get("grace_period_expires_date") or ""
    return value[:10] if re.match(r"\d{4}-\d{2}-\d{2}", value) else ""


def to_annotation(finding, files, is_new, link, today=None):
    """Platform-neutral annotation: external_id, severity (0-5), new, path, line,
    summary, details, link, overdue."""
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
    due = fix_by(finding)
    today = today or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    overdue = bool(due) and due < today
    if due:
        details.append(f"Fix by {due} (policy grace period){', overdue' if overdue else ''}")
    mitigation = MITIGATION_NOTES.get(((finding.get("finding_status") or {}).get("resolution_status") or "").upper())
    if mitigation:
        details.append(mitigation)
    details.append(f"Veracode issue ID: {finding.get('issue_id')}")
    return {
        "external_id": f"veracode-{finding.get('issue_id')}",
        "severity": severity,
        "new": is_new,
        "overdue": overdue,
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
    overdue = sum(a.get("overdue", False) for a in annotations)
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
    if ctx.get("note"):
        lines.insert(0, ctx["note"])
    if total:
        lines.append("Pull requests show annotations only on changed lines; this report lists them all.")
    if overdue:
        lines.append(f"{overdue} finding(s) are past their policy fix-by date.")
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
    single_url = None       # URL to upload one annotation; None = bulk requests only
    proxy_commit = ""       # Pipelines proxy: the commit this pipeline runs on

    def __init__(self, api, owner, slug, proxies=None, *, retry_post=False):
        self.api, self.owner, self.slug, self.proxies = api, owner, slug, proxies
        self.session = http_session(retry_post=retry_post)

    def _call(self, method, url, what, *, ok404=False, **kwargs):
        try:
            r = self.session.request(method, url, proxies=self.proxies, timeout=TIMEOUT, **kwargs)
            if ok404 and r.status_code == 404:
                return r
            return check(r, f"Bitbucket {what}")
        except requests.RequestException as exc:
            raise SystemExit(self.explain(url, f"ERROR: Bitbucket {what} failed: {network_reason(exc)}")) from None
        except SystemExit as exc:
            raise SystemExit(self.explain(url, str(exc))) from None

    def explain(self, url, message):
        """Add a hint when the Pipelines proxy is used for a commit other than its own."""
        match = re.search(r"/commit/([0-9a-f]{40})/", url)
        if self.proxy_commit and match and match.group(1) != self.proxy_commit and "proxy" not in message[-200:]:
            message += (f". This pipeline runs on commit {self.proxy_commit[:12]} and the Pipelines proxy may refuse "
                        f"reports for other commits: add the BITBUCKET_TOKEN repository variable (docs/SETUP.md), "
                        f"or run the report pipeline on commit {match.group(1)[:12]}")
        return message

    def publish(self, commit, report, annotations):
        """Replace the report on the commit and add its annotations. Returns the commit URL.
        If annotations fail, the report says so before the error is raised."""
        url = self.report_url(commit)
        self._call("DELETE", url, "delete report", ok404=True)
        self._call("PUT", url, "create report", json=self.report_body(report))
        body = [self.annotation_body(a) for a in annotations[:MAX_ANNOTATIONS]]
        batches = self.batches(body)
        rejected = []
        try:
            for n, batch in enumerate(batches, 1):
                count = len(batch) if isinstance(batch, list) else len(body)
                what = (f"add annotations (batch {n}/{len(batches)}: {count} annotations, "
                        f"{len(json.dumps(batch)) // 1024 + 1} KB)")
                try:
                    self._call("POST", f"{url}/annotations", what, json=batch)
                except SystemExit as error:
                    if self.single_url is None:
                        raise
                    log(f"WARNING: {str(error).removeprefix('ERROR: ')}. Retrying them one at a time.")
                    rejected += self.put_each(url, batch)
            if body and len(rejected) == len(body):
                raise SystemExit("ERROR: Bitbucket rejected every annotation (see above).")
        except (SystemExit, requests.RequestException):
            self.add_note(url, report, "Annotations could not be uploaded; open the Veracode results for the full list. ")
            raise
        if rejected:
            self.add_note(url, report, f"{len(rejected)} finding(s) were rejected by Bitbucket and are not shown "
                                       "here; open the Veracode results for them. ")
        return self.commit_url(commit)

    def put_each(self, url, batch):
        """Upload annotations one by one; returns the ones Bitbucket rejects. Raises when
        the first ones all fail: then it's the connection or permissions, not the content."""
        rejected, error = [], None
        for i, a in enumerate(batch):
            try:
                self._call("PUT", self.single_url(url, a), f"add annotation {a['external_id']}", json=a)
            except SystemExit as e:
                rejected.append(a)
                error = e
                log(f"  {a['external_id']} {a.get('path', '')}{':' + str(a['line']) if a.get('line') else ''}: "
                    f"{str(e).removeprefix('ERROR: ')}")
                if i == 4 and len(rejected) == 5:
                    raise SystemExit(f"{error} (also for single annotations)") from None
        return rejected

    def add_note(self, url, report, note):
        try:
            self._call("PUT", url, "update report", json=self.report_body(
                {**report, "details": (note + report["details"])[:MAX_TEXT]}))
        except (SystemExit, requests.RequestException):
            pass

    def posted_scan(self, commit):
        """Scan version shown on the commit's current report, or ''."""
        r = self._call("GET", self.report_url(commit), "read report", ok404=True)
        if r.status_code == 404 or not r.content:
            return ""
        return next((d.get("value") for d in r.json().get("data") or []
                     if d.get("title") == "Scan" and isinstance(d.get("value"), str)), "")

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
            self.proxy_commit = env.get("BITBUCKET_COMMIT", "").lower()
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

    @staticmethod
    def single_url(url, annotation):
        return f"{url}/annotations/{quote(annotation['external_id'], safe='')}"

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
    p.add_argument("--sync", action="store_true",
                   help="scheduled mode: post every finished scan (policy and all sandboxes) whose commit "
                        "has no report for it yet, without waiting")
    p.add_argument("--max-age-days", type=int, default=14,
                   help="--sync: ignore scans older than this (default 14)")
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
        # With a token, read the repository now (one GET) so a bad token or repo fails
        # before the wait, not after it. The Pipelines proxy may refuse this lookup.
        if not default_branch or bb.proxies is None:
            found = bb.default_branch()
            default_branch = default_branch or found
    if not default_branch:
        raise SystemExit("ERROR: could not read the default branch. Pass --default-branch.")
    return bb, default_branch


def find_app(vc, args, ctx):
    candidates = [args.app_name] if args.app_name else [f"{ctx['owner']}/{ctx['slug']}", ctx["slug"]]
    return vc.find_application(candidates, args.app_name or ctx["slug"])


def find_scan(vc, args, ctx, is_branch):
    """(application, sandbox or None, build) for this commit; raises Skip."""
    app = find_app(vc, args, ctx)
    sandbox = vc.find_sandbox(app["guid"], args.sandbox_name or ctx["sandbox"]) if is_branch else None
    log(f"Veracode: application '{app['profile']['name']}', "
        f"{'sandbox ' + repr(sandbox['name']) if sandbox else 'policy scan'}")
    build = wait_for_build(vc, app["id"], sandbox["id"] if sandbox else None, args.wait)
    return app, sandbox, build


def results_link(platform, app, build):
    oid = app.get("oid") or app.get("alt_org_id")
    if oid:
        return f"{platform}/auth/index.jsp#ReviewResultsAllFlaws:{oid}:{app['id']}:{build['build_id']}"
    fragment = app.get("results_url") or ""
    if fragment.startswith("http"):
        return fragment
    return f"{platform}/auth/index.jsp#{fragment}" if fragment else platform


def post_results(vc, bb, args, ctx, app, sandbox, build, files):
    """Build and post (or print) the report for one finished scan. Returns the report."""
    findings = vc.static_findings(app["guid"], sandbox["guid"] if sandbox else None)
    policy_ids = None
    if sandbox:
        lowest = min((int((f.get("finding_details") or {}).get("severity", 0) or 0) for f in findings), default=0)
        policy_ids = vc.policy_issue_ids(app["guid"], lowest) if findings else set()
    link = results_link(vc.platform, app, build)
    annotations = build_results(findings, policy_ids, files, link)
    report = build_report(ctx, build, annotations, sandbox is not None, link)
    log(f"Report: {'FAILED' if report['failed'] else 'PASSED'} - {report['details']}")
    if args.dry_run:
        cls = BitbucketDataCenter if ctx["server_url"] else BitbucketCloud
        log(json.dumps({"report": cls.report_body(report),
                        "annotations": [cls.annotation_body(a) for a in annotations[:MAX_ANNOTATIONS]]}, indent=2))
    else:
        where = bb.publish(ctx["commit"], report, annotations)
        log(f"Posted {min(len(annotations), MAX_ANNOTATIONS)} annotation(s): {where}")
    return report


def sync_target(vc, bb, args, ctx, app, sandbox, cutoff):
    """Post the latest scan of the policy (sandbox None) or a sandbox if it is finished and new."""
    build = vc.latest_build(app["id"], sandbox["id"] if sandbox else None)
    if build is None:
        raise Skip("no scan")
    state, why = build_state(build)
    if state != "ready":
        raise Skip(why)
    if build["published"] and build["published"] < cutoff:
        raise Skip(f"scan '{build['version']}' is older than {args.max_age_days} days")
    commit, note = scan_commit(build, args.repo_dir), ""
    if not commit:
        if sandbox:
            raise Skip(f"scan '{build['version']}' doesn't start with a commit SHA, so its commit is unknown")
        commit = git(["rev-parse", "HEAD"], args.repo_dir) or ""     # the sync runs on the default branch
        if len(commit) != 40:
            raise Skip(f"scan '{build['version']}' doesn't start with a commit SHA and the checkout has no HEAD")
        note = unnamed_note(build)
    if bb is not None and bb.posted_scan(commit) == build["version"]:
        raise Skip(f"scan '{build['version']}' already posted")
    log(f"{'sandbox ' + repr(ctx['sandbox']) if sandbox else 'policy scan'}: {why}")
    post_results(vc, bb, args, {**ctx, "commit": commit, "note": note}, app, sandbox, build,
                 RepoFiles(args.repo_dir, commit))


def unnamed_note(build):
    return (f"Scan '{build['version']}' doesn't start with a commit SHA, so it is shown on the latest "
            "commit; line numbers may be off if the code changed since the scan.")


def sync(args, env):
    """Scheduled mode: one pass over the policy scan and every sandbox, no waiting."""
    server_url = args.server_url or env.get("BITBUCKET_URL", "")
    server_url = require_https(server_url, "BITBUCKET_URL", strict=False) if server_url else ""
    owner, slug = ci_repo(args, env, server_url)
    if not (owner and slug):
        raise SystemExit("ERROR: could not detect the repository. Pass --repo <owner>/<repo>.")
    ctx = {"server_url": server_url, "owner": owner, "slug": slug}
    log(f"Bitbucket: {owner}/{slug} ({'Data Center ' + server_url if server_url else 'Cloud'}), sync")
    bb, default_branch = bitbucket_target(args, ctx, env)
    vc = Veracode()
    app = find_app(vc, args, ctx)
    cutoff = time.time() - args.max_age_days * 86400
    targets = [(None, default_branch)] + [(s, s.get("name", "")) for s in vc.sandboxes(app["guid"])]
    errors = 0
    for sandbox, branch in targets:
        label = f"sandbox '{branch}'" if sandbox else "policy scan"
        try:
            sync_target(vc, bb, args, {**ctx, "branch": branch, "sandbox": branch}, app, sandbox, cutoff)
        except Skip as why:
            log(f"{label}: skipped, {why}")
        except SystemExit as exc:          # one bad target (e.g. deleted commit) must not stop the rest
            if "HTTP 404" in str(exc):
                log(f"{label}: skipped, commit not found in Bitbucket (branch deleted or rewritten)")
            else:
                log(f"{label}: {exc}")
                errors += 1
    return 1 if errors else 0


def run(args, env=None):
    env = os.environ if env is None else env
    if args.sync:
        return sync(args, env)
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

    match = SHA_IN_VERSION.match(build["version"])
    if not (match and ctx["commit"].startswith(match.group(1).lower())):
        log(f"Veracode: scan '{build['version']}' was not made from this commit; showing it here with a note.")
        ctx = {**ctx, "note": f"Results of scan '{build['version']}', which was not made from this commit: "
                              "line numbers may be off where the code changed since."}
    report = post_results(vc, bb, args, ctx, app, sandbox, build, RepoFiles(args.repo_dir, ctx["commit"]))
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
