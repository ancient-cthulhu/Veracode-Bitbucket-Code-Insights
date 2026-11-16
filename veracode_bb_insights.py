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

Requirements: Python 3.9+, pip install -r requirements.txt
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

REPORT_KEY = "veracode-sast"
REPORTER = "Veracode"
TIMEOUT = 60
POLL_SECONDS = 30
MAX_ANNOTATIONS = 1000      # Bitbucket limit per report
BATCH_SIZE = 100            # Bitbucket Cloud limit per request

# Scan version must start with the commit SHA (7-40 hex), then "-" or the end.
SHA_IN_VERSION = re.compile(r"^([0-9a-fA-F]{7,40})(?:-|$)")
SCAN_FAILED_WORDS = ("failed", "error", "cancel", "no modules")

SEVERITY_NAMES = {5: "Very High", 4: "High", 3: "Medium", 2: "Low", 1: "Very Low", 0: "Info"}
CLOUD_SEVERITY = {5: "CRITICAL", 4: "HIGH", 3: "MEDIUM"}   # anything lower -> LOW
DC_SEVERITY = {5: "HIGH", 4: "HIGH", 3: "MEDIUM"}          # Data Center has no CRITICAL

PLATFORM_HOSTS = {
    "global": ("https://api.veracode.com", "https://analysiscenter.veracode.com"),
    "eu": ("https://api.veracode.eu", "https://analysiscenter.veracode.eu"),
    "fedramp": ("https://api.veracode.us", "https://analysiscenter.veracode.us"),
}


class Skip(Exception):
    """Nothing to post. Not an error: the step exits 0."""


def log(msg=""):
    print(msg, flush=True)


def http_session():
    """requests session that retries rate limits and gateway errors."""
    session = requests.Session()
    retry = Retry(total=5, backoff_factor=2, status_forcelist=(429, 502, 503, 504),
                  allowed_methods=None, respect_retry_after_header=True)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers["User-Agent"] = "veracode-bitbucket-code-insights"
    return session


def check(response, what):
    """Raise a short, readable error (no headers, no secrets) for a failed call."""
    if response.status_code >= 400:
        body = (response.text or "").strip().replace("\n", " ")[:300]
        raise SystemExit(f"ERROR: {what} failed: HTTP {response.status_code} {body}")
    return response


# =============================================================================
# 1. CI CONTEXT: commit, branch, repository
# =============================================================================
def git(args, cwd="."):
    try:
        out = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,
                             timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


def clean_branch(name):
    for prefix in ("refs/heads/", "origin/"):
        if name.startswith(prefix):
            name = name[len(prefix):]
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


def detect_context(args):
    env = os.environ
    ctx = {"server_url": (args.server_url or env.get("BITBUCKET_URL", "")).rstrip("/")}

    commit = args.commit or env.get("BITBUCKET_COMMIT") or env.get("GIT_COMMIT") \
        or git(["rev-parse", "HEAD"], args.repo_dir)
    # Jenkins "merge with target branch" PR builds use a local merge commit that
    # does not exist in Bitbucket; its first parent is the PR head commit.
    if not args.commit and env.get("CHANGE_ID") and not env.get("BITBUCKET_COMMIT"):
        parents = git(["rev-list", "--parents", "-n", "1", "HEAD"], args.repo_dir).split()
        if len(parents) > 2:
            commit = git(["rev-parse", "HEAD^1"], args.repo_dir) or commit
    ctx["commit"] = commit.lower()

    ctx["branch"] = clean_branch(args.branch or env.get("BITBUCKET_BRANCH") or env.get("CHANGE_BRANCH")
                                 or env.get("BRANCH_NAME") or env.get("GIT_BRANCH")
                                 or git(["rev-parse", "--abbrev-ref", "HEAD"], args.repo_dir))

    if args.repo:
        owner, _, slug = args.repo.partition("/")
    elif env.get("BITBUCKET_WORKSPACE") and env.get("BITBUCKET_REPO_SLUG"):
        owner, slug = env["BITBUCKET_WORKSPACE"], env["BITBUCKET_REPO_SLUG"]
    else:
        owner, slug = parse_repo_url(env.get("GIT_URL") or git(["remote", "get-url", "origin"], args.repo_dir))
    if ctx["server_url"] and owner and not owner.startswith("~"):
        owner = owner.upper()                          # Data Center project keys are upper case
    ctx["owner"], ctx["slug"] = owner, slug

    missing = [k for k in ("commit", "branch", "owner", "slug") if not ctx.get(k)]
    if missing:
        raise SystemExit(f"ERROR: could not detect {', '.join(missing)}. "
                         "Pass --commit, --branch and --repo <owner>/<repo>.")
    if ctx["branch"] == "HEAD":
        raise SystemExit("ERROR: detached HEAD, pass --branch <branch name>.")
    if not re.fullmatch(r"[0-9a-f]{7,40}", ctx["commit"]):
        raise SystemExit(f"ERROR: '{ctx['commit']}' is not a commit SHA.")
    return ctx


# =============================================================================
# 2. VERACODE
# =============================================================================
def veracode_credentials():
    """Accept VERACODE_API_ID / VERACODE_API_KEY (also the signing library's own
    names, or ~/.veracode/credentials). Returns the API ID, for the region."""
    for ours, lib in (("VERACODE_API_ID", "VERACODE_API_KEY_ID"),
                      ("VERACODE_API_KEY", "VERACODE_API_KEY_SECRET")):
        if os.getenv(ours) and not os.getenv(lib):
            os.environ[lib] = os.environ[ours]
    from veracode_api_signing.credentials import get_credentials
    try:
        return get_credentials()[0]
    except Exception:  # noqa: BLE001 - library raises several types
        raise SystemExit("ERROR: Veracode credentials not found. Set VERACODE_API_ID and VERACODE_API_KEY.") from None


class Veracode:
    def __init__(self):
        from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
        from veracode_api_signing.regions import get_region_for_api_credential
        api_id = veracode_credentials()
        self.rest, self.platform = PLATFORM_HOSTS[get_region_for_api_credential(api_id)]
        if os.getenv("VERACODE_API_BASE"):
            self.rest = os.environ["VERACODE_API_BASE"].rstrip("/")
            self.platform = self.rest.replace("://api.", "://analysiscenter.")
        self.session = http_session()
        self.session.auth = RequestsAuthPluginVeracodeHMAC()

    def _get(self, url, params, what):
        return check(self.session.get(url, params=params, timeout=TIMEOUT), what)

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
        apps = list(self._pages("/appsec/v1/applications", {"name": search, "size": 100},
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
        sandboxes = list(self._pages(f"/appsec/v1/applications/{app_guid}/sandboxes", {"size": 100},
                                     "sandboxes", "Sandbox API"))
        exact = [s for s in sandboxes if s.get("name") == name]
        loose = [s for s in sandboxes if s.get("name", "").lower() == name.lower()]
        if exact or len(loose) == 1:
            return (exact or loose)[0]
        raise Skip(f"No sandbox named '{name}'. The scan step must use the branch name as the sandbox name.")

    def latest_build(self, app_id, sandbox_id=None):
        """getbuildinfo.do (XML API): most recent static scan, or None."""
        params = {"app_id": app_id}
        if sandbox_id is not None:
            params["sandbox_id"] = sandbox_id
        r = self._get(f"{self.platform}/api/5.0/getbuildinfo.do", params, "getbuildinfo.do")
        root = ET.fromstring(r.content)
        if root.tag.endswith("error"):
            return None
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

    def static_findings(self, app_guid, sandbox_guid=None, violates_policy=False):
        """Open static findings, without approved mitigations."""
        params = {"scan_type": "STATIC", "size": 500}
        if sandbox_guid:
            params["context"] = sandbox_guid
        if violates_policy:
            params["violates_policy"] = "TRUE"
        out = []
        for f in self._pages(f"/appsec/v2/applications/{app_guid}/findings", params, "findings", "Findings API"):
            status = f.get("finding_status", {})
            if status.get("status", "").upper() == "CLOSED":
                continue
            if status.get("resolution_status", "").upper() == "APPROVED":
                continue
            out.append(f)
        return out


def build_state(build, commit):
    """('ready' | 'wait' | 'skip', reason) for the latest scan."""
    if build is None:
        return "wait", "no scan found yet"
    match = SHA_IN_VERSION.match(build["version"])
    if not match:
        return "skip", (f"latest scan '{build['version']}' is not named after a commit. "
                        "Name the scan version '<commit SHA>-<build number>'.")
    if not commit.startswith(match.group(1).lower()):
        return "skip", f"latest scan '{build['version']}' is for another commit"
    if not build["results_ready"]:
        if any(w in build["status"].lower() for w in SCAN_FAILED_WORDS):
            return "skip", f"scan '{build['version']}' did not complete: {build['status']}"
        return "wait", f"scan '{build['version']}' in progress: {build['status'] or 'queued'}"
    rules = build["rules_status"].lower()
    if rules in ("", "not assessed") or rules.startswith("calculating"):
        return "wait", "results ready, waiting for the policy evaluation"
    return "ready", f"scan '{build['version']}' is ready"


def wait_for_build(vc, app_id, sandbox_id, commit, wait_minutes):
    deadline = time.time() + wait_minutes * 60
    while True:
        build = vc.latest_build(app_id, sandbox_id)
        state, why = build_state(build, commit)
        if state == "ready":
            log(f"Veracode: {why}")
            return build
        if state == "skip":
            raise Skip(why)
        if time.time() >= deadline:
            raise Skip(f"{why} (stopped waiting after {wait_minutes} min)")
        log(f"Veracode: {why}; checking again in {POLL_SECONDS}s")
        time.sleep(POLL_SECONDS)


# =============================================================================
# 3. FINDINGS -> ANNOTATIONS
# =============================================================================
class RepoFiles:
    """Maps a Veracode file path to a path in the repository by matching the
    longest common ending, e.g. com/acme/Dao.java -> src/main/java/com/acme/Dao.java."""

    def __init__(self, repo_dir):
        listing = git(["ls-files", "-z"], repo_dir)
        files = [f for f in listing.split("\0") if f] if listing else self._walk(repo_dir)
        self.by_name = {}
        for path in files:
            self.by_name.setdefault(path.rsplit("/", 1)[-1].lower(), []).append(path)

    @staticmethod
    def _walk(repo_dir):
        out = []
        for root, dirs, names in os.walk(repo_dir):
            dirs[:] = [d for d in dirs if d != ".git"]
            rel = os.path.relpath(root, repo_dir).replace(os.sep, "/")
            out += [n if rel == "." else f"{rel}/{n}" for n in names]
        return out

    def resolve(self, vc_path):
        parts = [p for p in (vc_path or "").replace("\\", "/").lower().split("/") if p]
        if not parts:
            return None
        best, best_score, tie = None, 0, False
        for candidate in self.by_name.get(parts[-1], []):
            cparts = candidate.lower().split("/")
            score = 0
            while score < min(len(parts), len(cparts)) and parts[-1 - score] == cparts[-1 - score]:
                score += 1
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

    def handle_endtag(self, tag):
        self.parts.append(" ")


def plain_text(description, limit=1200):
    """Veracode descriptions are HTML: what is wrong, how to fix it, references."""
    parser = _TextOnly()
    parser.feed(description or "")
    text = " ".join("".join(parser.parts).split())
    text = text.split("References:")[0].strip()
    return text if len(text) <= limit else text[:limit - 3].rstrip() + "..."


def to_annotation(finding, files, is_new, link):
    d = finding.get("finding_details", {})
    severity = int(d.get("severity", 0) or 0)
    cwe = d.get("cwe", {}) or {}
    category = (d.get("finding_category", {}) or {}).get("name") or cwe.get("name") or "Finding"
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
        "summary": summary[:450],
        "details": "\n".join(x for x in details if x),
        "link": link,
    }


def build_results(findings, policy_ids, files, link):
    """policy_ids is None on the default branch, else the set of issue IDs open in the policy scan."""
    annotations = [to_annotation(f, files, policy_ids is not None and f.get("issue_id") not in policy_ids, link)
                   for f in findings]
    annotations.sort(key=lambda a: (not a["new"], -a["severity"], a["path"] is None, a["path"] or "", a["line"] or 0))
    return annotations


def build_report(ctx, build, annotations, is_branch, link):
    total = len(annotations)
    new = sum(a["new"] for a in annotations)
    unmapped = sum(a["path"] is None for a in annotations)
    omitted = max(0, total - MAX_ANNOTATIONS)

    if is_branch:
        failed = new > 0
        lines = [f"{new} finding(s) new in this branch violate the Veracode policy "
                 f"({total} in total, {total - new} already in the policy scan)."]
        title = f"Veracode SAST (sandbox {ctx['branch']})"
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
    return {"title": title, "details": " ".join(lines), "failed": failed, "data": data[:6], "link": link}


# =============================================================================
# 4. BITBUCKET (Cloud and Data Center)
# =============================================================================
class BitbucketCloud:
    def __init__(self, owner, slug):
        self.owner, self.slug = owner, slug
        self.session = http_session()
        self.proxies = None
        token, user = os.getenv("BITBUCKET_TOKEN", ""), os.getenv("BITBUCKET_USER", "")
        if token:
            self.api = "https://api.bitbucket.org/2.0"
            if user:      # Atlassian API token: Basic auth with the account email
                self.session.auth = (user, token)
            else:         # repository / workspace access token
                self.session.headers["Authorization"] = f"Bearer {token}"
        elif os.getenv("BITBUCKET_BUILD_NUMBER"):
            # Inside Bitbucket Pipelines: the local proxy adds authentication.
            proxy = os.getenv("BITBUCKET_PROXY", "http://localhost:29418")
            self.api = "http://api.bitbucket.org/2.0"
            self.proxies = {"http": proxy, "https": proxy}
        else:
            raise SystemExit("ERROR: set BITBUCKET_TOKEN (needed outside Bitbucket Pipelines).")

    def _call(self, method, url, what, ok404=False, **kwargs):
        r = self.session.request(method, url, proxies=self.proxies, timeout=TIMEOUT, **kwargs)
        if ok404 and r.status_code == 404:
            return r
        return check(r, what)

    def default_branch(self):
        r = self._call("GET", f"{self.api}/repositories/{self.owner}/{self.slug}", "Bitbucket repository")
        return (r.json().get("mainbranch") or {}).get("name", "")

    def publish(self, commit, report, annotations):
        url = f"{self.api}/repositories/{self.owner}/{self.slug}/commit/{commit}/reports/{REPORT_KEY}"
        self._call("DELETE", url, "Bitbucket delete report", ok404=True)
        self._call("PUT", url, "Bitbucket create report", json=self.report_body(report))
        body = [self.annotation_body(a) for a in annotations[:MAX_ANNOTATIONS]]
        for i in range(0, len(body), BATCH_SIZE):
            self._call("POST", f"{url}/annotations", "Bitbucket add annotations", json=body[i:i + BATCH_SIZE])
        return f"https://bitbucket.org/{self.owner}/{self.slug}/commits/{commit}"

    @staticmethod
    def report_body(report):
        data = []
        for title, kind, value in report["data"]:
            if kind == "LINK":
                value = {"text": "Open in Veracode", "href": value}
            data.append({"title": title, "type": kind, "value": value})
        return {"title": report["title"], "details": report["details"], "report_type": "SECURITY",
                "reporter": REPORTER, "link": report["link"],
                "result": "FAILED" if report["failed"] else "PASSED", "data": data}

    @staticmethod
    def annotation_body(a):
        body = {"external_id": a["external_id"], "annotation_type": "VULNERABILITY",
                "summary": a["summary"], "details": a["details"][:2000],
                "severity": CLOUD_SEVERITY.get(a["severity"], "LOW"), "link": a["link"]}
        if a["path"]:
            body["path"] = a["path"]
            if a["line"]:
                body["line"] = a["line"]
        return body


class BitbucketDataCenter(BitbucketCloud):
    def __init__(self, server_url, owner, slug):  # pylint: disable=super-init-not-called
        self.owner, self.slug = owner, slug
        self.server = server_url
        self.api = f"{server_url}/rest"
        self.session = http_session()
        self.proxies = None
        token = os.getenv("BITBUCKET_TOKEN", "")
        if not token:
            raise SystemExit("ERROR: set BITBUCKET_TOKEN (HTTP access token with repository write).")
        self.session.headers["Authorization"] = f"Bearer {token}"

    def _repo(self):
        return f"projects/{self.owner}/repos/{self.slug}"

    def default_branch(self):
        for path in ("default-branch", "branches/default"):     # newer / older servers
            r = self._call("GET", f"{self.api}/api/latest/{self._repo()}/{path}",
                           "Bitbucket default branch", ok404=True)
            if r.status_code != 404:
                return r.json().get("displayId", "")
        return ""

    def publish(self, commit, report, annotations):
        url = f"{self.api}/insights/latest/{self._repo()}/commits/{commit}/reports/{REPORT_KEY}"
        self._call("DELETE", url, "Bitbucket delete report", ok404=True)
        self._call("PUT", url, "Bitbucket create report", json=self.report_body(report))
        body = [self.annotation_body(a) for a in annotations[:MAX_ANNOTATIONS]]
        for i in range(0, len(body), BATCH_SIZE):
            self._call("POST", f"{url}/annotations", "Bitbucket add annotations",
                       json={"annotations": body[i:i + BATCH_SIZE]})
        return f"{self.server}/{self._repo()}/commits/{commit}"

    @staticmethod
    def report_body(report):
        data = []
        for title, kind, value in report["data"]:
            if kind == "LINK":
                value = {"linktext": "Open in Veracode", "href": value}
            data.append({"title": title, "type": kind, "value": value})
        return {"title": report["title"][:450], "details": report["details"][:2000], "reporter": REPORTER,
                "link": report["link"], "result": "FAIL" if report["failed"] else "PASS", "data": data}

    @staticmethod
    def annotation_body(a):
        message = f"{a['summary']}\n{a['details']}"
        body = {"externalId": a["external_id"], "type": "VULNERABILITY",
                "message": message[:2000], "severity": DC_SEVERITY.get(a["severity"], "LOW"), "link": a["link"]}
        if a["path"]:
            body["path"] = a["path"]
            if a["line"]:
                body["line"] = a["line"]
        return body


# =============================================================================
# 5. MAIN
# =============================================================================
def parse_args(argv):
    p = argparse.ArgumentParser(description="Post Veracode SAST policy findings to Bitbucket Code Insights.")
    p.add_argument("--commit", help="commit SHA (default: from CI variables)")
    p.add_argument("--branch", help="branch name (default: from CI variables)")
    p.add_argument("--repo", help="<workspace or PROJECT>/<repo slug> (default: from CI variables)")
    p.add_argument("--server-url", help="Bitbucket Data Center URL (or BITBUCKET_URL). Omit for Cloud.")
    p.add_argument("--default-branch", help="default branch (default: asked from Bitbucket)")
    p.add_argument("--app-name", default=os.getenv("VERACODE_APP_NAME", ""),
                   help="Veracode application profile (default: <owner>/<repo>, then <repo>)")
    p.add_argument("--sandbox-name", help="sandbox name (default: the branch name)")
    p.add_argument("--repo-dir", default=".", help="repository checkout used to match file paths")
    p.add_argument("--wait", type=int, default=20, help="minutes to wait for scan results (default 20)")
    p.add_argument("--fail-build", action="store_true", help="exit 2 when the report is FAILED")
    p.add_argument("--dry-run", action="store_true", help="print the report instead of posting it")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    ctx = detect_context(args)
    log(f"Bitbucket: {ctx['owner']}/{ctx['slug']} branch '{ctx['branch']}' commit {ctx['commit'][:12]}"
        f" ({'Data Center ' + ctx['server_url'] if ctx['server_url'] else 'Cloud'})")

    default_branch = args.default_branch or os.getenv("BITBUCKET_DEFAULT_BRANCH", "")
    bb = None
    if not args.dry_run or not default_branch:        # a dry run with --default-branch needs no Bitbucket access
        bb = (BitbucketDataCenter(ctx["server_url"], ctx["owner"], ctx["slug"]) if ctx["server_url"]
              else BitbucketCloud(ctx["owner"], ctx["slug"]))
        default_branch = default_branch or bb.default_branch()
    if not default_branch:
        raise SystemExit("ERROR: could not read the default branch. Pass --default-branch.")
    is_branch = ctx["branch"] != default_branch

    vc = Veracode()
    candidates = [args.app_name] if args.app_name else [f"{ctx['owner']}/{ctx['slug']}", ctx["slug"]]
    try:
        app = vc.find_application(candidates, args.app_name or ctx["slug"])
        app_name = app["profile"]["name"]
        sandbox = vc.find_sandbox(app["guid"], args.sandbox_name or ctx["branch"]) if is_branch else None
        log(f"Veracode: application '{app_name}', "
            f"{'sandbox ' + repr(sandbox['name']) if sandbox else 'policy scan'}")
        build = wait_for_build(vc, app["id"], sandbox["id"] if sandbox else None, ctx["commit"], args.wait)
    except Skip as why:
        log(f"Nothing posted: {why}")
        return 0

    findings = vc.static_findings(app["guid"], sandbox["guid"] if sandbox else None, violates_policy=True)
    policy_ids = None
    if sandbox:
        policy_ids = {f.get("issue_id") for f in vc.static_findings(app["guid"])}

    oid = app.get("oid") or app.get("alt_org_id")
    link = (f"{vc.platform}/auth/index.jsp#ReviewResultsAllFlaws:{oid}:{app['id']}:{build['build_id']}"
            if oid else app.get("results_url") or vc.platform)
    annotations = build_results(findings, policy_ids, RepoFiles(args.repo_dir), link)
    report = build_report(ctx, build, annotations, is_branch, link)
    log(f"Report: {'FAILED' if report['failed'] else 'PASSED'} - {report['details']}")

    if args.dry_run:
        log(json.dumps({"report": report, "annotations": annotations[:MAX_ANNOTATIONS]}, indent=2))
    else:
        where = bb.publish(ctx["commit"], report, annotations)
        log(f"Posted {min(len(annotations), MAX_ANNOTATIONS)} annotation(s): {where}")
    return 2 if args.fail_build and report["failed"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except requests.RequestException as exc:
        sys.exit(f"ERROR: network call failed: {type(exc).__name__}: {str(exc)[:300]}")
