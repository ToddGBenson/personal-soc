#!/usr/bin/env python3
"""Agent review: an agent-reviewed pull request merges itself. Refs: TheHub #62342

The workflow .github/workflows/agent-review.yml runs this file from the default
branch. It posts the `agent-review` check run on a pull request's head and arms
auto-merge when that check passes. Branch protection requires the check,
pinned to the agent-review GitHub App.

WHEN THE CHECK PASSES. Every one of these must hold:

  * A comment on the pull request has this exact first line:
        **Independent review (<model>) at <sha8>: SHIP|SHIP WITH NITS|BLOCK**
    The comment's author must have write access (OWNER, MEMBER or
    COLLABORATOR). keel and personal-soc are public, so anyone can type the
    line.
  * <sha8> is the current head, or a commit of this pull request whose change
    is identical to the head's. "Identical" means the same files with the
    same resulting blobs against the base. That is what a merge of main into
    the branch leaves when main touched none of the PR's files. A review at
    any other older head does not count.
  * The verdict is SHIP or SHIP WITH NITS, from a model that differs from
    every model in the PR's `Co-Authored-By: Claude ...` trailers. A trailer
    with no version ("Claude Sonnet") matches every version. A PR by an
    agent with no such trailer does not pass: stripping the trailer must not
    turn a self-review into an independent one. A Dependabot PR needs no
    trailer.
  * No BLOCK applies to the change, and no verdict comment that applies to it
    was edited or deleted. Either one makes the check fail "sticky". A sticky
    run is never rewritten, so deleting the BLOCK afterwards does not bring the
    SHIP back. Only a new change, and a new review of it, gets past.
  * The PR comes from a branch of this repository (not a fork) and targets the
    default branch.

WHEN AUTO-MERGE IS ARMED. Only when the check passes, the PR is not a draft,
and it changes nothing under .github/. A change to the gate itself, or to any
workflow, still waits for the operator's merge button. The gate disarms
auto-merge on every other outcome.

STRICT BRANCHES (the train). On every run, the gate looks for an armed PR that
is "in flight": up to date, with no red check. If none is, it merges the
default branch into the oldest armed PR that is BEHIND, one PR per run. The
merged head keeps its review only when its change is identical (see above). A
red PR does not hold up the train.

WHAT THIS PROVES, AND WHAT IT DOES NOT. Every agent comments, commits and
pushes as the operator's GitHub account. GitHub therefore cannot say which
agent, or which model, wrote a comment or a trailer. Both are claims. What
GitHub does enforce:

  * The check run comes from the agent-review App. Branch protection pins the
    App's id. A user token cannot create check runs at all. A workflow on a PR
    branch runs as github-actions, a different app id. The App's key lives
    only in the `agent-review` environment, which deploys from the default
    branch only, so only code already on main can post the check.
  * Changing that code is a PR under .github/. The gate never arms auto-merge
    for one.
  * enforce_admins holds the operator's own token to all of the above. Only a
    settings change gets past it, and a settings change is audit-logged.

What it does not stop: an agent that decides to lie. A builder can post a SHIP
comment under another model's name, or write a false trailer. This gate turns
the review protocol into a mechanical rule. Stale reviews, self-reviews by
mistake, ignored BLOCKs and post-review pushes all fail it. It does not
authenticate the reviewer.

    python3 agent_review.py run    # in the workflow: judge open PRs, then run the train
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

CHECK_NAME = "agent-review"
#: A check run's external_id when it records a BLOCK or a tampered verdict.
STICKY = "sticky"
TRUSTED = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
#: Authors that are not agents and carry no model trailer.
BOT_AUTHORS = frozenset({"dependabot[bot]"})
#: A PR touching this tree never merges itself.
GATE_TREE = ".github/"
#: GitHub's compare lists at most 300 files. A list that long may be cut short.
MAX_FILES = 300
#: How many of a PR's commits are checked for a sticky run.
MAX_COMMITS = 100
RED = frozenset({"failure", "timed_out", "cancelled", "action_required", "startup_failure"})

VERDICT = re.compile(
    r"\*\*Independent review \(([^()\r\n]{1,64})\) at ([0-9a-f]{8}): "
    r"(SHIP WITH NITS|SHIP|BLOCK)\*\*"
)
TRAILER = re.compile(r"(?i)^\s*co-authored-by:\s*(.+?)\s*<[^>]*>\s*$")
MODEL_FAMILY = re.compile(r"(?i)\b(claude|opus|sonnet|haiku|fable)\b")


@dataclass(frozen=True)
class Verdict:
    model: str
    model_key: str
    sha8: str
    verdict: str


@dataclass
class Decision:
    conclusion: str | None  # "success", "failure", or None (waiting)
    title: str
    summary: str = ""
    sticky: bool = False
    arm: bool = False


def model_key(name: str) -> str:
    """'Claude Opus 5.5', 'claude-opus-5-5' and 'Opus 5.5' all become 'opus-5-5'."""
    tokens = re.findall(r"[a-z]+|[0-9]+", name.lower())
    return "-".join(t for t in tokens if t != "claude")


def same_model(a: str, b: str) -> bool:
    """Whether two model keys can name one model. A key without a version
    ('sonnet', from a 'Co-Authored-By: Claude Sonnet' trailer) matches every
    version of it; 'opus-5-5' and 'opus-5-4' are two models."""
    ta, tb = a.split("-"), b.split("-")
    n = min(len(ta), len(tb))
    return n > 0 and ta[:n] == tb[:n]


def parse_verdict(body: str | None) -> Verdict | None:
    first = (body or "").split("\n", 1)[0]
    if first.endswith("\r"):
        first = first[:-1]
    m = VERDICT.fullmatch(first)
    if not m:
        return None
    key = model_key(m.group(1))
    if not key:
        return None
    return Verdict(m.group(1), key, m.group(2), m.group(3))


def builder_models(messages) -> set[str]:
    models = set()
    for message in messages:
        for line in (message or "").splitlines():
            m = TRAILER.match(line.rstrip("\r"))
            if m and MODEL_FAMILY.search(m.group(1)):
                key = model_key(m.group(1))
                if key:
                    models.add(key)
    return models


def _fail(title, summary="", sticky=False):
    return Decision("failure", title, summary, sticky=sticky)


class Gate:
    def __init__(self, gh, repo: str, app_id: int):
        self.gh = gh
        self.repo = repo
        self.app_id = int(app_id)

    # -- reading ---------------------------------------------------------------

    def _ours(self, runs):
        return sorted(
            (r for r in runs or []
             if r.get("name") == CHECK_NAME and (r.get("app") or {}).get("id") == self.app_id),
            key=lambda r: r.get("id") or 0,
        )

    def _files(self, base: str, sha: str, cache: dict):
        if sha not in cache:
            files = self.gh.compare_files(base, sha)
            cache[sha] = None if files is None or len(files) >= MAX_FILES else files
        return cache[sha]

    def _fingerprint(self, base: str, sha: str, cache: dict):
        files = self._files(base, sha, cache)
        if files is None:
            return None
        return tuple(sorted(
            (f.get("filename", ""), f.get("status", ""), f.get("sha") or "",
             f.get("previous_filename") or "")
            for f in files
        ))

    def _same_change(self, base, sha, head, cache) -> bool:
        if sha == head:
            return True
        a = self._fingerprint(base, sha, cache)
        return a is not None and a == self._fingerprint(base, head, cache)

    # -- the decision ------------------------------------------------------------

    def decide(self, pr: dict, event: dict | None = None) -> Decision:
        number = pr["number"]
        head = pr["head"]["sha"]
        base_repo = pr["base"]["repo"]
        base = pr["base"]["ref"]
        if (pr["head"].get("repo") or {}).get("full_name") != base_repo.get("full_name"):
            return _fail("Not judged: the pull request comes from a fork",
                         "Only branches of this repository merge themselves.")
        if base != base_repo.get("default_branch"):
            return _fail(f"Not judged: the pull request targets {base}, not the default branch")

        commits = self.gh.pr_commits(number)
        shas = [c["sha"] for c in commits]
        if head not in shas:
            shas.append(head)
        cache: dict = {}

        def applies(sha8: str) -> str | None:
            """The commit a review at sha8 names, when its change is the head's."""
            if head.startswith(sha8):
                return head
            named = [s for s in shas if s.startswith(sha8)]
            if len(named) == 1 and self._same_change(base, named[0], head, cache):
                return named[0]
            return None

        # A BLOCK or a tampered verdict already recorded on this change stands.
        for sha in shas[-MAX_COMMITS:]:
            if any(r.get("external_id") == STICKY for r in self._ours(self.gh.check_runs(sha))):
                if self._same_change(base, sha, head, cache):
                    return _fail("Blocked: a BLOCK or an edited verdict stands for this change",
                                 f"Recorded on {sha[:8]}. Push a fix and ask for a new review.",
                                 sticky=True)

        # An edit or a deletion of a verdict that applies to this change.
        if event and event.get("action") in ("edited", "deleted"):
            comment = event.get("comment") or {}
            old = ((event.get("changes") or {}).get("body") or {}).get("from")
            if comment.get("author_association") in TRUSTED:
                for body in (comment.get("body"), old):
                    v = parse_verdict(body)
                    if v and applies(v.sha8):
                        return _fail(f"Blocked: a verdict comment was {event['action']}",
                                     f"{comment.get('html_url', '')}. A verdict is final once "
                                     "posted; post a fresh review of a new head.", sticky=True)

        reviews, ignored = [], 0
        for c in self.gh.issue_comments(number):
            v = parse_verdict(c.get("body"))
            if not v:
                continue
            if c.get("author_association") not in TRUSTED:
                ignored += 1
                continue
            target = applies(v.sha8)
            if target:
                reviews.append((c, v, target))
        note = f" {ignored} verdict line(s) from accounts without write access were ignored." \
            if ignored else ""

        for c, v, _ in reviews:
            if c.get("updated_at") != c.get("created_at"):
                return _fail("Blocked: a verdict comment was edited after posting",
                             f"{c.get('html_url', '')}. A verdict is final once posted.",
                             sticky=True)
        for c, v, _ in reviews:
            if v.verdict == "BLOCK":
                return _fail(f"Blocked by {v.model} at {v.sha8}",
                             f"{c.get('html_url', '')}. Push a fix and ask for a new review.",
                             sticky=True)

        ships = [(c, v, t) for c, v, t in reviews if v.verdict in ("SHIP", "SHIP WITH NITS")]
        if not ships:
            return Decision(None, f"Waiting for an independent review at {head[:8]}",
                            "No SHIP, SHIP WITH NITS or BLOCK at this head (or at a commit with "
                            "an identical change). A review at an older head does not count." + note)

        builders = builder_models(c["commit"].get("message", "") for c in commits)
        author = (pr.get("user") or {}).get("login", "")
        if not builders and author not in BOT_AUTHORS:
            return _fail("Not independent: the builder's model is unknown",
                         "No commit carries a `Co-Authored-By: Claude ...` trailer, so the "
                         "review cannot be shown to come from another model." + note)
        independent = [(c, v, t) for c, v, t in ships
                       if not any(same_model(v.model_key, b) for b in builders)]
        if not independent:
            return _fail("Not independent: the reviewer is the same model as the builder",
                         f"Builder: {', '.join(sorted(builders))}. Reviews: "
                         f"{', '.join(v.model for _, v, _ in ships)}." + note)

        c, v, target = independent[-1]
        files = self._files(base, head, cache)
        touches_gate = files is None or any(
            (f.get("filename") or "").startswith(GATE_TREE)
            or (f.get("previous_filename") or "").startswith(GATE_TREE)
            for f in files
        )
        why_not = (" Not armed: a draft." if pr.get("draft") else
                   " Not armed: the change touches .github/ (or its file list is incomplete); "
                   "the operator merges it." if touches_gate else "")
        carried = "" if target == head else f" (carried from {target[:8]}: identical change)"
        return Decision(
            "success",
            f"{v.verdict} by {v.model} at {v.sha8}{carried}",
            f"{c.get('html_url', '')}. Builder: {', '.join(sorted(builders)) or author}. "
            "The model names are claims: every agent acts as one GitHub account."
            + why_not + note,
            arm=not pr.get("draft") and not touches_gate,
        )

    # -- writing -----------------------------------------------------------------

    def evaluate(self, number: int, event: dict | None = None) -> Decision:
        pr = self.gh.get_pr(number)
        d = self.decide(pr, event)
        head = pr["head"]["sha"]
        ours = self._ours(self.gh.check_runs(head))
        if any(r.get("external_id") == STICKY for r in ours):
            # Posted by another run since this one read: it stands, unwritten.
            d = _fail("Blocked: a BLOCK or an edited verdict stands for this change", sticky=True)
        else:
            fields = {"name": CHECK_NAME, "external_id": STICKY if d.sticky else "",
                      "output": {"title": d.title[:255], "summary": d.summary[:60000] or d.title}}
            if d.conclusion:
                fields.update(status="completed", conclusion=d.conclusion)
            else:
                fields["status"] = "in_progress"
            latest = ours[-1] if ours else None
            # A completed run is replaced by a new one rather than reopened.
            if latest and not (latest.get("status") == "completed" and not d.conclusion):
                self.gh.update_check(latest["id"], fields)
            else:
                self.gh.create_check(head, fields)
        if d.arm and not pr.get("auto_merge"):
            self.gh.set_auto_merge(pr, True)
        elif not d.arm and pr.get("auto_merge"):
            self.gh.set_auto_merge(pr, False)
        print(f"#{number} @ {head[:8]}: {d.conclusion or 'waiting'} - {d.title}"
              f"{' [armed]' if d.arm else ''}")
        return d

    def _red(self, sha: str) -> bool:
        return any(r.get("name") != CHECK_NAME and r.get("conclusion") in RED
                   for r in self.gh.check_runs(sha))

    def sweep(self):
        judged = []
        for pr in sorted(self.gh.list_open_prs(), key=lambda p: (p.get("created_at") or "",
                                                                 p["number"])):
            if pr["base"]["ref"] != (pr["base"].get("repo") or {}).get("default_branch"):
                continue
            try:
                d = self.evaluate(pr["number"])
            except Exception as exc:  # one PR never stops the rest
                print(f"#{pr['number']}: not judged: {exc}", file=sys.stderr)
                continue
            judged.append((pr["number"], d))
        return self.train(judged)

    def train(self, judged):
        ready = [self.gh.get_pr(n) for n, d in judged if d.arm]
        for pr in ready:
            if pr.get("mergeable_state") not in ("behind", "dirty") and not self._red(pr["head"]["sha"]):
                print(f"train: #{pr['number']} is in flight; nothing updated")
                return None
        for pr in ready:
            if pr.get("mergeable_state") == "behind":
                if self.gh.update_branch(pr["number"], pr["head"]["sha"]):
                    print(f"train: merged the base into #{pr['number']}")
                    return pr["number"]
        return None


# -- GitHub ----------------------------------------------------------------------

API = "https://api.github.com"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _request(method, url, token, body=None, scheme="token"):
    req = urllib.request.Request(
        url if url.startswith("http") else API + url,
        data=None if body is None else json.dumps(body).encode(),
        method=method,
        headers={"Authorization": f"{scheme} {token}", "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "agent-review"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read()
        return (json.loads(raw) if raw else None), resp.headers.get("Link", "")


def mint_token(app_id: int, key_pem: str, repo: str) -> str:
    """An installation token for this one repository, signed with openssl."""
    now = int(time.time())
    signing = (_b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()) + "."
               + _b64(json.dumps({"iat": now - 60, "exp": now + 540, "iss": str(app_id)}).encode()))
    keydir = tempfile.mkdtemp(dir=os.environ.get("RUNNER_TEMP"))
    keyfile = os.path.join(keydir, "k.pem")
    fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key_pem.encode())
        os.close(fd)
        sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", keyfile],
                             input=signing.encode(), capture_output=True, check=True).stdout
    finally:
        os.unlink(keyfile)
        os.rmdir(keydir)
    jwt = signing + "." + _b64(sig)
    inst, _ = _request("GET", f"/repos/{repo}/installation", jwt, scheme="Bearer")
    tok, _ = _request("POST", f"/app/installations/{inst['id']}/access_tokens", jwt, scheme="Bearer",
                      body={"repositories": [repo.split("/", 1)[1]],
                            "permissions": {"checks": "write", "contents": "write",
                                            "pull_requests": "write"}})
    print(f"::add-mask::{tok['token']}")
    return tok["token"]


class RestGitHub:
    def __init__(self, repo: str, token: str):
        self.repo = repo
        self.token = token

    def _get(self, path):
        return _request("GET", f"/repos/{self.repo}{path}", self.token)[0]

    def _pages(self, path, key=None, limit=1000):
        out, url = [], f"/repos/{self.repo}{path}"
        while url and len(out) < limit:
            data, link = _request("GET", url, self.token)
            out += data[key] if key else data
            m = re.search(r'<([^>]+)>;\s*rel="next"', link)
            url = m.group(1) if m else None
        return out

    def get_pr(self, number):
        return self._get(f"/pulls/{number}")

    def list_open_prs(self):
        return self._pages("/pulls?state=open&per_page=100")

    def pr_commits(self, number):
        return self._pages(f"/pulls/{number}/commits?per_page=100", limit=250)

    def issue_comments(self, number):
        return self._pages(f"/issues/{number}/comments?per_page=100")

    def compare_files(self, base, sha):
        try:
            data = self._get(f"/compare/{base}...{sha}")
        except urllib.error.HTTPError:
            return None
        return data.get("files")

    def check_runs(self, sha):
        return self._pages(f"/commits/{sha}/check-runs?filter=all&per_page=100", key="check_runs")

    def create_check(self, sha, fields):
        return _request("POST", f"/repos/{self.repo}/check-runs", self.token,
                        body={"head_sha": sha, **fields})[0]

    def update_check(self, run_id, fields):
        return _request("PATCH", f"/repos/{self.repo}/check-runs/{run_id}", self.token,
                        body=fields)[0]

    def _graphql(self, query, pr):
        data, _ = _request("POST", "/graphql", self.token,
                           body={"query": query, "variables": {"id": pr["node_id"]}},
                           scheme="bearer")
        return [e.get("message", "") for e in (data or {}).get("errors") or []]

    def set_auto_merge(self, pr, on):
        if not on:
            errors = self._graphql("mutation($id:ID!){disablePullRequestAutoMerge("
                                   "input:{pullRequestId:$id}){clientMutationId}}", pr)
            if errors:
                print(f"#{pr['number']}: disarm: {errors}", file=sys.stderr)
            return
        errors = self._graphql("mutation($id:ID!){enablePullRequestAutoMerge(input:"
                               "{pullRequestId:$id,mergeMethod:SQUASH}){clientMutationId}}", pr)
        if errors and any("clean status" in e for e in errors):
            # Already mergeable: GitHub refuses auto-merge then. Merge this exact head.
            try:
                _request("PUT", f"/repos/{self.repo}/pulls/{pr['number']}/merge", self.token,
                         body={"merge_method": "squash", "sha": pr["head"]["sha"]})
            except urllib.error.HTTPError as exc:
                print(f"#{pr['number']}: merge refused: {exc.code}", file=sys.stderr)
        elif errors:
            print(f"#{pr['number']}: arm: {errors}", file=sys.stderr)

    def update_branch(self, number, expected_head):
        try:
            _request("PUT", f"/repos/{self.repo}/pulls/{number}/update-branch", self.token,
                     body={"expected_head_sha": expected_head})
            return True
        except urllib.error.HTTPError as exc:
            print(f"#{number}: update refused: {exc.code}", file=sys.stderr)
            return False


def main(argv) -> int:
    if argv[1:] != ["run"]:
        print(__doc__)
        return 2
    repo = os.environ["GITHUB_REPOSITORY"]
    app_id = int(os.environ["AGENT_REVIEW_APP_ID"])
    token = mint_token(app_id, os.environ["AGENT_REVIEW_APP_KEY"], repo)
    gate = Gate(RestGitHub(repo, token), repo, app_id)
    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as fh:
        event = json.load(fh)
    name = os.environ.get("GITHUB_EVENT_NAME", "")
    if name == "issue_comment" and (event.get("issue") or {}).get("pull_request"):
        gate.evaluate(event["issue"]["number"], event=event)
    gate.sweep()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
