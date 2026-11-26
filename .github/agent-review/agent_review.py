#!/usr/bin/env python3
"""Agent review: an agent-reviewed pull request merges itself. Refs: TheHub #62342

The workflow .github/workflows/agent-review.yml runs this file from the default
branch. It posts the `agent-review` check run on a pull request's head and arms
auto-merge when that check passes. Branch protection requires the check,
pinned to the agent-review GitHub App.

WHEN THE CHECK PASSES. Every one of these must hold:

  * An issue comment on the pull request has this exact first line:
        **Independent review (<model>) at <sha8>: SHIP|SHIP WITH NITS|BLOCK**
    <model> is plain ASCII: letters, digits, spaces and . _ -. The comment's
    author must have write access (OWNER, MEMBER or COLLABORATOR). keel and
    personal-soc are public, so anyone can type the line. A PR review body can
    only block, never pass: GitHub keeps no trace of a review body's edits.
  * <sha8> is the current head, or a commit of this pull request whose change
    is the head's. The test for the same change has two parts. First, the PR
    must have the same files, statuses, resulting blobs and modes against the
    base. Second, if the merge base moved, main's changes between the two
    bases must be fully listed and must touch none of the PR's paths. That is
    what a clean merge of main leaves. A hand-resolved merge that keeps the
    PR's copy of a file main also changed does not pass it, because it would
    undo main's change unseen. A review at any other older head does not count.
  * The verdict is SHIP or SHIP WITH NITS, from a model that differs from
    every model in the PR's `Co-Authored-By: Claude ...` trailers. A trailer
    with no version ("Claude Sonnet") matches every version. A bare "Claude"
    matches every model, so no Claude can review that change. Every commit
    needs a model trailer, except merge commits and commits authored by
    Dependabot (author dependabot[bot] and a signature GitHub verified: the
    author login alone follows the commit's email). An unattributed commit cannot ride on an attributed one, and
    stripping a trailer cannot turn a self-review into an independent one.
  * No BLOCK applies to the change, and no verdict comment that applies to it
    was edited or deleted. Either one makes the check fail "sticky". A sticky
    run is never rewritten, so deleting the BLOCK afterwards does not bring the
    SHIP back. Only a new change, and a new review of it, gets past.
  * No malformed BLOCK applies to the change either. This is a trusted
    author's comment or review whose first non-empty line contains
    "Independent review" and "BLOCK" but is not the exact line. Strict parsing
    is right for a SHIP, since a near-miss only waits. For a BLOCK it would
    fail open, so a near-miss fails instead, in any letter case. That failure
    is not sticky: deleting or correcting the line clears it. A builder's note
    whose first line reads like one ("Rework after the independent review
    (BLOCK ...)") fails the head too, until it is reworded: the safe direction.
  * The PR comes from a branch of this repository (not a fork) and targets the
    default branch.

WHEN AUTO-MERGE IS ARMED. Only when the operator turned arming on
(AGENT_REVIEW_ARM=on), the check passes and the PR is not a draft. With arming
off the gate only judges: it posts the check and disarms, and never arms,
merges or updates a branch. That is the kill switch, and the enable script sets
it last. The change must also touch no control path: .github/, .claude/,
.sdlc/, platform/, ci/, any hooks/ directory, or test/manifest.txt. A change to
the gate, a workflow, a guard hook, the protection declaration or the pipeline
still waits for a person's merge. The list is the operator's choice. It leaves
out agent instruction files (CLAUDE.md, AGENTS.md), automation-policy.yml, the
scripts a workflow or the pipeline runs, and the tests: a change to those
merges itself once reviewed.

An arm GitHub accepted is announced with one comment on the PR, once per head.
A refused arm posts nothing and is tried again on the next run. The window to
veto: post a BLOCK verdict as a comment, or disable auto-merge. The gate never
re-arms a head it announced and a person then disarmed; a new push starts
again. Every other outcome disarms, before the check is written. The App's own
comments never start a run, so the announcement cannot re-run the gate.

STRICT BRANCHES (the train). On every run, the gate looks for an armed PR that
is "in flight": up to date, with no red check. If none is, it merges the
default branch into the oldest armed PR that is BEHIND, one PR per run. The
merged head keeps its review only when its change is the same (see above). A
red PR does not hold up the train.

WHAT THIS PROVES, AND WHAT IT DOES NOT. Every agent comments, commits and
pushes as the operator's GitHub account. GitHub therefore cannot say which
agent, or which model, wrote a comment or a trailer. Both are claims. What
GitHub does enforce:

  * The check run comes from the agent-review App. Branch protection pins the
    App's id. A user token cannot create check runs at all. A workflow on a PR
    branch runs as github-actions, a different app id. The App's key lives
    only in the `agent-review` environment, which deploys from the default
    branch only. Only code already on main can post the check, and that
    branch policy is the control to watch.
  * enforce_admins holds the operator's own token to the required checks.

What GitHub does not enforce, and rests on the agents' own rules and their
permission layer:

  * The control-path rule stops the gate arming. It does not stop the write
    credential from merging a PR whose check is green.
  * That credential can also change the protection, the environment or the
    App. A personal account's security log may not record those changes.
  * Anything that can make one agent lie, or steer it, can merge code outside
    the control paths with no person involved. That includes a builder that
    decides to, and text a builder reads from an issue or a dependency.

This gate makes the review protocol mechanical. Stale reviews, self-reviews
by mistake, ignored or malformed BLOCKs, hand merges and post-review pushes
all fail it. It does not authenticate the reviewer. That needs a reviewer
identity whose key no builder session can read, which is a separate story.

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
#: Authors that are not agents and carry no model trailer (with a verified signature).
BOT_AUTHORS = frozenset({"dependabot[bot]"})
#: A PR touching any of these never merges itself (see CONTROL_PATH).
CONTROL_PREFIXES = (".github/", ".claude/", ".sdlc/", "platform/", "ci/", "hooks/")
CONTROL_FILES = frozenset({"test/manifest.txt"})
#: GitHub's compare lists at most 300 files. A list that long may be cut short.
MAX_FILES = 300
#: How many of a PR's commits are checked for a sticky run.
MAX_COMMITS = 100
RED = frozenset({"failure", "timed_out", "cancelled", "action_required", "startup_failure"})

VERDICT = re.compile(
    r"\*\*Independent review \(([A-Za-z0-9 ._-]{1,64})\) at ([0-9a-f]{8}): "
    r"(SHIP WITH NITS|SHIP|BLOCK)\*\*"
)
TRAILER = re.compile(r"(?i)^\s*co-authored-by:\s*(.+?)\s*<[^>]*>\s*$")
MODEL_FAMILY = re.compile(r"(?i)\b(claude|opus|sonnet|haiku|fable)\b")
SHA_TOKEN = re.compile(r"(?<![0-9a-f])([0-9a-f]{7,40})(?![0-9a-f])")
#: The hidden marker in an arm announcement: the head it armed, in full.
ANNOUNCED = "<!-- agent-review-armed {sha} -->"
#: Bots that are not the agent-review App (a PR-branch workflow posts as github-actions).
OTHER_BOTS = frozenset({"github-actions[bot]", "dependabot[bot]"})


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
    """'Claude Opus 5.5', 'claude-opus-5-5' and 'Opus 5.5' all become 'opus-5-5'.
    A bare 'Claude' becomes '', which matches every model (same_model)."""
    tokens = re.findall(r"[a-z]+|[0-9]+", name.lower())
    return "-".join(t for t in tokens if t != "claude")


def same_model(a: str, b: str) -> bool:
    """Whether two model keys can name one model. A key without a version
    ('sonnet', from a 'Co-Authored-By: Claude Sonnet' trailer) matches every
    version of it, and an empty key (a bare 'Claude') matches everything;
    'opus-5-5' and 'opus-5-4' are two models."""
    if not a or not b:
        return True
    ta, tb = a.split("-"), b.split("-")
    n = min(len(ta), len(tb))
    return ta[:n] == tb[:n]


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


def _first_line(body: str | None) -> str:
    for line in (body or "").lstrip("﻿").splitlines():
        if line.strip():
            return line
    return ""


def loose_block(body: str | None) -> bool:
    """A first non-empty line that says "Independent review" and "BLOCK" but is
    not the exact verdict line: a BLOCK that missed the format."""
    line = _first_line(body).lower()
    return "independent review" in line and "block" in line and parse_verdict(body) is None


def commit_models(message: str | None) -> set[str]:
    models = set()
    for line in (message or "").splitlines():
        m = TRAILER.match(line.rstrip("\r"))
        if m and MODEL_FAMILY.search(m.group(1)):
            models.add(model_key(m.group(1)))
    return models


def builder_models(messages) -> set[str]:
    models: set[str] = set()
    for message in messages:
        models |= commit_models(message)
    return models


def control_path(path: str | None) -> bool:
    path = path or ""
    return (path.startswith(CONTROL_PREFIXES) or path in CONTROL_FILES
            or "/hooks/" in path)


def _paths(files) -> set[str]:
    return {p for f in files for p in (f.get("filename"), f.get("previous_filename")) if p}


def arming_enabled(env) -> bool:
    """The kill switch: the gate arms and merges only when the operator set
    AGENT_REVIEW_ARM to exactly "on"."""
    return env.get("AGENT_REVIEW_ARM") == "on"


def _by_a_bot(comment: dict) -> bool:
    return bool(comment.get("performed_via_github_app")) or \
        (comment.get("user") or {}).get("type") == "Bot"


def plan(event_name: str, event: dict, app_id: int):
    """(PR to judge first, whether to sweep) for one workflow event. A bot's
    comment starts nothing: the App's own announcement must not re-run the
    gate. An edit or a deletion judges its own PR only, so it never races
    the main run group's sweep."""
    if event_name != "issue_comment":
        return None, True
    comment = event.get("comment") or {}
    if _by_a_bot(comment):
        return None, False
    issue = event.get("issue") or {}
    if issue.get("pull_request") is None:
        return None, True
    return issue.get("number"), event.get("action") not in ("edited", "deleted")


def _fail(title, summary="", sticky=False):
    return Decision("failure", title, summary, sticky=sticky)


class Gate:
    def __init__(self, gh, repo: str, app_id: int, arming: bool = False):
        self.gh = gh
        self.repo = repo
        self.app_id = int(app_id)
        self.arming = arming

    # -- reading ---------------------------------------------------------------

    def _ours(self, runs):
        return sorted(
            (r for r in runs or []
             if r.get("name") == CHECK_NAME and (r.get("app") or {}).get("id") == self.app_id),
            key=lambda r: r.get("id") or 0,
        )

    def _compare(self, base: str, sha: str, cache: dict):
        """(files, merge base) of sha against base, or (None, None) when the
        list is unknown or may be cut short."""
        key = ("compare", base, sha)
        if key not in cache:
            data = self.gh.compare(base, sha)
            files = None if data is None else data.get("files")
            if files is None or len(files) >= MAX_FILES:
                cache[key] = (None, None)
            else:
                cache[key] = (files, data.get("merge_base"))
        return cache[key]

    def _files(self, base, sha, cache):
        return self._compare(base, sha, cache)[0]

    def _fingerprint(self, base, sha, cache, modes=True):
        files = self._files(base, sha, cache)
        if files is None:
            return None
        tree = {}
        if modes:
            key = ("modes", sha)
            if key not in cache:
                cache[key] = self.gh.tree_modes(sha)
            tree = cache[key]
            if tree is None:
                return None
        return tuple(sorted(
            (f.get("filename", ""), f.get("status", ""), f.get("sha") or "",
             f.get("previous_filename") or "", tree.get(f.get("filename", ""), "") if modes else "")
            for f in files
        ))

    def _same_tree(self, base, sha, head, cache) -> bool:
        """For a sticky mark: the same files and blobs. An unknown list counts
        as the same, so a lost listing never lifts a BLOCK."""
        if sha == head:
            return True
        a = self._fingerprint(base, sha, cache, modes=False)
        b = self._fingerprint(base, head, cache, modes=False)
        return a is None or b is None or a == b

    def _carries(self, base, sha, head, cache) -> bool:
        """For a review: the same change, as the module docstring defines it."""
        if sha == head:
            return True
        a = self._fingerprint(base, sha, cache)
        if a is None or a != self._fingerprint(base, head, cache):
            return False
        old = self._compare(base, sha, cache)[1]
        new = self._compare(base, head, cache)[1]
        if not old or not new:
            return False
        if old == new:
            return True
        drift = self._files(old, new, cache)
        if drift is None:
            return False
        pr = _paths(self._files(base, sha, cache)) | _paths(self._files(base, head, cache))
        return not (pr & _paths(drift))

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

        def named(token: str) -> list[str]:
            return [s for s in shas if s.startswith(token)]

        def applies(sha8: str) -> str | None:
            """The commit a review at sha8 names, when its change is the head's."""
            if head.startswith(sha8):
                return head
            hits = named(sha8)
            if len(hits) == 1 and self._carries(base, hits[0], head, cache):
                return hits[0]
            return None

        def blocks(sha8: str) -> bool:
            """Whether a BLOCK naming sha8 holds against the head: any named
            commit with the head's tree counts."""
            return head.startswith(sha8) or any(self._same_tree(base, s, head, cache)
                                                for s in named(sha8))

        # A BLOCK or a tampered verdict already recorded on this change stands.
        for sha in shas[-MAX_COMMITS:]:
            if any(r.get("external_id") == STICKY for r in self._ours(self.gh.check_runs(sha))):
                if self._same_tree(base, sha, head, cache):
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
                    if v and (applies(v.sha8) or blocks(v.sha8)):
                        return _fail(f"Blocked: a verdict comment was {event['action']}",
                                     f"{comment.get('html_url', '')}. A verdict is final once "
                                     "posted; post a fresh review of a new head.", sticky=True)

        reviews, ignored, loose = [], 0, []
        comments = self.gh.issue_comments(number)
        bodies = [(c, True) for c in comments] + [(r, False) for r in self.gh.pr_reviews(number)]
        for c, is_comment in bodies:
            body = c.get("body")
            v = parse_verdict(body)
            trusted = c.get("author_association") in TRUSTED
            if not v:
                if trusted and loose_block(body):
                    tokens = SHA_TOKEN.findall(_first_line(body))
                    if not tokens or any(blocks(t) for t in tokens):
                        loose.append(c)
                continue
            if not trusted:
                ignored += 1
                continue
            if is_comment:
                target = applies(v.sha8)
                if target:
                    reviews.append((c, v, target))
            elif v.verdict == "BLOCK" and blocks(v.sha8):
                return _fail(f"Blocked by {v.model} at {v.sha8} (a PR review)",
                             f"{c.get('html_url', '')}. Push a fix and ask for a new review.",
                             sticky=True)
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
        if loose:
            return _fail("Blocked: a malformed BLOCK line applies to this head",
                         f"{loose[0].get('html_url', '')}. Its first line names a BLOCK but is "
                         "not the exact verdict line. Correct or delete it, or push a fix. A "
                         "note that only mentions an earlier BLOCK on its first line counts "
                         "too: reword that line.")

        ships = [(c, v, t) for c, v, t in reviews if v.verdict in ("SHIP", "SHIP WITH NITS")]
        if not ships:
            return Decision(None, f"Waiting for an independent review at {head[:8]}",
                            "No SHIP, SHIP WITH NITS or BLOCK at this head (or at a commit with "
                            "the same change). A review at an older head does not count." + note)

        for c in commits:
            if len(c.get("parents") or []) > 1:
                continue
            if ((c.get("author") or {}).get("login") in BOT_AUTHORS
                    and ((c["commit"].get("verification") or {}).get("verified") is True)):
                continue
            if not commit_models(c["commit"].get("message", "")):
                return _fail(f"Not independent: commit {c['sha'][:8]} names no builder model",
                             "Every commit needs a `Co-Authored-By: Claude ...` trailer (merge "
                             "commits and Dependabot's own signed commits excepted), so the "
                             "review can "
                             "be shown to come from another model." + note)
        builders = builder_models(c["commit"].get("message", "") for c in commits)
        independent = [(c, v, t) for c, v, t in ships
                       if not any(same_model(v.model_key, b) for b in builders)]
        if not independent:
            return _fail("Not independent: the reviewer is the same model as the builder",
                         f"Builder: {', '.join(sorted(b or 'claude (any)' for b in builders))}. "
                         f"Reviews: {', '.join(v.model for _, v, _ in ships)}." + note)

        c, v, target = independent[-1]
        files = self._files(base, head, cache)
        touches_control = files is None or any(
            control_path(f.get("filename")) or control_path(f.get("previous_filename"))
            for f in files
        )
        why_not = (" Not armed: a draft." if pr.get("draft") else
                   " Not armed: the change touches a control path (or its file list is "
                   "incomplete); a person merges it." if touches_control else "")
        carried = "" if target == head else f" (carried from {target[:8]}: same change)"
        return Decision(
            "success",
            f"{v.verdict} by {v.model} at {v.sha8}{carried}",
            f"{c.get('html_url', '')}. Builder: "
            f"{', '.join(sorted(builders)) or (pr.get('user') or {}).get('login', '')}. "
            "The model names are claims: every agent acts as one GitHub account."
            + why_not + note,
            arm=not pr.get("draft") and not touches_control,
        )

    # -- writing -----------------------------------------------------------------

    def evaluate(self, number: int, event: dict | None = None) -> Decision:
        pr = self.gh.get_pr(number)
        d = self.decide(pr, event)
        head = pr["head"]["sha"]
        announced = False
        if self.arming and d.arm and not pr.get("auto_merge"):
            announced = self._announced(number, head)
            if announced:
                # Armed and announced, and now off: a person disarmed it. A veto.
                d = Decision(d.conclusion, d.title,
                             d.summary + " Not armed: a person disarmed this head after the "
                             "gate armed it. A person merges it, or a new push starts again.")
        ours = self._ours(self.gh.check_runs(head))
        if any(r.get("external_id") == STICKY for r in ours):
            # Posted by another run since this one read: it stands, unwritten.
            d = _fail("Blocked: a BLOCK or an edited verdict stands for this change", sticky=True)
        # Disarm before anything else is written: a failed write must not leave it armed.
        if not d.arm and pr.get("auto_merge"):
            self.gh.set_auto_merge(pr, False)
        if not any(r.get("external_id") == STICKY for r in ours):
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
        armed = ""
        if self.arming and d.arm and not pr.get("auto_merge") and not announced:
            # GitHub's answer decides: a refused arm posts nothing, so it cannot loop.
            armed = self.gh.set_auto_merge(pr, True) or ""
            if armed:
                self.gh.comment(number, (
                    (f"agent-review merged {head[:8]} directly (it was already mergeable): "
                     if armed == "merged" else f"agent-review armed auto-merge at {head[:8]}: ")
                    + f"{d.title}.\n\n"
                    "It merges when the required checks pass. To stop it, post a BLOCK verdict "
                    "as a comment, or disable auto-merge: the gate does not re-arm this head "
                    "after that. A BLOCK in a PR review is read only on the next run. "
                    "Refs: TheHub #62342\n\n" + ANNOUNCED.format(sha=head)))
        print(f"#{number} @ {head[:8]}: {d.conclusion or 'waiting'} - {d.title}"
              f"{' [' + str(armed) + ']' if armed else ''}")
        return d

    def _announced(self, number: int, head: str) -> bool:
        """Whether this App already announced an arm of this exact head."""
        marker = ANNOUNCED.format(sha=head)
        for c in self.gh.issue_comments(number):
            app = (c.get("performed_via_github_app") or {}).get("id")
            user = c.get("user") or {}
            ours = app == self.app_id or (app is None and user.get("type") == "Bot"
                                          and user.get("login") not in OTHER_BOTS)
            if ours and marker in (c.get("body") or ""):
                return True
        return False

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
        if not self.arming:
            return None
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

    def compare(self, base, sha):
        try:
            data = self._get(f"/compare/{base}...{sha}")
        except urllib.error.HTTPError:
            return None
        return {"files": data.get("files"),
                "merge_base": (data.get("merge_base_commit") or {}).get("sha")}

    def tree_modes(self, sha):
        """{path: mode} for every blob at sha, or None when the tree is cut short."""
        try:
            data = self._get(f"/git/trees/{sha}?recursive=1")
        except urllib.error.HTTPError:
            return None
        if data.get("truncated"):
            return None
        return {t["path"]: t["mode"] for t in data.get("tree") or [] if t.get("type") == "blob"}

    def pr_reviews(self, number):
        return self._pages(f"/pulls/{number}/reviews?per_page=100")

    def comment(self, number, body):
        _request("POST", f"/repos/{self.repo}/issues/{number}/comments", self.token,
                 body={"body": body})

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
        """Truthy when GitHub did it: "armed", "merged" (already mergeable, so
        merged at this exact head) or, to disarm, "disarmed". "" when refused."""
        if not on:
            errors = self._graphql("mutation($id:ID!){disablePullRequestAutoMerge("
                                   "input:{pullRequestId:$id}){clientMutationId}}", pr)
            if errors:
                print(f"#{pr['number']}: disarm: {errors}", file=sys.stderr)
            return "" if errors else "disarmed"
        errors = self._graphql("mutation($id:ID!){enablePullRequestAutoMerge(input:"
                               "{pullRequestId:$id,mergeMethod:SQUASH}){clientMutationId}}", pr)
        if not errors:
            return "armed"
        if any("clean status" in e for e in errors):
            # Already mergeable: GitHub refuses auto-merge then. Merge this exact head.
            try:
                _request("PUT", f"/repos/{self.repo}/pulls/{pr['number']}/merge", self.token,
                         body={"merge_method": "squash", "sha": pr["head"]["sha"]})
                return "merged"
            except urllib.error.HTTPError as exc:
                print(f"#{pr['number']}: merge refused: {exc.code}", file=sys.stderr)
                return ""
        print(f"#{pr['number']}: arm: {errors}", file=sys.stderr)
        return ""

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
    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as fh:
        event = json.load(fh)
    number, sweep = plan(os.environ.get("GITHUB_EVENT_NAME", ""), event, app_id)
    if number is None and not sweep:
        print("a bot's comment: nothing to judge")
        return 0
    gate = Gate(RestGitHub(repo, token), repo, app_id, arming=arming_enabled(os.environ))
    print(f"arming: {'on' if gate.arming else 'off (AGENT_REVIEW_ARM is not on): judging only'}")
    if number is not None:
        gate.evaluate(number, event=event)
    if sweep:
        gate.sweep()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
