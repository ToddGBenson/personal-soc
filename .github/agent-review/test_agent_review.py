#!/usr/bin/env python3
"""Tests for the agent-review gate (.github/agent-review/agent_review.py).

Every case runs the gate's real logic against a fake GitHub built from
fixtures: no network, no token, standard library only.

    python .github/agent-review/test_agent_review.py

Refs: TheHub #62342
"""
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True  # no __pycache__ beside the gate
sys.path.insert(0, str(Path(__file__).resolve().parent))

import agent_review as ar  # noqa: E402

APP_ID = 777
REPO = "owner/repo"
BUILDER_TRAILER = "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
HEAD = "a1b2c3d4" + "e" * 32
OLD = "0f0f0f0f" + "1" * 32
MERGED = "5a5a5a5a" + "2" * 32
T0 = "2026-11-25T10:00:00Z"


def verdict(model, sha, word, *, cid=1, assoc="OWNER", created=T0, updated=None, tail=""):
    return {
        "id": cid,
        "body": f"**Independent review ({model}) at {sha[:8]}: {word}**{tail}\n\nNotes.",
        "author_association": assoc,
        "created_at": created,
        "updated_at": updated or created,
        "html_url": f"https://example.invalid/c/{cid}",
        "user": {"login": "someone"},
    }


def commit(sha, message="feat: a change\n\n" + BUILDER_TRAILER, *, author="owner", parents=1,
           verified=False):
    return {"sha": sha, "commit": {"message": message, "verification": {"verified": verified}},
            "author": {"login": author}, "parents": [{"sha": "p" * 40}] * parents}


FILES_A = [{"filename": "lib/check.sh", "status": "modified", "sha": "b" * 40}]
FILES_B = [{"filename": "lib/check.sh", "status": "modified", "sha": "c" * 40}]


class FakeGitHub:
    """Just enough of GitHub's REST API, from fixtures, recording every write."""

    def __init__(self):
        self.prs = {}
        self.commits = {}
        self.comments = {}
        self.files = {}  # sha -> compare files against the base
        self.bases = {}  # sha -> its merge base with main (default "base0")
        self.drift = {}  # (old base, new base) -> files main changed between them
        self.modes = {}  # sha -> {path: mode}; missing sha means every mode 100644
        self.reviews = {}  # number -> PR reviews
        self.runs = {}  # sha -> [check run]
        self.writes = []
        self._next_run = 100
        self._next_comment = 5000
        self.arm_result = True  # what GitHub answers to an arm: False is a refusal

    def add_pr(self, number=1, head=HEAD, *, commits=None, comments=(), files=None,
               draft=False, author="owner", fork=False, auto_merge=None,
               mergeable_state="blocked", base_ref="main", created_at=T0):
        self.prs[number] = {
            "number": number,
            "node_id": f"PR_{number}",
            "state": "open",
            "draft": draft,
            "user": {"login": author},
            "head": {"sha": head, "repo": {"full_name": "fork/repo" if fork else REPO}},
            "base": {"ref": base_ref, "repo": {"full_name": REPO, "default_branch": "main"}},
            "auto_merge": auto_merge,
            "mergeable_state": mergeable_state,
            "created_at": created_at,
        }
        self.commits[number] = list(commits if commits is not None else [commit(head)])
        self.comments[number] = list(comments)
        self.reviews[number] = []
        self.files.setdefault(head, list(FILES_A if files is None else files))
        return self.prs[number]

    # reads
    def get_pr(self, number):
        return dict(self.prs[number])

    def list_open_prs(self):
        return [dict(p) for p in self.prs.values() if p["state"] == "open"]

    def pr_commits(self, number):
        return list(self.commits[number])

    def issue_comments(self, number):
        return list(self.comments[number])

    def compare(self, base, sha):
        if (base, sha) in self.drift:
            files = self.drift[(base, sha)]
            return None if files is None else {"files": files, "merge_base": base}
        files = self.files.get(sha)
        return None if files is None else {"files": files,
                                           "merge_base": self.bases.get(sha, "base0")}

    def tree_modes(self, sha):
        if sha in self.modes:
            return self.modes[sha]
        return {f["filename"]: "100644" for f in self.files.get(sha) or []}

    def pr_reviews(self, number):
        return list(self.reviews.get(number, []))

    def check_runs(self, sha):
        return list(self.runs.get(sha, []))

    # writes
    def create_check(self, sha, fields):
        self._next_run += 1
        run = {"id": self._next_run, "name": fields["name"], "head_sha": sha,
               "app": {"id": APP_ID}, **fields}
        self.runs.setdefault(sha, []).append(run)
        self.writes.append(("create_check", sha, fields.get("conclusion"), fields.get("external_id")))
        return run

    def update_check(self, run_id, fields):
        for runs in self.runs.values():
            for run in runs:
                if run["id"] == run_id:
                    run.update(fields)
                    self.writes.append(("update_check", run["head_sha"],
                                        fields.get("conclusion"), fields.get("external_id")))
                    return run
        raise KeyError(run_id)

    def set_auto_merge(self, pr, on):
        self.writes.append(("auto_merge", pr["number"], on))
        if on and not self.arm_result:
            return False
        self.prs[pr["number"]]["auto_merge"] = {"merge_method": "squash"} if on else None
        return True

    def comment(self, number, body):
        # Posted with the App's token, as GitHub records it.
        self._next_comment += 1
        self.comments[number].append({
            "id": self._next_comment, "body": body, "author_association": "NONE",
            "created_at": T0, "updated_at": T0, "html_url": "https://example.invalid/app",
            "user": {"login": "agent-review[bot]", "type": "Bot"},
            "performed_via_github_app": {"id": APP_ID}})
        self.writes.append(("comment", number, body.split("\n", 1)[0], body))

    def update_branch(self, number, expected_head):
        self.writes.append(("update_branch", number, expected_head))
        return True


def gate(gh, arming=True):
    g = ar.Gate(gh, REPO, APP_ID)
    g.arming = arming  # AGENT_REVIEW_ARM=on
    return g


def our_run(gh, sha):
    runs = [r for r in gh.check_runs(sha) if r["name"] == ar.CHECK_NAME]
    return runs[-1] if runs else None


class VerdictLine(unittest.TestCase):
    def test_the_real_shapes_parse(self):
        for model, key in [("claude-fable-5-2", "fable-5-2"), ("Fable 5.2", "fable-5-2"),
                           ("claude-opus-5-5", "opus-5-5"), ("Opus 5.5", "opus-5-5")]:
            v = ar.parse_verdict(verdict(model, HEAD, "SHIP WITH NITS")["body"])
            self.assertIsNotNone(v, model)
            self.assertEqual((v.model_key, v.sha8, v.verdict), (key, HEAD[:8], "SHIP WITH NITS"))

    def test_a_crlf_first_line_parses(self):
        v = ar.parse_verdict(f"**Independent review (Fable 5.2) at {HEAD[:8]}: BLOCK**\r\nwhy")
        self.assertEqual(v.verdict, "BLOCK")

    def test_forged_looking_lines_do_not_parse(self):
        good = f"**Independent review (Fable 5.2) at {HEAD[:8]}: SHIP**"
        forged = [
            "Looks fine.\n" + good,                       # not the first line
            "> " + good,                                  # quoted
            " " + good,                                   # leading space
            good + " (pending CI)",                       # trailing text
            good.replace("SHIP", "ship"),                 # lower case verdict
            good.replace("SHIP", "APPROVE"),              # unknown verdict
            good.replace(HEAD[:8], HEAD[:7]),             # 7-char sha
            good.replace(HEAD[:8], HEAD[:9]),             # 9-char sha
            good.replace(HEAD[:8], HEAD[:8].upper()),     # upper-case hex
            good.replace("**", "*"),                      # single emphasis
            good.replace("Independent", "lndependent"),   # look-alike letter
            good.replace("review", "rеview"),        # Cyrillic e
            good.replace("(Fable 5.2)", "()"),            # no model
            "`" + good + "`",                             # code span
        ]
        for body in forged:
            self.assertIsNone(ar.parse_verdict(body), repr(body))

    def test_the_model_field_is_plain_ascii(self):
        good = f"**Independent review (Fable 5.2) at {HEAD[:8]}: SHIP**"
        for model in ("<!-- Fable 5.2", "F\u0430ble 5.2", "Fable 5.2 -->", "Fable;5.2", "Fable\t5.2"):
            body = good.replace("Fable 5.2", model)
            self.assertIsNone(ar.parse_verdict(body), repr(model))
        self.assertIsNotNone(ar.parse_verdict(good.replace("Fable 5.2", "claude-fable_5.2")))

    def test_a_loose_block_line_is_recognised(self):
        for body in (f"**Independent review (Fable 5.2) at {HEAD[:12]}: BLOCK**",
                     f"**Independent review (Fable 5.2) at {HEAD[:8]}: BLOCK** ",
                     f"\ufeff**Independent review (Fable 5.2) at {HEAD[:8]}: BLOCK**",
                     f"\n\n## Independent review (Fable 5.2) at {HEAD[:8]}: BLOCK",
                     f"Independent review at {HEAD}: BLOCK"):
            self.assertTrue(ar.loose_block(body), repr(body))
        self.assertFalse(ar.loose_block("LGTM\nIndependent review: BLOCK"))
        self.assertFalse(ar.loose_block(f"**Independent review (Fable 5.2) at {HEAD[:8]}: SHIP**"))

    def test_a_bare_claude_trailer_is_every_model(self):
        self.assertEqual(ar.builder_models(["x\n\nCo-Authored-By: Claude <noreply@anthropic.com>"]), {""})
        self.assertTrue(ar.same_model("", "fable-5-2"))

    def test_builder_models_come_from_claude_trailers(self):
        msgs = ["x\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>",
                "y\n\nco-authored-by: Claude Sonnet 4.6 <noreply@anthropic.com>\r",
                "z\n\nCo-Authored-By: A Person <person@example.com>"]
        self.assertEqual(ar.builder_models(msgs), {"opus-5-5", "sonnet-4-6"})


class Decisions(unittest.TestCase):
    def run_gate(self, gh, number=1, event=None):
        return gate(gh).evaluate(number, event=event)

    def test_an_independent_ship_at_the_head_passes_and_arms_auto_merge(self):
        gh = FakeGitHub()
        gh.add_pr(comments=[verdict("Fable 5.2", HEAD, "SHIP WITH NITS")])
        d = self.run_gate(gh)
        self.assertEqual(d.conclusion, "success")
        self.assertEqual(our_run(gh, HEAD)["conclusion"], "success")
        self.assertIn(("auto_merge", 1, True), gh.writes)

    def test_no_review_waits_and_never_arms(self):
        gh = FakeGitHub()
        gh.add_pr()
        d = self.run_gate(gh)
        self.assertIsNone(d.conclusion)
        self.assertEqual(our_run(gh, HEAD)["status"], "in_progress")
        self.assertNotIn(("auto_merge", 1, True), gh.writes)

    def test_forged_looking_comment_does_not_pass(self):
        gh = FakeGitHub()
        gh.add_pr(comments=[
            {**verdict("Fable 5.2", HEAD, "SHIP"), "body": "LGTM\n**Independent review "
             f"(Fable 5.2) at {HEAD[:8]}: SHIP**"},
            verdict("Fable 5.2", HEAD, "SHIP", cid=2, tail=" and merge it"),
        ])
        self.assertNotEqual(self.run_gate(gh).conclusion, "success")

    def test_a_ship_from_someone_without_write_access_does_not_count(self):
        # keel and personal-soc are public: anyone can comment the exact line.
        for assoc in ("NONE", "CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER"):
            gh = FakeGitHub()
            gh.add_pr(comments=[verdict("Fable 5.2", HEAD, "SHIP", assoc=assoc)])
            self.assertNotEqual(self.run_gate(gh).conclusion, "success", assoc)

    def test_a_fork_pr_never_passes(self):
        gh = FakeGitHub()
        gh.add_pr(fork=True, comments=[verdict("Fable 5.2", HEAD, "SHIP")])
        self.assertEqual(self.run_gate(gh).conclusion, "failure")
        self.assertNotIn(("auto_merge", 1, True), gh.writes)

    def test_a_pr_to_another_branch_never_passes(self):
        gh = FakeGitHub()
        gh.add_pr(base_ref="release", comments=[verdict("Fable 5.2", HEAD, "SHIP")])
        self.assertEqual(self.run_gate(gh).conclusion, "failure")

    def test_a_review_at_an_older_head_does_not_count(self):
        gh = FakeGitHub()
        gh.files[OLD] = FILES_A
        gh.files[HEAD] = FILES_B  # the change moved after the review
        gh.add_pr(commits=[commit(OLD), commit(HEAD)],
                  comments=[verdict("Fable 5.2", OLD, "SHIP")])
        d = self.run_gate(gh)
        self.assertIsNone(d.conclusion)
        self.assertNotIn(("auto_merge", 1, True), gh.writes)

    def test_a_review_at_a_sha_not_in_the_pr_does_not_count(self):
        gh = FakeGitHub()
        gh.files["9" * 40] = FILES_A  # same change, but not this PR's commit
        gh.add_pr(comments=[verdict("Fable 5.2", "9" * 40, "SHIP")])
        self.assertIsNone(self.run_gate(gh).conclusion)

    def test_a_merge_of_main_with_an_identical_change_keeps_the_review(self):
        gh = FakeGitHub()
        gh.files[OLD] = FILES_A
        gh.files[MERGED] = FILES_A  # main merged in, the PR's change untouched
        gh.add_pr(head=MERGED, commits=[commit(OLD), commit(MERGED, "Merge branch 'main'", parents=2)],
                  comments=[verdict("Fable 5.2", OLD, "SHIP")])
        self.assertEqual(self.run_gate(gh).conclusion, "success")

    def test_an_unknown_change_fingerprint_never_carries(self):
        gh = FakeGitHub()
        gh.files[OLD] = None  # compare truncated or failed
        gh.files[MERGED] = FILES_A
        gh.add_pr(head=MERGED, commits=[commit(OLD), commit(MERGED)],
                  comments=[verdict("Fable 5.2", OLD, "SHIP")])
        self.assertIsNone(self.run_gate(gh).conclusion)

    def test_a_self_review_does_not_pass(self):
        gh = FakeGitHub()
        gh.add_pr(comments=[verdict("Claude Opus 5.5", HEAD, "SHIP")])
        d = self.run_gate(gh)
        self.assertEqual(d.conclusion, "failure")
        self.assertIn("same model", d.title)
        self.assertNotIn(("auto_merge", 1, True), gh.writes)

    def test_a_reviewer_whose_model_matches_the_builders_does_not_pass(self):
        # Spelled differently from the trailer, the same model all the same.
        for spelled in ("claude-opus-5-5", "Opus 5.5", "OPUS-5.5"):
            gh = FakeGitHub()
            gh.add_pr(comments=[verdict(spelled, HEAD, "SHIP")])
            self.assertEqual(self.run_gate(gh).conclusion, "failure", spelled)

    def test_a_trailer_without_a_version_matches_every_version(self):
        # "Co-Authored-By: Claude Sonnet" is on real commits; a Sonnet 5.5 review is no
        # more independent of it than a Sonnet review would be.
        gh = FakeGitHub()
        gh.add_pr(commits=[commit(HEAD, "a\n\nCo-Authored-By: Claude Sonnet <noreply@anthropic.com>")],
                  comments=[verdict("Sonnet 5.5", HEAD, "SHIP")])
        self.assertEqual(self.run_gate(gh).conclusion, "failure")
        self.assertTrue(ar.same_model("opus", "opus-5-5"))
        self.assertFalse(ar.same_model("opus-5-5", "opus-5-4"))
        self.assertFalse(ar.same_model("opus-5", "fable-5"))

    def test_any_builder_model_counts_as_the_builder(self):
        gh = FakeGitHub()
        gh.add_pr(commits=[commit(OLD, "a\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>"),
                           commit(HEAD)],
                  comments=[verdict("Fable 5.2", HEAD, "SHIP")])
        self.assertEqual(self.run_gate(gh).conclusion, "failure")

    def test_no_builder_trailer_on_an_agent_pr_does_not_pass(self):
        # Stripping the trailer must not turn a self-review into an independent one.
        gh = FakeGitHub()
        gh.add_pr(commits=[commit(HEAD, "feat: no trailer")],
                  comments=[verdict("Fable 5.2", HEAD, "SHIP")])
        d = self.run_gate(gh)
        self.assertEqual(d.conclusion, "failure")
        self.assertIn("builder", d.title)

    def test_a_dependabot_pr_needs_no_builder_trailer(self):
        gh = FakeGitHub()
        gh.add_pr(author="dependabot[bot]",
                  commits=[commit(HEAD, "build(deps): bump x", author="dependabot[bot]",
                                  verified=True)],
                  comments=[verdict("Opus 5.5", HEAD, "SHIP")])
        self.assertEqual(self.run_gate(gh).conclusion, "success")

    def test_an_unsigned_dependabot_commit_needs_a_builder_trailer(self):
        # The author login follows the commit's email, which anyone can set.
        gh = FakeGitHub()
        gh.add_pr(author="dependabot[bot]",
                  commits=[commit(HEAD, "build(deps): bump x", author="dependabot[bot]")],
                  comments=[verdict("Opus 5.5", HEAD, "SHIP")])
        d = self.run_gate(gh)
        self.assertEqual(d.conclusion, "failure")
        self.assertIn("builder", d.title)

    def test_block_after_ship_fails_sticks_and_disarms(self):
        gh = FakeGitHub()
        gh.add_pr(comments=[verdict("Fable 5.2", HEAD, "SHIP", cid=1)])
        self.assertEqual(self.run_gate(gh).conclusion, "success")
        gh.comments[1].append(verdict("claude-fable-5-2", HEAD, "BLOCK", cid=2,
                                      created="2026-11-25T11:00:00Z"))
        d = self.run_gate(gh)
        self.assertEqual(d.conclusion, "failure")
        self.assertTrue(d.sticky)
        self.assertIn(("auto_merge", 1, False), gh.writes)
        self.assertEqual(our_run(gh, HEAD)["external_id"], ar.STICKY)

    def test_a_ship_after_block_at_the_same_head_does_not_pass(self):
        gh = FakeGitHub()
        gh.add_pr(comments=[verdict("Fable 5.2", HEAD, "BLOCK", cid=1),
                            verdict("Fable 5.2", HEAD, "SHIP", cid=2,
                                    created="2026-11-25T11:00:00Z")])
        self.assertEqual(self.run_gate(gh).conclusion, "failure")

    def test_deleting_the_block_does_not_restore_the_ship(self):
        gh = FakeGitHub()
        block = verdict("Fable 5.2", HEAD, "BLOCK", cid=2)
        gh.add_pr(comments=[verdict("Fable 5.2", HEAD, "SHIP", cid=1), block])
        self.run_gate(gh)
        gh.comments[1] = [c for c in gh.comments[1] if c["id"] != 2]
        d = self.run_gate(gh, event={"action": "deleted", "comment": block})
        self.assertEqual(d.conclusion, "failure")
        # and a later run, without the event, still holds
        self.assertEqual(self.run_gate(gh).conclusion, "failure")

    def test_a_block_deleted_before_any_run_saw_it_still_sticks(self):
        gh = FakeGitHub()
        block = verdict("Fable 5.2", HEAD, "BLOCK", cid=2)
        gh.add_pr(comments=[verdict("Fable 5.2", HEAD, "SHIP", cid=1)])
        d = self.run_gate(gh, event={"action": "deleted", "comment": block})
        self.assertEqual(d.conclusion, "failure")
        self.assertEqual(self.run_gate(gh).conclusion, "failure")

    def test_a_block_carries_through_a_merge_of_main(self):
        gh = FakeGitHub()
        gh.files[OLD] = FILES_A
        gh.files[MERGED] = FILES_A
        gh.add_pr(head=OLD, commits=[commit(OLD)],
                  comments=[verdict("Fable 5.2", OLD, "SHIP", cid=1),
                            verdict("Fable 5.2", OLD, "BLOCK", cid=2)])
        self.run_gate(gh)
        gh.comments[1] = gh.comments[1][:1]  # the BLOCK is deleted
        gh.prs[1]["head"]["sha"] = MERGED
        gh.commits[1] = [commit(OLD), commit(MERGED, "Merge branch 'main'", parents=2)]
        self.assertEqual(self.run_gate(gh).conclusion, "failure")

    def test_a_new_push_after_ship_needs_a_new_review(self):
        gh = FakeGitHub()
        gh.files[OLD] = FILES_A
        gh.add_pr(head=OLD, commits=[commit(OLD)], comments=[verdict("Fable 5.2", OLD, "SHIP")])
        self.assertEqual(self.run_gate(gh).conclusion, "success")
        gh.prs[1]["head"]["sha"] = HEAD
        gh.commits[1].append(commit(HEAD))
        gh.files[HEAD] = FILES_B
        d = self.run_gate(gh)
        self.assertIsNone(d.conclusion)
        self.assertEqual(our_run(gh, HEAD)["status"], "in_progress")
        self.assertIn(("auto_merge", 1, False), gh.writes)

    def test_an_edited_verdict_comment_fails_and_sticks(self):
        gh = FakeGitHub()
        gh.add_pr(comments=[verdict("Fable 5.2", HEAD, "SHIP", updated="2026-11-25T10:05:00Z")])
        d = self.run_gate(gh)
        self.assertEqual(d.conclusion, "failure")
        self.assertTrue(d.sticky)
        self.assertIn("edited", d.title)

    def test_an_edit_that_turns_a_block_into_something_else_sticks(self):
        # The edit event carries the old body; the comment now reads harmless.
        gh = FakeGitHub()
        was = verdict("Fable 5.2", HEAD, "BLOCK", cid=2)
        now = {**was, "body": "never mind", "updated_at": "2026-11-25T10:05:00Z"}
        gh.add_pr(comments=[verdict("Fable 5.2", HEAD, "SHIP", cid=1), now])
        d = self.run_gate(gh, event={"action": "edited", "comment": now,
                                     "changes": {"body": {"from": was["body"]}}})
        self.assertEqual(d.conclusion, "failure")
        self.assertEqual(self.run_gate(gh).conclusion, "failure")

    def test_an_edited_review_of_an_old_head_does_not_poison_the_new_one(self):
        gh = FakeGitHub()
        gh.files[OLD] = FILES_A
        gh.files[HEAD] = FILES_B
        gh.add_pr(commits=[commit(OLD), commit(HEAD)], comments=[
            verdict("Fable 5.2", OLD, "BLOCK", cid=1, updated="2026-11-25T10:05:00Z"),
            verdict("Fable 5.2", HEAD, "SHIP", cid=2)])
        self.assertEqual(self.run_gate(gh).conclusion, "success")

    def test_a_sticky_run_is_never_overwritten(self):
        gh = FakeGitHub()
        gh.add_pr(comments=[verdict("Fable 5.2", HEAD, "SHIP")])
        gh.runs[HEAD] = [{"id": 5, "name": ar.CHECK_NAME, "head_sha": HEAD, "app": {"id": APP_ID},
                          "status": "completed", "conclusion": "failure",
                          "external_id": ar.STICKY}]
        self.assertEqual(self.run_gate(gh).conclusion, "failure")
        self.assertEqual(gh.runs[HEAD][0]["conclusion"], "failure")

    def test_a_sticky_run_that_lands_mid_run_is_not_overwritten(self):
        # Another run posts the BLOCK between this run's read and its write.
        gh = FakeGitHub()
        gh.add_pr(comments=[verdict("Fable 5.2", HEAD, "SHIP")])
        sticky = {"id": 5, "name": ar.CHECK_NAME, "head_sha": HEAD, "app": {"id": APP_ID},
                  "status": "completed", "conclusion": "failure", "external_id": ar.STICKY}
        reads = []

        def check_runs(sha):
            reads.append(sha)
            return [sticky] if len(reads) > 1 else []

        gh.check_runs = check_runs
        gate(gh).evaluate(1)
        self.assertFalse([w for w in gh.writes if w[0] in ("create_check", "update_check")])
        self.assertEqual(sticky["conclusion"], "failure")
        self.assertNotIn(("auto_merge", 1, True), gh.writes)

    def test_a_run_by_another_app_is_ignored(self):
        # A forged check run of the same name (a workflow on the PR branch, as
        # github-actions) is neither trusted nor sticky; ours is created beside it.
        gh = FakeGitHub()
        gh.add_pr(comments=[verdict("Fable 5.2", HEAD, "BLOCK")])
        gh.runs[HEAD] = [{"id": 5, "name": ar.CHECK_NAME, "head_sha": HEAD, "app": {"id": 15368},
                          "status": "completed", "conclusion": "success", "external_id": ""}]
        self.run_gate(gh)
        self.assertEqual(gh.runs[HEAD][0]["conclusion"], "success")  # untouched
        self.assertEqual(our_run(gh, HEAD)["app"]["id"], APP_ID)
        self.assertEqual(our_run(gh, HEAD)["conclusion"], "failure")

    def test_a_change_to_github_dir_passes_review_but_never_arms(self):
        gh = FakeGitHub()
        gh.add_pr(files=[{"filename": ".github/workflows/agent-review.yml", "status": "modified",
                          "sha": "d" * 40}],
                  comments=[verdict("Fable 5.2", HEAD, "SHIP")])
        d = self.run_gate(gh)
        self.assertEqual(d.conclusion, "success")
        self.assertFalse(d.arm)
        self.assertNotIn(("auto_merge", 1, True), gh.writes)

    def test_a_rename_out_of_github_dir_never_arms(self):
        gh = FakeGitHub()
        gh.add_pr(files=[{"filename": "x.yml", "previous_filename": ".github/workflows/ci.yml",
                          "status": "renamed", "sha": "d" * 40}],
                  comments=[verdict("Fable 5.2", HEAD, "SHIP")])
        self.assertFalse(self.run_gate(gh).arm)

    def test_an_unknown_file_list_never_arms(self):
        gh = FakeGitHub()
        gh.add_pr(comments=[verdict("Fable 5.2", HEAD, "SHIP")])
        gh.files[HEAD] = None
        self.assertFalse(self.run_gate(gh).arm)

    def test_a_draft_never_arms(self):
        gh = FakeGitHub()
        gh.add_pr(draft=True, comments=[verdict("Fable 5.2", HEAD, "SHIP")])
        self.assertFalse(self.run_gate(gh).arm)


    # -- rework after review (TheHub #62342) --------------------------------------

    def test_a_hand_merge_that_undoes_mains_change_does_not_carry(self):
        # Fable's scratch repository: the PR edits a file, main fixes the same
        # file, and main is merged in with the conflict resolved "ours". The
        # PR's resulting blob is unchanged, so only the base side shows it.
        gh = FakeGitHub()
        gh.files[OLD] = FILES_A
        gh.files[MERGED] = FILES_A
        gh.bases[OLD], gh.bases[MERGED] = "base1", "base2"
        gh.drift[("base1", "base2")] = [{"filename": "lib/check.sh", "status": "modified",
                                         "sha": "f" * 40}]
        gh.add_pr(head=MERGED, commits=[commit(OLD), commit(MERGED, "Merge branch 'main'", parents=2)],
                  comments=[verdict("Fable 5.2", OLD, "SHIP")])
        self.assertIsNone(self.run_gate(gh).conclusion)

    def test_a_merge_of_main_that_touched_other_files_carries(self):
        gh = FakeGitHub()
        gh.files[OLD] = FILES_A
        gh.files[MERGED] = FILES_A
        gh.bases[OLD], gh.bases[MERGED] = "base1", "base2"
        gh.drift[("base1", "base2")] = [{"filename": "docs/x.md", "status": "modified",
                                         "sha": "f" * 40}]
        gh.add_pr(head=MERGED, commits=[commit(OLD), commit(MERGED, "Merge branch 'main'", parents=2)],
                  comments=[verdict("Fable 5.2", OLD, "SHIP")])
        self.assertEqual(self.run_gate(gh).conclusion, "success")

    def test_an_unknown_base_drift_does_not_carry(self):
        for drift in (None, [{"filename": f"f{i}", "status": "added", "sha": "f" * 40}
                             for i in range(300)]):
            gh = FakeGitHub()
            gh.files[OLD] = FILES_A
            gh.files[MERGED] = FILES_A
            gh.bases[OLD], gh.bases[MERGED] = "base1", "base2"
            gh.drift[("base1", "base2")] = drift
            gh.add_pr(head=MERGED, commits=[commit(OLD), commit(MERGED, "m", parents=2)],
                      comments=[verdict("Fable 5.2", OLD, "SHIP")])
            self.assertIsNone(self.run_gate(gh).conclusion)

    def test_a_mode_change_does_not_carry(self):
        gh = FakeGitHub()
        gh.files[OLD] = FILES_A
        gh.files[MERGED] = FILES_A
        gh.modes[OLD] = {"lib/check.sh": "100644"}
        gh.modes[MERGED] = {"lib/check.sh": "100755"}
        gh.add_pr(head=MERGED, commits=[commit(OLD), commit(MERGED)],
                  comments=[verdict("Fable 5.2", OLD, "SHIP")])
        self.assertIsNone(self.run_gate(gh).conclusion)

    def test_an_unknown_tree_does_not_carry(self):
        gh = FakeGitHub()
        gh.files[OLD] = FILES_A
        gh.files[MERGED] = FILES_A
        gh.modes[OLD] = gh.modes[MERGED] = None  # e.g. both trees truncated
        gh.add_pr(head=MERGED, commits=[commit(OLD), commit(MERGED)],
                  comments=[verdict("Fable 5.2", OLD, "SHIP")])
        self.assertIsNone(self.run_gate(gh).conclusion)

    def test_a_malformed_block_fails_a_ship(self):
        for line in (f"**Independent review (Fable 5.2) at {HEAD[:12]}: BLOCK**",
                     f"**Independent review (Fable 5.2) at {HEAD[:8]}: BLOCK** ",
                     f"\ufeff**Independent review (Fable 5.2) at {HEAD[:8]}: BLOCK**",
                     f"\n## Independent review (Fable 5.2) at {HEAD[:8]}: BLOCK",
                     "**Independent review (Fable 5.2): BLOCK**"):
            gh = FakeGitHub()
            block = {**verdict("Fable 5.2", HEAD, "SHIP", cid=2), "body": line + "\n\nWhy."}
            gh.add_pr(comments=[verdict("Fable 5.2", HEAD, "SHIP", cid=1), block])
            d = self.run_gate(gh)
            self.assertEqual(d.conclusion, "failure", repr(line))
            self.assertIn("malformed", d.title)
            self.assertNotIn(("auto_merge", 1, True), gh.writes)

    def test_a_malformed_block_of_an_old_change_does_not_poison_the_head(self):
        gh = FakeGitHub()
        gh.files[OLD] = FILES_A
        gh.files[HEAD] = FILES_B
        block = {**verdict("Fable 5.2", OLD, "SHIP", cid=1),
                 "body": f"**Independent review (Fable 5.2) at {OLD[:12]}: BLOCK**"}
        gh.add_pr(commits=[commit(OLD), commit(HEAD)],
                  comments=[block, verdict("Fable 5.2", HEAD, "SHIP", cid=2)])
        self.assertEqual(self.run_gate(gh).conclusion, "success")

    def test_a_malformed_block_from_an_outsider_is_ignored(self):
        gh = FakeGitHub()
        block = {**verdict("Fable 5.2", HEAD, "SHIP", cid=2, assoc="NONE"),
                 "body": f"**Independent review (X) at {HEAD[:12]}: BLOCK**"}
        gh.add_pr(comments=[verdict("Fable 5.2", HEAD, "SHIP", cid=1), block])
        self.assertEqual(self.run_gate(gh).conclusion, "success")

    def test_a_block_in_a_pr_review_body_fails_the_head(self):
        for body in (f"**Independent review (Fable 5.2) at {HEAD[:8]}: BLOCK**\n\nWhy.",
                     f"**Independent review (Fable 5.2) at {HEAD[:12]}: BLOCK**"):
            gh = FakeGitHub()
            gh.add_pr(comments=[verdict("Fable 5.2", HEAD, "SHIP")])
            gh.reviews[1] = [{"id": 9, "body": body, "author_association": "OWNER",
                              "html_url": "https://example.invalid/r/9", "state": "COMMENTED"}]
            self.assertEqual(self.run_gate(gh).conclusion, "failure", body)

    def test_a_ship_in_a_pr_review_body_does_not_count(self):
        # A review body's edits leave no trace in the API, so it can only block.
        gh = FakeGitHub()
        gh.add_pr()
        gh.reviews[1] = [{"id": 9, "body": verdict("Fable 5.2", HEAD, "SHIP")["body"],
                          "author_association": "OWNER", "state": "COMMENTED"}]
        self.assertIsNone(self.run_gate(gh).conclusion)

    def test_an_unattributed_commit_does_not_ride_on_an_attributed_one(self):
        gh = FakeGitHub()
        gh.add_pr(commits=[commit(OLD), commit(HEAD, "fix: no trailer")],
                  comments=[verdict("Fable 5.2", HEAD, "SHIP")])
        d = self.run_gate(gh)
        self.assertEqual(d.conclusion, "failure")
        self.assertIn(HEAD[:8], d.title)

    def test_a_bare_claude_trailer_cannot_be_reviewed_by_any_claude(self):
        gh = FakeGitHub()
        gh.add_pr(commits=[commit(OLD), commit(HEAD, "x\n\nCo-Authored-By: Claude <noreply@anthropic.com>")],
                  comments=[verdict("Fable 5.2", HEAD, "SHIP")])
        self.assertEqual(self.run_gate(gh).conclusion, "failure")

    def test_a_dependabot_pr_with_a_pushed_unattributed_commit_does_not_pass(self):
        gh = FakeGitHub()
        gh.add_pr(author="dependabot[bot]",
                  commits=[commit(OLD, "build(deps): bump x", author="dependabot[bot]",
                                  verified=True),
                           commit(HEAD, "fix: tweak", author="owner")],
                  comments=[verdict("Opus 5.5", HEAD, "SHIP")])
        self.assertEqual(self.run_gate(gh).conclusion, "failure")

    def test_a_failing_outcome_disarms_before_the_check_is_written(self):
        gh = FakeGitHub()
        gh.add_pr(auto_merge={"merge_method": "squash"},
                  comments=[verdict("Fable 5.2", HEAD, "BLOCK")])
        self.run_gate(gh)
        kinds = [w[0] for w in gh.writes]
        self.assertLess(kinds.index("auto_merge"), kinds.index("create_check"))

    def test_a_failed_check_write_still_leaves_the_pr_disarmed(self):
        gh = FakeGitHub()
        gh.add_pr(auto_merge={"merge_method": "squash"},
                  comments=[verdict("Fable 5.2", HEAD, "BLOCK")])

        def boom(sha, fields):
            raise RuntimeError("API down")

        gh.create_check = boom
        with self.assertRaises(RuntimeError):
            self.run_gate(gh)
        self.assertIsNone(gh.prs[1]["auto_merge"])

    def test_control_paths_never_arm(self):
        for path in (".claude/hooks/guard-bash.sh", ".sdlc/protection.yaml", "platform/MANIFEST.yml",
                     "ci/pipeline.yml", "test/manifest.txt", "hooks/pre-commit",
                     "skills/x/hooks/guard.sh", ".github/CODEOWNERS"):
            gh = FakeGitHub()
            gh.add_pr(files=[{"filename": path, "status": "modified", "sha": "d" * 40}],
                      comments=[verdict("Fable 5.2", HEAD, "SHIP")])
            d = self.run_gate(gh)
            self.assertEqual(d.conclusion, "success", path)
            self.assertFalse(d.arm, path)

    def test_every_arm_is_announced_once(self):
        gh = FakeGitHub()
        gh.add_pr(comments=[verdict("Fable 5.2", HEAD, "SHIP")])
        self.run_gate(gh)
        self.run_gate(gh)
        notes = [w for w in gh.writes if w[0] == "comment"]
        self.assertEqual(len(notes), 1)
        self.assertIn("armed auto-merge", notes[0][2])
        self.assertFalse(ar.loose_block(notes[0][3]))
        self.assertIsNone(ar.parse_verdict(notes[0][3]))
        # A BLOCK in a PR review body is read late; the comment is read at once.
        self.assertIn("post a BLOCK verdict as a comment", notes[0][3])

    def test_a_refused_arm_posts_nothing_and_does_not_loop(self):
        gh = FakeGitHub()
        gh.add_pr(comments=[verdict("Fable 5.2", HEAD, "SHIP")])
        gh.arm_result = False
        for _ in range(3):
            d = self.run_gate(gh)
            self.assertEqual(d.conclusion, "success")
        self.assertFalse([w for w in gh.writes if w[0] == "comment"])
        self.assertIsNone(gh.prs[1]["auto_merge"])
        # GitHub allows it again: the next run arms and announces, once.
        gh.arm_result = True
        self.run_gate(gh)
        self.run_gate(gh)
        self.assertEqual(len([w for w in gh.writes if w[0] == "comment"]), 1)

    def test_a_head_a_person_disarmed_is_never_rearmed(self):
        gh = FakeGitHub()
        gh.add_pr(comments=[verdict("Fable 5.2", HEAD, "SHIP")])
        self.run_gate(gh)
        self.assertIsNotNone(gh.prs[1]["auto_merge"])
        gh.prs[1]["auto_merge"] = None  # a person disables auto-merge: a veto
        before = len(gh.writes)
        for _ in range(2):
            d = self.run_gate(gh)
        self.assertEqual(d.conclusion, "success")
        self.assertFalse(d.arm)
        self.assertIn("disarmed", d.summary)
        self.assertNotIn(("auto_merge", 1, True), gh.writes[before:])
        self.assertFalse([w for w in gh.writes[before:] if w[0] == "comment"])
        self.assertIsNone(gh.prs[1]["auto_merge"])

    def test_a_disarmed_head_does_not_veto_the_next_head(self):
        gh = FakeGitHub()
        gh.add_pr(comments=[verdict("Fable 5.2", OLD, "SHIP")],
                  commits=[commit(OLD)], head=OLD)
        self.run_gate(gh)
        gh.prs[1]["auto_merge"] = None
        gh.prs[1]["head"]["sha"] = HEAD
        gh.commits[1].append(commit(HEAD))
        gh.files[HEAD] = FILES_B
        gh.comments[1].append(verdict("Fable 5.2", HEAD, "SHIP", cid=2))
        before = len(gh.writes)
        self.assertTrue(self.run_gate(gh).arm)
        self.assertIn(("auto_merge", 1, True), gh.writes[before:])

    def test_an_announcement_not_posted_by_the_app_is_not_a_veto(self):
        gh = FakeGitHub()
        fake = {"id": 9, "body": f"agent-review armed auto-merge at {HEAD[:8]}: x\n\n"
                f"<!-- agent-review-armed {HEAD} -->", "author_association": "OWNER",
                "created_at": T0, "updated_at": T0, "user": {"login": "someone", "type": "User"}}
        gh.add_pr(comments=[verdict("Fable 5.2", HEAD, "SHIP"), fake])
        self.run_gate(gh)
        self.assertIn(("auto_merge", 1, True), gh.writes)

    def test_with_arming_off_the_gate_only_judges(self):
        gh = FakeGitHub()
        gh.add_pr(comments=[verdict("Fable 5.2", HEAD, "SHIP")], mergeable_state="behind")
        d = gate(gh, arming=False).evaluate(1)
        self.assertEqual(d.conclusion, "success")
        self.assertEqual(our_run(gh, HEAD)["conclusion"], "success")
        gate(gh, arming=False).sweep()
        self.assertLessEqual({w[0] for w in gh.writes}, {"create_check", "update_check"})
        self.assertNotIn(("auto_merge", 1, True), gh.writes)
        self.assertFalse([w for w in gh.writes if w[0] in ("comment", "update_branch")])

    def test_arming_is_off_unless_the_variable_says_on(self):
        self.assertFalse(ar.Gate(FakeGitHub(), REPO, APP_ID).arming)
        for value, on in ((None, False), ("", False), ("off", False), ("ON ", False),
                          ("true", False), ("on", True)):
            env = {} if value is None else {"AGENT_REVIEW_ARM": value}
            self.assertEqual(ar.arming_enabled(env), on, repr(value))

class Train(unittest.TestCase):
    """One BEHIND PR is brought up to date at a time, and only when none is in flight."""

    def two_reviewed(self, gh, states):
        for n, state in zip((1, 2), states):
            head = f"{n}" * 8 + "f" * 32
            gh.files[head] = FILES_A
            gh.add_pr(n, head=head, comments=[verdict("Fable 5.2", head, "SHIP", cid=n)],
                      mergeable_state=state, created_at=f"2026-11-2{n}T00:00:00Z")

    def test_the_oldest_behind_pr_is_updated_when_nothing_is_in_flight(self):
        gh = FakeGitHub()
        self.two_reviewed(gh, ("behind", "behind"))
        gate(gh).sweep()
        updates = [w for w in gh.writes if w[0] == "update_branch"]
        self.assertEqual(updates, [("update_branch", 1, "1" * 8 + "f" * 32)])

    def test_nothing_is_updated_while_one_is_in_flight(self):
        gh = FakeGitHub()
        self.two_reviewed(gh, ("behind", "blocked"))
        gate(gh).sweep()
        self.assertFalse([w for w in gh.writes if w[0] == "update_branch"])

    def test_a_red_pr_does_not_hold_the_train(self):
        gh = FakeGitHub()
        self.two_reviewed(gh, ("behind", "blocked"))
        head2 = "2" * 8 + "f" * 32
        gh.runs[head2] = [{"id": 9, "name": "Concourse / keel", "head_sha": head2,
                           "app": {"id": 1}, "status": "completed", "conclusion": "failure"}]
        gate(gh).sweep()
        self.assertIn(("update_branch", 1, "1" * 8 + "f" * 32), gh.writes)

    def test_the_train_does_not_run_with_arming_off(self):
        gh = FakeGitHub()
        self.two_reviewed(gh, ("behind", "behind"))
        gate(gh, arming=False).sweep()
        self.assertFalse([w for w in gh.writes if w[0] == "update_branch"])

    def test_an_unreviewed_behind_pr_is_left_alone(self):
        gh = FakeGitHub()
        gh.add_pr(1, mergeable_state="behind")
        gate(gh).sweep()
        self.assertFalse([w for w in gh.writes if w[0] == "update_branch"])


class Events(unittest.TestCase):
    """Which runs judge what (main)."""

    def comment_event(self, action="created", **user):
        return {"action": action, "issue": {"number": 4, "pull_request": {}},
                "comment": {"id": 1, "body": "x", "user": user or {"login": "someone",
                                                                    "type": "User"}}}

    def test_a_persons_comment_judges_its_pr_then_sweeps(self):
        self.assertEqual(ar.plan("issue_comment", self.comment_event(), APP_ID), (4, True))

    def test_the_apps_own_comment_starts_nothing(self):
        for user, app in (({"login": "agent-review[bot]", "type": "Bot"}, {"id": APP_ID}),
                          ({"login": "agent-review[bot]", "type": "Bot"}, None)):
            event = self.comment_event(**user)
            if app:
                event["comment"]["performed_via_github_app"] = app
            self.assertEqual(ar.plan("issue_comment", event, APP_ID), (None, False))

    def test_an_edit_or_deletion_judges_its_own_pr_only(self):
        for action in ("edited", "deleted"):
            self.assertEqual(ar.plan("issue_comment", self.comment_event(action), APP_ID),
                             (4, False))

    def test_an_issue_comment_off_a_pr_only_sweeps(self):
        event = {"action": "created", "issue": {"number": 4},
                 "comment": {"user": {"login": "someone", "type": "User"}}}
        self.assertEqual(ar.plan("issue_comment", event, APP_ID), (None, True))

    def test_other_events_sweep(self):
        for name in ("push", "schedule", "workflow_dispatch"):
            self.assertEqual(ar.plan(name, {}, APP_ID), (None, True))


class WorkflowShape(unittest.TestCase):
    """The workflow properties the trust argument rests on (agent_review.py docstring)."""

    text = (Path(__file__).resolve().parent.parent / "workflows" / "agent-review.yml").read_text()

    def test_the_token_gets_nothing_by_default(self):
        self.assertRegex(self.text, r"(?m)^permissions: \{\}$")

    def test_no_job_is_named_like_the_check(self):
        self.assertNotRegex(self.text, r"(?m)^  agent-review:")
        self.assertNotRegex(self.text, r"(?m)^\s+name:\s*agent-review\s*$")

    def test_the_gate_runs_in_the_main_only_environment_from_the_default_branch(self):
        gate_job = self.text.split("\n  gate:\n", 1)[1].split("\n  tests:\n", 1)[0]
        self.assertIn("environment: agent-review", gate_job)
        self.assertIn("ref: ${{ github.event.repository.default_branch }}", gate_job)
        self.assertIn("persist-credentials: false", gate_job)
        self.assertIn("github.event_name != 'pull_request'", gate_job)
        self.assertNotIn("github.event.pull_request.head", self.text)

    def test_the_tests_job_holds_no_secret(self):
        tests_job = self.text.split("\n  tests:\n", 1)[1]
        self.assertNotIn("secrets.", tests_job)
        self.assertNotIn("environment:", tests_job)

    def test_no_trigger_runs_with_a_pr_heads_context(self):
        self.assertNotIn("pull_request_target", self.text)
        self.assertNotIn("workflow_run", self.text)

    def test_the_schedule_runs_only_where_the_operator_turned_it_on(self):
        # A private repository pays for runner minutes: the schedule is opt-in.
        self.assertIn("vars.AGENT_REVIEW_SCHEDULE == 'on'", self.text)

    def test_an_edit_or_deletion_is_never_displaced_by_a_later_event(self):
        # Its own concurrency group per comment: a pending run that is replaced
        # loses the payload, and an edit or deletion's payload is the evidence.
        self.assertIn("format('agent-review-tamper-{0}', github.event.comment.id)", self.text)

    def test_a_bot_comment_never_starts_the_gate(self):
        # The App's own announcement would otherwise re-run the gate.
        self.assertIn("github.event.comment.user.type != 'Bot'", self.text)

    def test_arming_follows_the_operators_variable(self):
        self.assertIn("AGENT_REVIEW_ARM: ${{ vars.AGENT_REVIEW_ARM }}", self.text)

    def test_runs_never_interleave(self):
        self.assertIn("cancel-in-progress: false", self.text)


if __name__ == "__main__":
    unittest.main(verbosity=1)
