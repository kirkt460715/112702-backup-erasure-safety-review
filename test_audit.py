"""审计引擎测试：固定合成资料的核心结论 + 临时资料的边界/变体场景。"""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import audit
import records_view

RECORDS = Path(__file__).with_name("records")


def write_records(directory: Path, data: dict) -> Path:
    for name, rows in data.items():
        (directory / f"{name}.json").write_text(
            json.dumps(rows, ensure_ascii=False), encoding="utf-8")
    return directory


def temp_report(data: dict, as_of=None):
    with tempfile.TemporaryDirectory() as tmp:
        path = write_records(Path(tmp), data)
        return audit.audit(path, as_of=as_of)


def find_copies(report, **criteria):
    result = []
    for copy in report["copies"]:
        if all(copy.get(key) == value for key, value in criteria.items()):
            result.append(copy)
    return result


def one_copy(report, **criteria):
    matches = find_copies(report, **criteria)
    assert len(matches) == 1, f"期望恰好一个副本 {criteria}，实际 {len(matches)}: {matches}"
    return matches[0]


class ShippedFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = audit.audit(RECORDS)

    def test_report_is_json_serializable(self):
        json.dumps(self.report, ensure_ascii=False)

    def test_as_of_day_derived_from_observation_records(self):
        self.assertEqual(self.report["as_of_day"], 10)
        self.assertEqual(self.report["summary"]["inferred_event_day"], 10)

    def test_ledger_dispositions(self):
        by_item = {i["item"]: i for i in self.report["items"]}
        self.assertEqual(by_item["att-7"]["retention"]["disposition"], "expired")
        self.assertTrue(by_item["att-7"]["retention"]["expired"])
        self.assertEqual(by_item["lease-7"]["retention"]["disposition"], "on_hold")
        self.assertTrue(by_item["lease-7"]["retention"]["on_hold"])
        self.assertEqual(by_item["lease-7"]["hold_until"], 37)

    def test_primary_attachment_cleaned_and_confirmed(self):
        primary = one_copy(self.report, kind="primary", item="att-7")
        self.assertEqual(primary["status"], "cleaned_verified")
        self.assertIn("clean-1", primary["evidence"]["erasure_proof_ids"])

    def test_old_proof_does_not_cover_derived_index(self):
        # child-2 中的派生索引 index-a -> att-7：clean-1 范围是 primary，不匹配。
        idx = one_copy(self.report, kind="derived_index", scope="index-a", snapshot="child-2")
        self.assertEqual(idx["status"], "expired_residual_copy")
        self.assertEqual(idx["evidence"]["erasure_proof_ids"], [])
        # att-7 由父代 backup-1 直接携带，血缘提示该派生索引仍可重现到期附件。
        child = next(g for g in self.report["snapshot_generations"] if g["id"] == "child-2")
        self.assertTrue(any("index-a" in note and "backup-1" in note
                            for note in child["lineage_notes"]))

    def test_snapshot_generation_still_lists_expired_identity(self):
        residual = one_copy(self.report, kind="snapshot_record", item="att-7", snapshot="backup-1")
        self.assertEqual(residual["status"], "expired_residual_copy")
        self.assertTrue(residual["restorable_reappearance_risk"])

    def test_rebuilt_index_is_pending_actual_reverification(self):
        rebuilt = one_copy(self.report, kind="restored_index", target="restored-2", scope="index-a")
        self.assertEqual(rebuilt["status"], "pending_reverification")
        self.assertEqual(rebuilt["evidence"]["review"]["state"], "pending")
        # 访问回执 not_approved 被归一为 blocked（缓解措施，而非清理结论）。
        self.assertEqual(rebuilt["evidence"]["access"]["state"], "blocked")

    def test_held_lease_verified_on_restore_target(self):
        lease = one_copy(self.report, kind="restored_record", target="restored-2", item="lease-7")
        self.assertEqual(lease["status"], "held_verified")
        self.assertTrue(lease["held"])

    def test_restore_decision_distinguishes_one_pending_copy_from_whole_generation(self):
        approvals = self.report["restore_approvals"]
        self.assertEqual(len(approvals), 1)
        decision = approvals[0]
        self.assertEqual(decision["target"], "restored-2")
        self.assertEqual(decision["from_snapshot"], "child-2")
        self.assertEqual(decision["decision"], "pending_verification")
        self.assertFalse(decision["approved"])
        self.assertFalse(decision["generation_passed"])
        self.assertFalse(decision["whole_generation_verified"])
        self.assertTrue(decision["partial"])
        self.assertEqual(decision["affected_copies"], ["index-a"])
        self.assertEqual(decision["affected_copy_count"], 1)
        self.assertEqual(decision["verified_copies"], ["lease-7"])
        self.assertFalse(self.report["summary"]["whole_generation_passed"])
        self.assertEqual(self.report["overall_decision"], "pending_verification")

    def test_no_derived_or_backup_copy_is_verified_clean(self):
        self.assertEqual(self.report["derived_index_cleaned_copies"], [])
        self.assertEqual(self.report["backup_cleaned_copies"], [])
        self.assertEqual(self.report["summary"]["derived_or_backup_cleaned_copies"], 0)
        self.assertEqual(self.report["summary"]["cleaned_verified_copies"], 1)

    def test_integrity_gap_and_pending_scope_retained(self):
        codes = {g["code"] for g in self.report["gaps"]}
        self.assertIn("no_integrity_material", codes)
        pending = {(p["target"], p["scope"]) for p in self.report["pending_scope"]}
        self.assertIn(("restored-2", "index-a"), pending)

    def test_defensive_checklist_covers_required_revalidations(self):
        codes = {c["code"] for c in self.report["defensive_checks"]}
        for required in (
            "reverify_erasure_on_rebuilt_copy",
            "verify_access_restriction_enforced",
            "reconcile_attached_snapshot_manifest",
            "rebuild_indexes_and_confirm_purge",
            "verify_held_records_intact_and_policy",
            "sweep_colocated_attachments",
            "close_pending_scope_with_new_receipt",
            "establish_integrity_evidence",
            "deletion_guard_for_hold",
        ):
            self.assertIn(required, codes)
        text = "\n".join(self.report["checklist"])
        self.assertIn("index-a", text)
        self.assertIn("restored-2", text)

    def test_deletion_guard_blocks_hold_allows_expired(self):
        guard = audit.evaluate_deletion(self.report, ["att-7", "lease-7"])
        self.assertEqual([b["item"] for b in guard["blocked_held"]], ["lease-7"])
        self.assertEqual(guard["allowed_after_scope_and_reverification"], ["att-7"])

    def test_records_view_forwards_audit_api(self):
        self.assertTrue(callable(records_view.build_report))
        self.assertTrue(callable(records_view.audit))


class EvidenceMatchingTests(unittest.TestCase):
    def test_target_bound_old_proof_without_new_review_is_not_enough(self):
        report = temp_report({
            "retention": [{"id": "e1", "item": "att", "category": "personal_attachment", "expires": 5}],
            "snapshots": [{"id": "s1", "derived": {"idx": "att"}}],
            "restores": [
                {"id": "clean-old", "item": "att", "scope": "idx", "target": "t1",
                 "proof": "confirmed", "action": "erasure", "day": 6},
                {"id": "op", "from": "s1", "target": "t1", "scope": ["idx"], "access": "not_approved"},
            ],
        }, as_of=10)
        rebuilt = one_copy(report, target="t1", scope="idx")
        self.assertEqual(rebuilt["status"], "reverification_missing")
        self.assertEqual(report["restore_approvals"][0]["decision"], "pending_verification")

    def test_fresh_independent_check_passes_rebuilt_derived_copy(self):
        report = temp_report({
            "retention": [{"id": "e1", "item": "att", "category": "personal_attachment", "expires": 5}],
            "snapshots": [{"id": "s1", "derived": {"idx": "att"}}],
            "restores": [
                {"id": "op", "from": "s1", "target": "t1", "scope": ["idx"], "access": "not_approved"},
                {"id": "rev", "target": "t1", "checked": ["idx"], "pending": []},
            ],
        }, as_of=10)
        rebuilt = one_copy(report, target="t1", scope="idx")
        self.assertEqual(rebuilt["status"], "cleaned_verified")
        approval = report["restore_approvals"][0]
        self.assertEqual(approval["decision"], "generation_verified")
        self.assertTrue(approval["whole_generation_verified"])

    def test_hidden_report_is_not_erasure(self):
        report = temp_report({
            "retention": [{"id": "e1", "item": "att", "expires": 5}],
            "snapshots": [],
            "restores": [
                {"id": "hide-1", "item": "att", "scope": "primary",
                 "proof": "confirmed", "action": "hidden", "day": 6},
            ],
        }, as_of=10)
        primary = one_copy(report, kind="primary", item="att")
        self.assertEqual(primary["status"], "hidden_not_erased")
        self.assertEqual(primary["evidence"]["hiding_proof_ids"], ["hide-1"])
        self.assertFalse(primary["cleaned"])

    def test_accessible_expired_copy_blocks_approval(self):
        report = temp_report({
            "retention": [{"id": "e1", "item": "att", "expires": 5}],
            "snapshots": [{"id": "s1", "contains": ["att"]}],
            "restores": [
                {"id": "op", "from": "s1", "target": "t1", "access": "approved"},
            ],
        }, as_of=10)
        copy = one_copy(report, target="t1", item="att")
        self.assertEqual(copy["status"], "expired_accessible")
        approval = report["restore_approvals"][0]
        self.assertEqual(approval["decision"], "blocked_reappearance")
        self.assertTrue(approval["blocked"])

    def test_whole_generation_with_expired_and_held_records_passes_once_all_checked(self):
        report = temp_report({
            "retention": [
                {"id": "e1", "item": "att", "expires": 5},
                {"id": "k1", "item": "lease", "hold_until": 99},
            ],
            "snapshots": [{"id": "s1", "contains": ["att", "lease"], "derived": {"idx": "att"}}],
            "restores": [
                {"id": "op", "from": "s1", "target": "t1", "access": "not_approved"},
                {"id": "rev", "target": "t1", "checked": ["att", "lease", "idx"]},
            ],
        }, as_of=10)
        approval = report["restore_approvals"][0]
        self.assertEqual(approval["decision"], "generation_verified")
        self.assertEqual(approval["copies_total"], 3)

    def test_partition_scoped_proof_matches_partition_copy(self):
        report = temp_report({
            "retention": [{"id": "e1", "item": "att", "expires": 5}],
            "snapshots": [{"id": "s1", "contains": [{"id": "att", "partition": "p1"}]}],
            "restores": [
                {"id": "clean-p", "item": "att", "scope": "p1",
                 "proof": "confirmed", "action": "clean", "day": 6},
            ],
        }, as_of=10)
        copy = one_copy(report, kind="snapshot_record", snapshot="s1", item="att")
        self.assertEqual(copy["status"], "cleaned_verified")

    def test_unknown_snapshot_is_evidence_gap_and_pending_scope(self):
        report = temp_report({
            "retention": [],
            "snapshots": [],
            "restores": [
                {"id": "op", "from": "ghost-gen", "target": "tX", "scope": ["mystery-index"],
                 "access": "pending"},
            ],
        })
        self.assertEqual(report["restore_approvals"][0]["decision"], "evidence_gap")
        self.assertTrue(any(g["code"] == "unresolved_reference" for g in report["gaps"]))
        self.assertTrue(any(p["scope"] == "mystery-index" for p in report["pending_scope"]))

    def test_unclassified_identity_is_not_skipped(self):
        report = temp_report({
            "retention": [],
            "snapshots": [{"id": "s1", "contains": ["mystery-att"]}],
            "restores": [],
        }, as_of=10)
        copy = one_copy(report, item="mystery-att", snapshot="s1")
        self.assertEqual(copy["status"], "classification_gap")
        self.assertTrue(any(g["code"] == "unclassified_identity" for g in report["gaps"]))

    def test_name_collision_does_not_merge_identities(self):
        report = temp_report({
            "retention": [
                {"id": "r1", "item": "att-a", "name": "合同.pdf", "expires": 1},
                {"id": "r2", "item": "att-b", "name": "合同.pdf", "hold_until": 99},
            ],
            "snapshots": [],
            "restores": [],
        }, as_of=10)
        self.assertEqual(len(report["identity_conflicts"]), 1)
        conflict = report["identity_conflicts"][0]
        self.assertEqual(conflict["attributed_items"], ["att-a", "att-b"])
        items = {i["item"] for i in report["items"]}
        self.assertEqual(items, {"att-a", "att-b"})

    def test_name_collision_preference_follows_cross_source_corroboration(self):
        report = temp_report({
            "retention": [
                {"id": "r1", "item": "att-a", "name": "台账.pdf", "expires": 1},
                {"id": "r2", "item": "att-b", "name": "台账.pdf", "hold_until": 99},
            ],
            "snapshots": [{"id": "s1", "contains": ["att-b"]}],
            "restores": [],
        }, as_of=10)
        conflict = report["identity_conflicts"][0]
        self.assertEqual(conflict["preferred_verifiable_item"], "att-b")
        self.assertIn("snapshots", conflict["source_corroboration"]["att-b"])
        self.assertNotIn("snapshots", conflict["source_corroboration"]["att-a"])

    def test_correction_overrides_expiry(self):
        report = temp_report({
            "retention": [
                {"id": "e1", "item": "att", "category": "personal_attachment", "expires": 5},
                {"id": "c1", "corrects": "e1", "item": "att", "expires": 20},
            ],
            "snapshots": [],
            "restores": [],
        }, as_of=10)
        item = one = next(i for i in report["items"] if i["item"] == "att")
        self.assertEqual(item["expires"], 20)
        self.assertEqual(item["retention"]["disposition"], "within_retention")
        self.assertTrue(report["corrections"][0].get("corrects") == "e1")

    def test_hold_is_period_scoped_and_can_lapse(self):
        report = audit.audit(RECORDS, as_of=40)
        lease = next(i for i in report["items"] if i["item"] == "lease-7")
        self.assertEqual(lease["retention"]["disposition"], "hold_lapsed")
        self.assertTrue(any(g["code"] == "hold_period_ended" for g in report["gaps"]))
        guard = audit.evaluate_deletion(report, ["lease-7"])
        self.assertEqual(guard["blocked_held"], [])
        self.assertIn("lease-7", guard["indeterminate_requires_ledger"])

    def test_hold_on_one_item_does_not_hide_other_same_disk_item(self):
        report = temp_report({
            "retention": [
                {"id": "k", "item": "lease", "hold_until": 99},
                {"id": "e", "item": "att", "expires": 1},
            ],
            "snapshots": [{"id": "s1", "disk": "disk-1",
                           "contains": [{"id": "lease", "disk": "disk-1"},
                                        {"id": "att", "disk": "disk-1"}]}],
            "restores": [],
        }, as_of=10)
        statuses = {(c["item"], c["status"]) for c in report["copies"] if c["snapshot"] == "s1"}
        self.assertIn(("lease", "held_lawfully"), statuses)
        self.assertIn(("att", "expired_residual_copy"), statuses)
        self.assertTrue(any(c["code"] == "sweep_colocated_attachments"
                            for c in report["defensive_checks"]))

    def test_missing_source_is_reported_not_crashed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_records(Path(tmp), {"retention": []})
            report = audit.audit(path)
            codes = {g["code"] for g in report["gaps"]}
            self.assertIn("source_absent", codes)

    def test_object_form_derived_index_and_chinese_receipts(self):
        report = temp_report({
            "retention": [{"id": "e", "item": "档-1", "category": "人员附件", "expires": 3}],
            "snapshots": [{"id": "g1", "derived": {"全文索引": {"source": "档-1"}}}],
            "restores": [
                {"id": "c", "item": "档-1", "scope": "全文索引",
                 "proof": "已确认", "type": "清除", "day": 4},
            ],
        }, as_of=5)
        idx = one_copy(report, kind="derived_index", item="档-1")
        self.assertEqual(idx["scope"], "全文索引")
        self.assertEqual(idx["status"], "cleaned_verified")

    def test_object_review_entries_and_multiple_targets_worst_case(self):
        report = temp_report({
            "retention": [{"id": "e", "item": "a1", "expires": 1}],
            "snapshots": [{"id": "s1", "contains": ["a1"]}, {"id": "s2", "contains": ["a1"]}],
            "restores": [
                {"id": "o1", "from": "s1", "target": "T1", "access": "not_approved"},
                {"id": "v1", "target": "T1", "checked": [{"id": "a1"}]},
                {"id": "o2", "from": "s2", "target": "T2", "access": "approved"},
            ],
        }, as_of=10)
        decisions = {a["target"]: a["decision"] for a in report["restore_approvals"]}
        self.assertEqual(decisions["T1"], "generation_verified")
        self.assertEqual(decisions["T2"], "blocked_reappearance")
        self.assertEqual(report["overall_decision"], "blocked_reappearance")
        self.assertFalse(report["summary"]["whole_generation_passed"])


class CliTests(unittest.TestCase):
    def test_main_json_returns_zero(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = audit.main(["--records", str(RECORDS)])
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["overall_decision"], "pending_verification")

    def test_main_check_returns_3_when_restore_not_passed(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = audit.main(["--records", str(RECORDS), "--check"])
        self.assertEqual(code, 3)

    def test_main_text_renders_chinese_report(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = audit.main(["--records", str(RECORDS), "--format", "text"])
        self.assertEqual(code, 0)
        self.assertIn("恢复审批", buf.getvalue())
        self.assertIn("index-a", buf.getvalue())

    def test_records_view_audit_subcommand(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = records_view.main(["audit", "--records", str(RECORDS)])
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        self.assertIn("copies", payload)

    def test_default_records_location_works_with_no_args(self):
        report = audit.audit(None)
        self.assertEqual(report["summary"]["items_total"], 2)


if __name__ == "__main__":
    unittest.main()
