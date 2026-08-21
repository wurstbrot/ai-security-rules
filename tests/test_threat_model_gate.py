"""Negative and positive tests for the local threat-model defense-in-depth hook."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HOOK = REPOSITORY_ROOT / "content" / ".claude" / "hooks" / "threat-model-gate.py"


class ThreatModelGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.project = Path(self.temporary_directory.name).resolve()
        for directory in ("specifications", "threat-models", "plans"):
            (self.project / "docs" / directory).mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def run_gate(self, event: str | dict[str, object]) -> subprocess.CompletedProcess[str]:
        payload = event if isinstance(event, str) else json.dumps(event)
        environment = os.environ.copy()
        environment["CLAUDE_PROJECT_DIR"] = str(self.project)
        return subprocess.run(
            [sys.executable, str(HOOK)],
            input=payload,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )

    def write_artifact(self, directory: str, body: str) -> None:
        (self.project / "docs" / directory / "feature.md").write_text(
            body, encoding="utf-8"
        )

    def write_model(self, body: str) -> None:
        self.write_artifact("threat-models", body)

    def valid_model(self, pattern: str) -> str:
        return (
            "Status: approved\nApproved-by: reviewer\nApproved-at: 2026-08-21\n\n"
            "Applies-to:\n"
            f"- `{pattern}`\n\n"
            "## Scope and protection requirement\nHigh integrity.\n\n"
            "## User story and abuse stories\nAs an attacker, I bypass the gate.\n\n"
            "## Threats and mitigations\nReject unmatched writes.\n\n"
            "## Accepted risks\nThe local hook is defense in depth.\n"
        )

    def valid_specification(self, pattern: str) -> str:
        return (
            "Status: approved\nApproved-by: reviewer\nApproved-at: 2026-08-21\n\nApplies-to:\n"
            f"- `{pattern}`\n\n# Feature\n\n## Acceptance criteria\nSecure.\n"
        )

    def valid_plan(self, pattern: str) -> str:
        return (
            "Status: approved\nApproved-by: reviewer\nApproved-at: 2026-08-21\n\nApplies-to:\n"
            f"- `{pattern}`\n\n# Plan\n\n## Implementation steps\n1. Implement.\n"
        )

    def write_valid_artifacts(self, pattern: str) -> None:
        self.write_artifact("specifications", self.valid_specification(pattern))
        self.write_model(self.valid_model(pattern))
        self.write_artifact("plans", self.valid_plan(pattern))

    def event(self, path: str, field: str = "file_path") -> dict[str, object]:
        return {"tool_input": {field: path}}

    def test_rejects_malformed_json(self) -> None:
        self.assertEqual(self.run_gate("not-json").returncode, 2)

    def test_rejects_missing_tool_input(self) -> None:
        self.assertEqual(self.run_gate({}).returncode, 2)

    def test_rejects_missing_path(self) -> None:
        self.assertEqual(self.run_gate({"tool_input": {}}).returncode, 2)

    def test_rejects_outside_project_path(self) -> None:
        gate_run = self.run_gate(self.event(str(self.project.parent / "outside.py")))
        self.assertEqual(gate_run.returncode, 2)
        self.assertIn("target-outside-project", gate_run.stderr)

    def test_allows_threat_model_document_creation(self) -> None:
        target = self.project / "docs" / "threat-models" / "new.md"
        self.assertEqual(self.run_gate(self.event(str(target))).returncode, 0)

    def test_empty_model_does_not_authorize_code(self) -> None:
        self.write_model("")
        target = self.project / "src" / "app.py"
        self.assertEqual(self.run_gate(self.event(str(target))).returncode, 2)

    def test_unapproved_model_does_not_authorize_code(self) -> None:
        self.write_model("Status: proposed\n\nApplies-to:\n- `src/**`\n")
        target = self.project / "src" / "app.py"
        self.assertEqual(self.run_gate(self.event(str(target))).returncode, 2)

    def test_unrelated_model_does_not_authorize_code(self) -> None:
        self.write_model(self.valid_model("web/**"))
        target = self.project / "src" / "app.py"
        self.assertEqual(self.run_gate(self.event(str(target))).returncode, 2)

    def test_approved_model_authorizes_matching_code(self) -> None:
        self.write_valid_artifacts("src/**")
        target = self.project / "src" / "app.py"
        self.assertEqual(self.run_gate(self.event(str(target))).returncode, 0)

    def test_approved_marker_without_required_analysis_is_rejected(self) -> None:
        self.write_model("Status: approved\n\nApplies-to:\n- `src/**`\n")
        target = self.project / "src" / "app.py"
        self.assertEqual(self.run_gate(self.event(str(target))).returncode, 2)

    def test_approved_prefix_is_not_accepted(self) -> None:
        self.write_model(self.valid_model("src/**").replace(
            "Status: approved", "Status: approved-pending", 1
        ))
        target = self.project / "src" / "app.py"
        self.assertEqual(self.run_gate(self.event(str(target))).returncode, 2)

    def test_symlink_escape_is_rejected(self) -> None:
        link = self.project / "src"
        link.symlink_to(self.project.parent, target_is_directory=True)
        gate_run = self.run_gate(self.event(str(link / "outside.py")))
        self.assertEqual(gate_run.returncode, 2)
        self.assertIn("target-outside-project", gate_run.stderr)

    def test_notebook_path_is_checked(self) -> None:
        target = self.project / "src" / "analysis.ipynb"
        gate_run = self.run_gate(self.event(str(target), field="notebook_path"))
        self.assertEqual(gate_run.returncode, 2)

    def test_security_markdown_is_not_implicitly_exempt(self) -> None:
        target = self.project / ".ai-security-rules" / "general.md"
        gate_run = self.run_gate(self.event(str(target)))
        self.assertEqual(gate_run.returncode, 2)
        self.assertIn("no-approved-specification-for-target", gate_run.stderr)

    def test_model_without_approved_specification_is_rejected(self) -> None:
        self.write_model(self.valid_model("src/**"))
        gate_run = self.run_gate(self.event(str(self.project / "src" / "app.py")))
        self.assertEqual(gate_run.returncode, 2)
        self.assertIn("no-approved-specification-for-target", gate_run.stderr)

    def test_model_and_specification_without_plan_are_rejected(self) -> None:
        self.write_model(self.valid_model("src/**"))
        self.write_artifact("specifications", self.valid_specification("src/**"))
        gate_run = self.run_gate(self.event(str(self.project / "src" / "app.py")))
        self.assertEqual(gate_run.returncode, 2)
        self.assertIn("no-approved-plan-for-target", gate_run.stderr)

    def test_empty_approved_plan_does_not_authorize_code(self) -> None:
        self.write_model(self.valid_model("src/**"))
        self.write_artifact("specifications", self.valid_specification("src/**"))
        empty_plan = self.valid_plan("src/**").replace("1. Implement.", "")
        self.write_artifact("plans", empty_plan)
        gate_run = self.run_gate(self.event(str(self.project / "src" / "app.py")))
        self.assertEqual(gate_run.returncode, 2)
        self.assertIn("no-approved-plan-for-target", gate_run.stderr)

    def test_allows_specification_and_plan_creation(self) -> None:
        for directory in ("specifications", "plans"):
            target = self.project / "docs" / directory / "new.md"
            self.assertEqual(self.run_gate(self.event(str(target))).returncode, 0)


if __name__ == "__main__":
    unittest.main()
