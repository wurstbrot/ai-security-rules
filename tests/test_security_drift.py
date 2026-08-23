"""Tests for protected security-asset drift detection."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "rules" / ".claude" / "hooks" / "verify-security-drift.py"


class SecurityDriftTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.project = Path(self.temporary_directory.name).resolve()
        (self.project / ".ai-security-rules").mkdir()
        (self.project / ".claude" / "hooks").mkdir(parents=True)
        (self.project / "AGENTS.md").write_text("instructions\n", encoding="utf-8")
        (self.project / ".ai-security-rules" / "general.md").write_text(
            "rules\n", encoding="utf-8"
        )
        (self.project / ".claude" / "hooks" / "gate.py").write_text(
            "pass\n", encoding="utf-8"
        )
        self.assertEqual(self.run_checker("--write").returncode, 0)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def run_checker(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["CLAUDE_PROJECT_DIR"] = str(self.project)
        return subprocess.run(
            [sys.executable, str(CHECKER), *arguments],
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )

    def run_and_parse(self) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        completed = self.run_checker()
        return completed, json.loads(completed.stdout)

    def test_matching_manifest_passes(self) -> None:
        completed, report = self.run_and_parse()
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(report["status"], "ok")

    def test_modified_file_is_reported(self) -> None:
        (self.project / "AGENTS.md").write_text("changed\n", encoding="utf-8")
        completed, report = self.run_and_parse()
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(report["modified"], ["AGENTS.md"])

    def test_missing_file_is_reported(self) -> None:
        (self.project / "AGENTS.md").unlink()
        completed, report = self.run_and_parse()
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(report["missing"], ["AGENTS.md"])

    def test_unexpected_rule_is_reported(self) -> None:
        (self.project / ".ai-security-rules" / "new.md").write_text(
            "new\n", encoding="utf-8"
        )
        completed, report = self.run_and_parse()
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(report["unexpected"], [".ai-security-rules/new.md"])

    def test_invalid_manifest_is_rejected(self) -> None:
        (self.project / ".security-rule-manifest.json").write_text(
            "not-json", encoding="utf-8"
        )
        completed, report = self.run_and_parse()
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(report["reason"], "invalid-manifest")


if __name__ == "__main__":
    unittest.main()
