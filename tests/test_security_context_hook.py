"""Tests for phase- and stack-specific security context loading."""

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1] / "rules"
HOOK = ROOT / ".claude" / "hooks" / "load-security-context.py"


class SecurityContextHookTest(unittest.TestCase):
    def run_hook(self, payload: str | dict[str, object]) -> subprocess.CompletedProcess[str]:
        event = payload if isinstance(payload, str) else json.dumps(payload)
        environment = os.environ.copy()
        environment["CLAUDE_PROJECT_DIR"] = str(ROOT)
        return subprocess.run(
            [sys.executable, str(HOOK)],
            input=event,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )

    def test_implementation_loads_baseline_and_detected_stack(self) -> None:
        hook_run = self.run_hook({"prompt": "/speckit.implement Spring Boot endpoint"})
        self.assertEqual(hook_run.returncode, 0)
        output = json.loads(hook_run.stdout)
        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertIn(".ai-security-rules/general.md", context)
        self.assertIn(".ai-security-rules/frameworks/spring-boot.md", context)
        self.assertIn(".ai-security-rules/languages/java.md", context)
        self.assertIn(".ai-security-rules/web.md", context)
        self.assertNotIn(".ai-security-rules/languages/javascript.md", context)
        self.assertNotIn(".ai-security-rules/frameworks/flask.md", context)

    def test_review_loads_verification_rules(self) -> None:
        hook_run = self.run_hook({"prompt": "/speckit.review this change"})
        self.assertEqual(hook_run.returncode, 0)
        context = json.loads(hook_run.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn(".ai-security-rules/verification.md", context)

    def test_unknown_phase_adds_no_context(self) -> None:
        hook_run = self.run_hook({"prompt": "hello"})
        self.assertEqual(hook_run.returncode, 0)
        self.assertEqual(hook_run.stdout, "")

    def test_malformed_event_fails_closed(self) -> None:
        hook_run = self.run_hook("not-json")
        self.assertEqual(hook_run.returncode, 2)
        self.assertIn("invalid-event", hook_run.stderr)

    def test_oversized_prompt_fails_closed(self) -> None:
        hook_run = self.run_hook({"prompt": "x" * 32_769})
        self.assertEqual(hook_run.returncode, 2)
        self.assertIn("invalid-prompt", hook_run.stderr)


if __name__ == "__main__":
    unittest.main()
