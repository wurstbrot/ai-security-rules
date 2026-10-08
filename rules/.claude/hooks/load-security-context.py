#!/usr/bin/env python3
"""Inject fixed, phase-appropriate security rules into Claude context."""

import json
import os
import re
import sys
from pathlib import Path


MAX_PROMPT_LENGTH = 32_768
MAX_CONTEXT_LENGTH = 256_000

PHASE_RULES = {
    "specify": (
        ".ai-security-rules/threat-modeling.md",
        ".ai-security-rules/architecture.md",
        ".ai-security-rules/authorization.md",
    ),
    "plan": (
        ".ai-security-rules/threat-modeling.md",
        ".ai-security-rules/architecture.md",
        ".ai-security-rules/authorization.md",
    ),
    "implement": (
        ".ai-security-rules/general.md",
        ".ai-security-rules/authorization.md",
        ".ai-security-rules/opa.md",
    ),
    "review": (".ai-security-rules/verification.md",),
}

STACK_RULES = {
    ".ai-security-rules/languages/python.md": ("python", "flask"),
    ".ai-security-rules/languages/javascript.md": (
        "javascript", "typescript", "node.js", "nodejs", "angular", "react", "reactjs"
    ),
    ".ai-security-rules/languages/java.md": ("java", "spring boot", "spring-boot"),
    ".ai-security-rules/frameworks/flask.md": ("flask",),
    ".ai-security-rules/frameworks/angular.md": ("angular",),
    ".ai-security-rules/frameworks/reactjs.md": ("react", "reactjs"),
    ".ai-security-rules/frameworks/spring-boot.md": ("spring boot", "spring-boot"),
    ".ai-security-rules/frameworks/terraform.md": ("terraform",),
    ".ai-security-rules/frameworks/docker.md": ("docker", "dockerfile", "compose"),
    ".ai-security-rules/iac.md": ("kubernetes", "helm", "iac", "pipeline", "ci/cd"),
    ".ai-security-rules/web.md": ("http", "endpoint", "browser", "cookie", "web ui"),
    ".ai-security-rules/cryptography.md": ("crypto", "encryption", "cipher", "hashing"),
    ".ai-security-rules/supply-chain.md": ("dependency", "package", "container image"),
}


def fail(reason: str) -> "NoReturn":
    print(f"Security context hook: denied ({reason}).", file=sys.stderr)
    raise SystemExit(2)


def mentions(term: str, lowered: str) -> bool:
    return re.search(rf"(?<!\w){re.escape(term)}(?!\w)", lowered) is not None


def detect_phase(prompt: str) -> str | None:
    lowered = prompt.casefold()
    commands = {
        "/speckit.specify": "specify",
        "/speckit.plan": "plan",
        "/speckit.implement": "implement",
        "/speckit.review": "review",
    }
    for command, phase in commands.items():
        if command in lowered:
            return phase
    # Inflections are listed rather than matched by prefix. Whole-word matching
    # is what keeps "preview" out of the review phase, and a prefix match would
    # put it straight back.
    keywords = (
        ("review", ("review", "reviews", "reviewing", "verify", "verifies",
                    "verifying", "verification")),
        ("implement", ("implement", "implements", "implementing",
                       "implementation", "build", "builds", "building",
                       "rebuild", "rebuilds", "rebuilding", "change code")),
        ("plan", ("plan", "plans", "planning")),
        ("specify", ("specify", "specifies", "specifying", "specification")),
    )
    for phase, terms in keywords:
        # Whole words only. As bare substrings "preview" matched "review" and
        # "rebuild" matched "build", so the wrong ruleset loaded and the hook
        # still exited 0 with valid output.
        if any(mentions(term, lowered) for term in terms):
            return phase
    return None


def selected_rules(prompt: str, phase: str) -> list[str]:
    selected = list(PHASE_RULES[phase])
    lowered = prompt.casefold()
    for rule, terms in STACK_RULES.items():
        if any(mentions(term, lowered) for term in terms) and rule not in selected:
            selected.append(rule)
    return selected


def load_context(root: Path, rules: list[str]) -> str:
    sections: list[str] = []
    for relative in rules:
        try:
            target = (root / relative).resolve(strict=True)
            target.relative_to(root)
            content = target.read_text(encoding="utf-8")
        except ValueError:
            fail("rule-outside-project")
        except (OSError, UnicodeError):
            fail("rule-unreadable")
        sections.append(f"<!-- Loaded security rule: {relative} -->\n{content}")
    context = "\n\n".join(sections)
    if len(context) > MAX_CONTEXT_LENGTH:
        fail("context-too-large")
    return context


try:
    event = json.load(sys.stdin)
except (json.JSONDecodeError, ValueError):
    fail("invalid-event")
prompt = event.get("prompt")
if not isinstance(prompt, str) or len(prompt) > MAX_PROMPT_LENGTH:
    fail("invalid-prompt")
phase = detect_phase(prompt)
if phase is None:
    raise SystemExit(0)
root_value = os.environ.get("CLAUDE_PROJECT_DIR")
if not root_value:
    fail("missing-project-root")
root = Path(root_value).resolve(strict=True)
context = load_context(root, selected_rules(prompt, phase))
json.dump(
    {
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": context,
        }
    },
    sys.stdout,
)
