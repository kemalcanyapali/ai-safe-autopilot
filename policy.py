from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

MAX_FILE_BYTES = 10 * 1024 * 1024

SECRET_PATTERNS = (
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("OpenAI key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("Stripe live key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,}\b")),
    (
        "assigned credential",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|refresh[_-]?token)"
            r"\s*[:=]\s*[\"'][^\"'\s]{16,}[\"']"
        ),
    ),
)

IGNORED_CREDENTIAL_MARKERS = (
    "${{",
    "secrets.",
    "process.env",
    "os.environ",
    "getenv(",
    "example",
    "placeholder",
    "dummy",
    "redacted",
)

FORBIDDEN_DIRECTORIES = {
    ".mypy_cache",
    ".pytest_cache",
    ".venv",
    ".wrangler",
    "__pycache__",
    "node_modules",
}

FORBIDDEN_FILENAMES = {
    "credentials.json",
    "id_ed25519",
    "id_rsa",
    "service-account.json",
}

FORBIDDEN_SUFFIXES = {".key", ".p12", ".pem", ".pfx"}

SENSITIVE_DIRECTORIES = {".github/actions", ".github/workflows", "infra", "migrations", "terraform"}
SENSITIVE_FILENAMES = {
    "docker-compose.yml",
    "docker-compose.yaml",
    "dockerfile",
    "shopify.app.toml",
    "shopify.extension.toml",
    "wrangler.json",
    "wrangler.jsonc",
    "wrangler.toml",
}
SENSITIVE_SUFFIXES = {".tf", ".tfvars", ".service", ".timer"}


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout


def changed_paths(base: str) -> list[Path]:
    output = subprocess.run(
        ["git", "diff", "--name-only", "-z", "--diff-filter=ACMRTUXB", f"origin/{base}...HEAD"],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    return [Path(raw.decode("utf-8")) for raw in output.split(b"\0") if raw]


def classify_paths(paths: list[Path]) -> tuple[list[str], list[str]]:
    violations: list[str] = []
    review_reasons: list[str] = []

    for path in paths:
        normalized = path.as_posix().lower()
        parts = set(normalized.split("/"))
        name = path.name.lower()
        suffix = path.suffix.lower()

        if name.startswith(".env") and name not in {".env.example", ".env.sample", ".env.template"}:
            violations.append(f"environment file: {path.as_posix()}")
        if parts & FORBIDDEN_DIRECTORIES:
            violations.append(f"generated/private directory: {path.as_posix()}")
        if name in FORBIDDEN_FILENAMES or suffix in FORBIDDEN_SUFFIXES:
            violations.append(f"credential file: {path.as_posix()}")

        if any(normalized == directory or normalized.startswith(f"{directory}/") for directory in SENSITIVE_DIRECTORIES):
            review_reasons.append(path.as_posix())
        elif name in SENSITIVE_FILENAMES or suffix in SENSITIVE_SUFFIXES:
            review_reasons.append(path.as_posix())
        elif name.startswith("alchemy.") or ("deploy" in name and suffix in {".js", ".mjs", ".py", ".sh", ".ts"}):
            review_reasons.append(path.as_posix())
        elif "schema" in name and suffix in {".js", ".json", ".py", ".sql", ".ts"}:
            review_reasons.append(path.as_posix())

        if path.is_file() and path.stat().st_size > MAX_FILE_BYTES:
            violations.append(f"file exceeds 10 MiB: {path.as_posix()}")

    return sorted(set(violations)), sorted(set(review_reasons))


def validate_json(paths: list[Path]) -> list[str]:
    failures: list[str] = []
    for path in paths:
        if path.suffix.lower() != ".json" or not path.is_file():
            continue
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            failures.append(f"invalid JSON {path.as_posix()}: {error}")
    return failures


def secret_findings(diff: str) -> list[str]:
    findings: list[str] = []
    for line_number, raw_line in enumerate(diff.splitlines(), 1):
        if not raw_line.startswith("+") or raw_line.startswith("+++"):
            continue
        line = raw_line[1:]
        lowered = line.lower()
        for label, pattern in SECRET_PATTERNS:
            if not pattern.search(line):
                continue
            if label == "assigned credential" and any(marker in lowered for marker in IGNORED_CREDENTIAL_MARKERS):
                continue
            findings.append(f"{label} in added diff line {line_number}")
    return findings


def write_outputs(path: str | None, requires_review: bool, reasons: list[str]) -> None:
    if not path:
        return
    with Path(path).open("a", encoding="utf-8") as output:
        output.write(f"requires_review={'true' if requires_review else 'false'}\n")
        output.write(f"review_reason_count={len(reasons)}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--github-output")
    args = parser.parse_args()

    paths = changed_paths(args.base)
    path_violations, review_reasons = classify_paths(paths)
    json_failures = validate_json(paths)

    diff_check = subprocess.run(
        ["git", "diff", "--check", f"origin/{args.base}...HEAD"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
    )
    whitespace_failures = [line for line in diff_check.stdout.splitlines() if line]
    added_diff = git("diff", "--unified=0", "--no-color", f"origin/{args.base}...HEAD")
    secrets = secret_findings(added_diff)

    failures = path_violations + json_failures + whitespace_failures + secrets
    write_outputs(args.github_output, bool(review_reasons), review_reasons)

    print(f"AI policy checked {len(paths)} changed file(s).")
    if review_reasons:
        print("Manual review required for sensitive paths:")
        for reason in review_reasons:
            print(f"- {reason}")
    if failures:
        print("Policy violations:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("AI policy passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
