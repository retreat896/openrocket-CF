import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SENSITIVE_FILENAMES = (
    re.compile(r"(^|/)\.env($|\.)", re.I),
    re.compile(r"\.(pem|key|p12|pfx|jks|keystore)$", re.I),
    re.compile(r"(^|/)(credentials|secrets)\.json$", re.I),
)

SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])ghp_[A-Za-z0-9]{36,}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{20,}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9]{20,}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])pdl_[A-Za-z0-9]+_[A-Za-z0-9]+(?![A-Za-z0-9])"),
    re.compile(r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*[\"'][^\"'\s]{12,}[\"']"),
)

TEXT_SUFFIXES = {
    ".c", ".cc", ".cpp", ".css", ".env", ".html", ".ini", ".java",
    ".js", ".json", ".jsx", ".md", ".mjs", ".ps1", ".py", ".rs",
    ".sh", ".toml", ".ts", ".tsx", ".txt", ".yaml", ".yml",
}


def staged_files():
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    return [item.decode("utf-8", "replace") for item in result.stdout.split(b"\0") if item]


def repository_files():
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    return [item.decode("utf-8", "replace") for item in result.stdout.split(b"\0") if item]


def scan_files(files):
    findings = []
    for name in files:
        normalized = name.replace("\\", "/")
        if normalized == ".env.example" or normalized.endswith("/.env.example"):
            pass
        elif any(pattern.search(normalized) for pattern in SENSITIVE_FILENAMES):
            findings.append((name, "sensitive filename"))

        path = ROOT / name
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            for pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append((name, f"secret-like content at line {line_number}"))
                    break
    return findings


def main():
    staged = staged_files()
    files = staged if staged else repository_files()
    findings = scan_files(files)
    if findings:
        print("Secret scan failed:")
        for name, reason in findings:
            print(f"  - {name}: {reason}")
        print("Remove credentials or secrets before committing.")
        return 1
    print("Secret scan passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
